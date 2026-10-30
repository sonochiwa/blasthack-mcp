// Package analyzer statically scans forum attachments: archives, Lua/CLEO/Pawn sources and PE
// binaries (.asi/.dll/.exe/.sf). Nothing is ever executed; findings point at code worth reading.
package analyzer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

type Finding struct {
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	Detail   string `json:"detail"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Snippet  string `json:"snippet,omitempty"`
}

type FileReport struct {
	Path     string    `json:"path"`
	Type     string    `json:"type"`
	Note     string    `json:"note,omitempty"`
	Size     int       `json:"size,omitempty"`
	SHA256   string    `json:"sha256,omitempty"`
	Lines    int       `json:"lines,omitempty"`
	PE       *PEInfo   `json:"pe,omitempty"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Name    string         `json:"name"`
	Size    int            `json:"size"`
	SHA256  string         `json:"sha256"`
	Files   []FileReport   `json:"files"`
	Summary map[string]int `json:"summary"`
	Note    string         `json:"note"`
}

var severityOrder = map[string]int{"high": 0, "medium": 1, "info": 2}

func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Sniff tells archives, PE files, Lua bytecode and text apart by content, not by extension.
func Sniff(data []byte, name string) string {
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")), bytes.HasPrefix(data, []byte("PK\x05\x06")):
		return "zip"
	case bytes.HasPrefix(data, []byte("Rar!\x1a\x07")):
		return "rar"
	case bytes.HasPrefix(data, []byte("7z\xbc\xaf\x27\x1c")):
		return "7z"
	case bytes.HasPrefix(data, []byte("MZ")):
		return "pe"
	case bytes.HasPrefix(data, []byte("\x1bLJ")):
		return "luajit_bytecode"
	case bytes.HasPrefix(data, []byte("\x1bLua")):
		return "lua_bytecode"
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		return "elf"
	}
	ext := strings.ToLower(path.Ext(name))
	text := isText(data)
	if (ext == ".cs" || ext == ".cm" || ext == ".cleo" || ext == ".s") && !text {
		return "cleo_compiled"
	}
	if text {
		return "text"
	}
	return "binary"
}

func isText(data []byte) bool {
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if len(sample) == 0 {
		return true
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}
	// The 8 KB cut can split a multi-byte character, so allow up to three trailing bytes.
	for cut := 0; cut < 4 && cut < len(sample); cut++ {
		if utf8.Valid(sample[:len(sample)-cut]) {
			return true
		}
	}
	bad := 0
	for _, b := range sample {
		if b < 9 || (b > 13 && b < 32) {
			bad++
		}
	}
	return float64(bad)/float64(len(sample)) < 0.01
}

// DecodeText reads UTF-8 (with or without BOM) and falls back to CP1251, the usual SA-MP encoding.
func DecodeText(data []byte) string {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if utf8.Valid(data) {
		return string(data)
	}
	if out, err := charmap.Windows1251.NewDecoder().Bytes(data); err == nil {
		return string(out)
	}
	return string(data)
}

func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	e := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

var asciiRun = regexp.MustCompile(`[\x20-\x7e]{6,}`)

// PrintableStrings extracts ASCII and UTF-16LE strings from a binary, like strings(1).
func PrintableStrings(data []byte, minLen int) string {
	var b strings.Builder
	for _, m := range asciiRun.FindAll(data, -1) {
		if len(m) >= minLen {
			b.Write(m)
			b.WriteByte('\n')
		}
	}
	var run []byte
	flush := func() {
		if len(run) >= minLen {
			b.Write(run)
			b.WriteByte('\n')
		}
		run = run[:0]
	}
	for i := 0; i+1 < len(data); i += 2 {
		if data[i] >= 0x20 && data[i] <= 0x7e && data[i+1] == 0 {
			run = append(run, data[i])
		} else {
			flush()
		}
	}
	flush()
	return b.String()
}

func lineOf(text string, pos int) int {
	return strings.Count(text[:pos], "\n") + 1
}

func snippetAt(text string, pos int) string {
	start := strings.LastIndexByte(text[:pos], '\n') + 1
	end := strings.IndexByte(text[pos:], '\n')
	if end < 0 {
		end = len(text)
	} else {
		end += pos
	}
	line := text[start:end]
	if len(line) > 160 {
		rel := pos - start
		from, to := max(0, rel-80), min(len(line), rel+80)
		line = line[from:to]
	}
	return strings.ToValidUTF8(strings.TrimSpace(line), "")
}

// ScanText runs every source rule over text and reports at most a few hits per rule.
func ScanText(file, text string) []Finding {
	var out []Finding
	for _, r := range append(append([]Rule{}, sourceRules...), sqlRules...) {
		hits := r.match(text)
		if len(hits) == 0 {
			continue
		}
		limit := 5
		if r.ID == "net.url" {
			limit = 15
		}
		seen := map[int]bool{}
		for _, pos := range hits {
			line := lineOf(text, pos)
			if seen[line] {
				continue
			}
			if len(seen) == limit {
				break
			}
			seen[line] = true
			out = append(out, Finding{r.Severity, r.ID, r.Detail, file, line, snippetAt(text, pos)})
		}
		if len(hits) > limit {
			out = append(out, Finding{Severity: "info", Rule: r.ID, File: file,
				Detail: fmt.Sprintf("... and %d more matches", len(hits)-limit)})
		}
	}
	longest := 0
	for _, l := range strings.Split(text, "\n") {
		longest = max(longest, len(l))
	}
	if longest > 5000 {
		out = append(out, Finding{Severity: "medium", Rule: "obf.long_line", File: file,
			Detail: fmt.Sprintf("Line of %d chars (minified/obfuscated code)", longest)})
	}
	sample := []byte(text)
	if len(sample) > 2_000_000 {
		sample = sample[:2_000_000]
	}
	if e := entropy(sample); e > 5.8 {
		out = append(out, Finding{Severity: "medium", Rule: "obf.entropy", File: file,
			Detail: fmt.Sprintf("High entropy of text %.2f (encrypted/packed data)", e)})
	}
	return out
}

func onlyPrefixes(findings []Finding, prefixes ...string) []Finding {
	var out []Finding
	for _, f := range findings {
		for _, p := range prefixes {
			if strings.HasPrefix(f.Rule, p) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

var doubleExt = regexp.MustCompile(`(?i)\.(?:lua|txt|png|jpg|pdf|cs)\.(?:exe|scr|bat|cmd|vbs|js)$`)

func analyzeMember(m Member) FileReport {
	if len(m.Data) == 0 {
		kind := "unavailable"
		if strings.Contains(m.Note, "archive") {
			kind = "archive"
		}
		rep := FileReport{Path: m.Path, Type: kind, Note: m.Note, Findings: []Finding{}}
		if strings.Contains(m.Note, "password") {
			rep.Findings = append(rep.Findings, Finding{Severity: "high", Rule: "archive.encrypted", File: m.Path,
				Detail: "Password-protected archive: contents cannot be checked (classic way to hide malware)"})
		}
		return rep
	}
	kind := Sniff(m.Data, m.Path)
	rep := FileReport{Path: m.Path, Type: kind, Note: m.Note, Size: len(m.Data), SHA256: SHA256(m.Data)}
	var findings []Finding
	ext := strings.ToLower(path.Ext(m.Path))
	switch kind {
	case "text":
		text := DecodeText(m.Data)
		rep.Lines = strings.Count(text, "\n") + 1
		findings = ScanText(m.Path, text)
	case "lua_bytecode", "luajit_bytecode":
		findings = append(findings, Finding{Severity: "high", Rule: "lua.bytecode", File: m.Path,
			Detail: "Compiled Lua bytecode (.luac): source closed — the rules forbid software protected from analysis in pre-moderated sections"})
		findings = append(findings, withoutLines(onlyPrefixes(ScanText(m.Path, PrintableStrings(m.Data, 5)),
			"exfil", "steal", "exec", "persist", "evasion", "net"))...)
	case "pe":
		rep.PE, findings = scanPE(m.Path, m.Data)
		if ext == ".scr" || ext == ".com" || ext == ".pif" {
			findings = append(findings, Finding{Severity: "high", Rule: "pe.ext", File: m.Path,
				Detail: "Executable with extension " + ext})
		}
	case "cleo_compiled":
		findings = append(findings, Finding{Severity: "info", Rule: "cleo.compiled", File: m.Path,
			Detail: "Compiled CLEO script: decompile with Sanny Builder to review"})
		findings = append(findings, withoutLines(ScanText(m.Path, PrintableStrings(m.Data, 5)))...)
	default:
		for _, f := range ScanText(m.Path, PrintableStrings(m.Data, 6)) {
			if f.Severity == "high" {
				f.Line = 0
				findings = append(findings, f)
			}
		}
	}
	if doubleExt.MatchString(m.Path) {
		findings = append(findings, Finding{Severity: "high", Rule: "file.double_ext", File: m.Path,
			Detail: "Double extension: disguised executable"})
	}
	switch ext {
	case ".bat", ".cmd", ".vbs", ".ps1", ".js", ".hta", ".lnk", ".scr":
		findings = append(findings, Finding{Severity: "medium", Rule: "file.script", File: m.Path,
			Detail: "Windows script/executable file (" + ext + ") inside the release"})
	}
	if findings == nil {
		findings = []Finding{}
	}
	rep.Findings = findings
	return rep
}

// withoutLines drops line numbers that only point into extracted strings, not into the file.
func withoutLines(findings []Finding) []Finding {
	for i := range findings {
		findings[i].Line = 0
	}
	return findings
}

// Analyze unpacks name/data recursively and scans every file in it.
func Analyze(name string, data []byte) Report {
	members := Unpack(name, data)
	rep := Report{Name: name, Size: len(data), SHA256: SHA256(data), Summary: map[string]int{"high": 0, "medium": 0, "info": 0},
		Note: "Static heuristics only, nothing was executed. Read the flagged lines with read_attachment before deciding."}
	for _, m := range members {
		fr := analyzeMember(m)
		sort.SliceStable(fr.Findings, func(i, j int) bool {
			return severityOrder[fr.Findings[i].Severity] < severityOrder[fr.Findings[j].Severity]
		})
		for _, f := range fr.Findings {
			rep.Summary[f.Severity]++
		}
		rep.Files = append(rep.Files, fr)
	}
	return rep
}

// ReadMember returns one file of an attachment: the attachment itself or a file inside its archive.
func ReadMember(name string, data []byte, member string) (string, []byte, error) {
	var files []Member
	var paths []string
	for _, m := range Unpack(name, data) {
		if len(m.Data) > 0 {
			files = append(files, m)
			paths = append(paths, m.Path)
		}
	}
	if member != "" {
		for _, m := range files {
			if m.Path == member || strings.HasSuffix(m.Path, "/"+member) {
				return m.Path, m.Data, nil
			}
		}
		return "", nil, fmt.Errorf("no file %q; files: %v", member, paths)
	}
	if len(files) == 1 {
		return files[0].Path, files[0].Data, nil
	}
	return "", nil, fmt.Errorf("the archive has several files, pass member; files: %v", paths)
}
