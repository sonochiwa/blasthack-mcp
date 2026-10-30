package analyzer

import (
	"bytes"
	"debug/pe"
	"fmt"
	"sort"
	"strings"
)

type PESection struct {
	Name    string  `json:"name"`
	Size    uint32  `json:"size"`
	Entropy float64 `json:"entropy"`
}

type PEInfo struct {
	Machine   string              `json:"machine"`
	DLL       bool                `json:"dll"`
	DotNet    bool                `json:"dotnet"`
	Timestamp uint32              `json:"timestamp"`
	Sections  []PESection         `json:"sections"`
	Imports   map[string][]string `json:"imports"`
}

// comDescriptor is the data directory index of the .NET (CLR) header.
const comDescriptor = 14

func scanPE(file string, data []byte) (*PEInfo, []Finding) {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, []Finding{{Severity: "medium", Rule: "pe.invalid", File: file, Detail: "Damaged PE: " + err.Error()}}
	}
	defer f.Close()
	info := &PEInfo{Machine: fmt.Sprintf("0x%x", f.Machine), DLL: f.Characteristics&pe.IMAGE_FILE_DLL != 0,
		Timestamp: f.TimeDateStamp, Imports: map[string][]string{}}
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		info.Machine = "x86"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		info.Machine = "x64"
	}
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		info.DotNet = len(oh.DataDirectory) > comDescriptor && oh.DataDirectory[comDescriptor].VirtualAddress != 0
	case *pe.OptionalHeader64:
		info.DotNet = len(oh.DataDirectory) > comDescriptor && oh.DataDirectory[comDescriptor].VirtualAddress != 0
	}

	var findings []Finding
	var imageEnd int64
	for _, s := range f.Sections {
		raw, _ := s.Data()
		e := entropy(raw)
		info.Sections = append(info.Sections, PESection{s.Name, s.Size, float64(int(e*100)) / 100})
		imageEnd = max(imageEnd, int64(s.Offset)+int64(s.Size))
		if packer, ok := packerSections[s.Name]; ok {
			findings = append(findings, Finding{Severity: "high", Rule: "pe.packer", File: file,
				Detail: fmt.Sprintf("Packer/protector %s (section %s) — forbidden by the rules: protected from analysis", packer, s.Name)})
		} else if e > 7.2 && s.Size > 4096 {
			findings = append(findings, Finding{Severity: "medium", Rule: "pe.high_entropy", File: file,
				Detail: fmt.Sprintf("Section %s has entropy %.2f: packed/encrypted", s.Name, e)})
		}
	}

	symbols, _ := f.ImportedSymbols()
	flat := map[string]bool{}
	for _, sym := range symbols {
		name, dll, _ := strings.Cut(sym, ":")
		flat[name] = true
		if len(info.Imports[dll]) < 40 {
			info.Imports[dll] = append(info.Imports[dll], name)
		}
	}
	var sus []string
	high := false
	for name := range flat {
		if why, ok := peSuspiciousImports[name]; ok {
			sus = append(sus, fmt.Sprintf("%s (%s)", name, why))
			high = high || peHighRiskImports[why]
		}
	}
	if len(sus) > 0 {
		sort.Strings(sus)
		sev := "medium"
		if high {
			sev = "high"
		}
		findings = append(findings, Finding{Severity: sev, Rule: "pe.imports", File: file,
			Detail: "Suspicious imports: " + strings.Join(sus, ", ")})
	}
	if len(flat) < 8 && !info.DotNet {
		findings = append(findings, Finding{Severity: "medium", Rule: "pe.few_imports", File: file,
			Detail: fmt.Sprintf("Only %d imports: sign of a packer/manual import resolution", len(flat))})
	}
	if info.DotNet {
		findings = append(findings, Finding{Severity: "info", Rule: "pe.dotnet", File: file,
			Detail: ".NET assembly: decompile with dnSpy/ILSpy to review the code"})
	}
	if overlay := int64(len(data)) - imageEnd; imageEnd > 0 && overlay > 1024 {
		findings = append(findings, Finding{Severity: "medium", Rule: "pe.overlay", File: file,
			Detail: fmt.Sprintf("%d bytes appended after the PE (overlay)", overlay)})
	}
	for _, s := range ScanText(file, PrintableStrings(data, 6)) {
		switch s.Rule {
		case "obf.entropy", "obf.long_line", "obf.names", "obf.base64_blob":
			continue
		}
		s.Line = 0
		findings = append(findings, s)
	}
	return info, findings
}
