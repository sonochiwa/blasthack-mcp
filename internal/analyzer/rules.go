package analyzer

import (
	"regexp"
	"strings"
)

// Rule flags code worth reading. The matcher returns byte offsets of the hits.
type Rule struct {
	Severity string
	ID       string
	Detail   string
	match    func(text string) []int
}

func rx(severity, id, detail, pattern string) Rule {
	re := regexp.MustCompile(pattern)
	return Rule{severity, id, detail, func(text string) []int {
		var out []int
		for _, m := range re.FindAllStringIndex(text, 2000) {
			out = append(out, m[0])
		}
		return out
	}}
}

// Go regexps have no lookbehind, so "load(" is filtered by hand: it must not be a method call
// (x.load, x:load), part of a longer name, or the definition "function load(".
var dynamicCall = regexp.MustCompile(`(loadstring|load|dofile|loadfile)\s*\(`)

func dynamicCodeRule() Rule {
	return Rule{"medium", "exec.dynamic_code", "Dynamic code execution (load/loadstring/dofile)", func(text string) []int {
		var out []int
		for _, m := range dynamicCall.FindAllStringIndex(text, 2000) {
			if m[0] > 0 {
				prev := text[m[0]-1]
				if prev == '.' || prev == ':' || prev == '_' || isAlnum(prev) {
					continue
				}
			}
			if strings.HasSuffix(text[:m[0]], "function ") {
				continue
			}
			out = append(out, m[0])
		}
		return out
	}}
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// The three rules below look for long repetitions. As regexps ({400,}, {40,}) they compile into huge
// automata and slow every server start by seconds, so they are plain scans.

var stringCharCall = regexp.MustCompile(`(?i)string\.char\s*\(`)

func stringCharRule() Rule {
	return Rule{"medium", "obf.string_char", "Long string.char(...) chains (hidden strings)", func(text string) []int {
		var out []int
		for _, m := range stringCharCall.FindAllStringIndex(text, 2000) {
			args := 0
			for i := m[1]; i < len(text) && args < 20; i++ {
				c := text[i]
				if c == ',' {
					args++
				} else if !(c >= '0' && c <= '9' || c == ' ' || c == '\t' || c == '\r' || c == '\n') {
					break
				}
			}
			if args >= 20 {
				out = append(out, m[0])
			}
		}
		return out
	}}
}

var escapeSeq = regexp.MustCompile(`(?i)\\\d{1,3}|\\x[0-9a-f]{2}`)

func escapeBlobRule() Rule {
	return Rule{"medium", "obf.escape_blob", "Long strings of \\ddd / \\xNN escapes (hidden code)", func(text string) []int {
		var out []int
		runStart, runEnd, runLen := -1, -1, 0
		flush := func() {
			if runLen >= 40 {
				out = append(out, runStart)
			}
		}
		for _, m := range escapeSeq.FindAllStringIndex(text, -1) {
			if m[0] == runEnd {
				runLen++
			} else {
				flush()
				runStart, runLen = m[0], 1
			}
			runEnd = m[1]
		}
		flush()
		return out
	}}
}

func base64BlobRule() Rule {
	return Rule{"medium", "obf.base64_blob", "Large base64 blob", func(text string) []int {
		var out []int
		start := -1
		for i := 0; i <= len(text); i++ {
			isB64 := i < len(text) && (isAlnum(text[i]) || text[i] == '+' || text[i] == '/')
			if isB64 && start < 0 {
				start = i
			} else if !isB64 && start >= 0 {
				if i-start >= 400 {
					out = append(out, start)
				}
				start = -1
			}
		}
		return out
	}}
}

const sqlKeyword = `(?:SELECT\s.+?\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|REPLACE\s+INTO|WHERE\s)`

// A string literal in either quote style that contains SQL; the other quote may appear inside it.
const sqlLiteral = `(?:"[^"\n]*` + sqlKeyword + `[^"\n]*"|'[^'\n]*` + sqlKeyword + `[^'\n]*')`

var sourceRules = []Rule{
	rx("high", "exfil.discord_webhook", "Discord webhook: typical channel for stealing data", `(?i)discord(?:app)?\.com/api/webhooks/`),
	rx("medium", "net.telegram_bot", "Telegram Bot API (check what is sent and whose token it is)", `(?i)api\.telegram\.org/bot`),
	rx("high", "exfil.paste", "Paste/temporary file services", `(?i)pastebin\.com|hastebin|paste\.ee|transfer\.sh|anonfiles|file\.io|0x0\.st|ngrok\.io|ngrok-free`),
	rx("medium", "net.raw_ip", "Hardcoded IP address in a URL", `(?i)https?://\d{1,3}(?:\.\d{1,3}){3}`),
	rx("info", "net.url", "External URL", `(?i)https?://[^\s"'<>)\]]+`),
	rx("high", "steal.browser", "Access to browser passwords/cookies", `Login Data|Local State|\bCookies\b|\\Google\\Chrome|\\Yandex\\YandexBrowser|\\Opera Software|Mozilla\\Firefox\\Profiles|logins\.json|key4\.db`),
	rx("high", "steal.discord_token", "Access to Discord local storage (tokens)", `(?i)discord\\Local Storage|leveldb|discordcanary|dQw4w9WgXcQ`),
	rx("high", "steal.telegram", "Access to Telegram session (tdata)", `(?i)tdata\\|Telegram Desktop`),
	rx("high", "steal.crypto", "Access to crypto wallets", `(?i)wallet\.dat|Exodus|Electrum|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn`),
	rx("medium", "steal.samp_cfg", "Reads SA-MP/launcher settings (nickname, servers, saved passwords)", `(?i)USERDATA\.DAT|samp\.saw|sa-mp\.cfg|\\GTA San Andreas User Files\\SAMP|arizona.*launcher.*(?:json|cfg)`),
	rx("medium", "steal.password_dialog", "Captures input from dialogs (login/password)", `(?i)onSendDialogResponse|sampGetCurrentDialogEditboxText|sampGetDialogEditboxText`),
	rx("info", "steal.password_word", "Mentions password/token in code", `(?i)\b(?:password|passwd|pass|parol|token)\b|пароль`),
	rx("high", "exec.shell", "Runs OS commands", `(?i)os\.execute|io\.popen|ShellExecute[AW]?\b|WinExec|CreateProcess[AW]?\b|system\s*\(|powershell|cmd(?:\.exe)?\s*/c|mshta|rundll32|regsvr32|certutil|bitsadmin`),
	rx("high", "exec.download", "Downloads files from the internet", `(?i)downloadUrlToFile|URLDownloadToFile[AW]?`),
	rx("medium", "net.http_native", "Native HTTP (WinHTTP/WinINet): check where and what is sent", `(?i)WinHttpOpen\b|InternetOpen(?:Url)?[AW]?\b|HttpSendRequest[AW]?\b`),
	rx("high", "persist.autorun", "Autorun/persistence in Windows", `(?i)CurrentVersion\\Run|\\Start Menu\\Programs\\Startup|schtasks|HKEY_LOCAL_MACHINE|RegSetValue|RegCreateKey`),
	rx("high", "evasion.av", "Tries to disable or hide from antivirus", `(?i)Add-MpPreference|DisableRealtimeMonitoring|ExclusionPath|Set-MpPreference`),
	dynamicCodeRule(),
	rx("medium", "exec.ffi_load", "Loads native libraries through FFI", `(?i)ffi\.load\s*\(|LoadLibrary[AW]?\b`),
	rx("medium", "proc.memory", "Writes into other processes' memory / injection", `(?i)WriteProcessMemory|CreateRemoteThread|VirtualAllocEx|NtCreateThreadEx|OpenProcess\b`),
	rx("medium", "input.keylogger", "Global key interception (possible keylogger)", `(?i)SetWindowsHookEx|GetAsyncKeyState.*for|GetKeyboardState`),
	rx("medium", "fs.write_outside", "Writes files outside the game folder", `(?i)getenv\s*\(\s*['"](?:APPDATA|LOCALAPPDATA|TEMP|USERPROFILE)|%APPDATA%|%TEMP%|C:\\\\Windows|C:\\\\Users`),
	rx("medium", "fs.delete", "Deletes files/folders", `(?i)os\.remove\s*\(|DeleteFile[AW]?\b|RemoveDirectory|rmdir\s|del\s+/[fqs]`),
	rx("medium", "update.self", "Self-update: downloads code that can change after moderation", `(?i)(?:update|autoupdate|version).{0,80}(?:raw\.githubusercontent|pastebin|gist\.github|http)`),
	rx("info", "net.http_lib", "Network library (requests/socket/effil/luasocket/curl)", `(?i)require\s*\(?\s*['"](?:requests|socket(?:\.http)?|ssl\.https|effil|lanes|luacurl|copas|websocket)['"]`),
	rx("high", "obf.marker", "Known obfuscator marker", `\b(?:Luraph|MoonSec|IronBrew|Moonveil|wearedevs|Jx-Obfuscator)\b|[Oo]bfuscated (?:with|by)|lua-obfuscator|Lua Obfuscator|Prometheus Obfuscator`),
	stringCharRule(),
	escapeBlobRule(),
	base64BlobRule(),
	rx("medium", "obf.names", "Names like IlIlIl/l1l1/_0x (obfuscated identifiers)", `\b(?:[Il]{6,}|[Il1]{8,}|_0x[0-9a-f]{4,})\b`),
	rx("medium", "obf.bytecode_string", "Embedded Lua/LuaJIT bytecode in a string", `(?i)\\27LJ|\\027LJ|\\x1bLJ|\\27Lua|\\x1bLua`),
}

var sqlRules = []Rule{
	rx("high", "sqli.lua_concat", "SQL is built by string concatenation (..) — possible SQL injection",
		`(?i)`+sqlLiteral+`\s*\.\.\s*[A-Za-z_]`),
	rx("high", "sqli.format_s", "SQL with %s placeholder through string.format/format — possible SQL injection",
		`(?i)(?:string\.format|format|sprintf|snprintf|mysql_format)\s*\([^\n]*`+sqlKeyword+`[^\n]*%s`),
	rx("high", "sqli.php_superglobal", "PHP: request data inserted into SQL",
		`(?i)`+sqlKeyword+`[^\n;]*\$_(?:GET|POST|REQUEST|COOKIE)`),
	rx("high", "sqli.concat_generic", "SQL is concatenated with a variable (+ / .)",
		`(?i)`+sqlLiteral+`\s*[+.]\s*\$?[A-Za-z_]`),
	rx("medium", "sqli.exec", "Raw SQL execution (check that parameters are escaped/bound)",
		`(?i)db:exec\s*\(|:execute\s*\(|:query\s*\(|mysql_(?:t|p)?query\s*\(|sqlite3?_exec|db_query\s*\(|mysql_query\s*\(`),
}

var peSuspiciousImports = map[string]string{
	"URLDownloadToFileA": "download", "URLDownloadToFileW": "download",
	"InternetOpenA": "network", "InternetOpenW": "network",
	"InternetOpenUrlA": "network", "InternetOpenUrlW": "network",
	"HttpSendRequestA": "network", "HttpSendRequestW": "network",
	"WinHttpOpen": "network", "WinHttpSendRequest": "network",
	"send": "socket", "connect": "socket", "WSAStartup": "socket",
	"ShellExecuteA": "exec", "ShellExecuteW": "exec", "ShellExecuteExW": "exec", "WinExec": "exec",
	"CreateProcessA": "exec", "CreateProcessW": "exec",
	"CryptUnprotectData": "decrypts saved browser passwords (DPAPI)",
	"RegSetValueExA":     "registry", "RegSetValueExW": "registry",
	"SetWindowsHookExA": "keyboard hook", "SetWindowsHookExW": "keyboard hook", "GetAsyncKeyState": "keyboard",
	"CreateRemoteThread": "injection", "WriteProcessMemory": "process memory", "VirtualAllocEx": "injection",
	"IsDebuggerPresent": "anti-debug", "CheckRemoteDebuggerPresent": "anti-debug",
	"NtQueryInformationProcess": "anti-debug",
	"GetClipboardData":          "clipboard",
	"BCryptDecrypt":             "decrypts data (browser cookies)",
}

var peHighRiskImports = map[string]bool{
	"download": true, "decrypts saved browser passwords (DPAPI)": true, "decrypts data (browser cookies)": true,
}

var packerSections = map[string]string{
	"UPX0": "UPX", "UPX1": "UPX", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".themida": "Themida",
	".winlice": "WinLicense", ".enigma1": "Enigma", ".enigma2": "Enigma", ".MPRESS1": "MPRESS",
	".aspack": "ASPack", ".petite": "Petite", ".nsp0": "NsPack", ".adata": "ASProtect", "pebundle": "PEBundle",
	".boom": "The Boomerang", ".obsidium": "Obsidium",
}
