"""Static analysis of forum attachments: archives, Lua/CLEO/Pawn sources, PE binaries (.asi/.dll/.exe/.sf).

Nothing here ever executes the files. Archives are read in memory (7z.exe is used only to list/print RAR members).
Heuristics point at places worth reading; the verdict is the reviewer's.
"""

from __future__ import annotations

import hashlib
import io
import math
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field

MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_DEPTH = 3
SEVENZIP = os.environ.get("BLASTHACK_7Z") or shutil.which("7z") or next(
    (p for p in (r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe") if os.path.exists(p)), None)

TEXT_EXT = {".lua", ".txt", ".ini", ".json", ".cfg", ".pwn", ".inc", ".cs", ".cpp", ".c", ".h", ".hpp", ".py",
            ".ahk", ".js", ".php", ".md", ".xml", ".yml", ".yaml", ".bat", ".cmd", ".ps1", ".vbs", ".toml", ".sql", ".html", ".css"}


@dataclass
class Member:
    path: str
    data: bytes
    note: str | None = None


@dataclass
class Finding:
    severity: str  # high / medium / info
    rule: str
    detail: str
    file: str
    line: int | None = None
    snippet: str | None = None

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


# ---------------------------------------------------------------- type detection

def sniff(data: bytes, name: str) -> str:
    head = data[:16]
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x1bLJ"):
        return "luajit_bytecode"
    if head.startswith(b"\x1bLua"):
        return "lua_bytecode"
    if head.startswith(b"\x7fELF"):
        return "elf"
    ext = os.path.splitext(name.lower())[1]
    if ext == ".cs" and b"\x00" in data[:4096]:
        return "cleo_compiled"
    if ext in (".cs", ".cm", ".cleo", ".s") and not _is_text(data):
        return "cleo_compiled"
    if _is_text(data):
        return "text"
    return "binary"


def _is_text(data: bytes) -> bool:
    sample = data[:8192]
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass
    bad = sum(1 for b in sample if b < 9 or 13 < b < 32)
    return bad / len(sample) < 0.01


def decode_text(data: bytes) -> str:
    for enc in ("utf-8-sig", "cp1251"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


# ---------------------------------------------------------------- archives

def unpack(name: str, data: bytes, depth: int = 0, budget: list[int] | None = None) -> list[Member]:
    """Flatten archives (recursively) into members. Non-archives come back as a single member."""
    budget = budget if budget is not None else [MAX_TOTAL_BYTES]
    kind = sniff(data, name)
    if kind not in ("zip", "rar", "7z") or depth >= MAX_DEPTH:
        return [Member(name, data)]
    out: list[Member] = [Member(name, b"", note=f"{kind} archive")]
    try:
        for inner_name, inner, note in _list_archive(kind, data, budget):
            full = f"{name}/{inner_name}"
            if inner is None:
                out.append(Member(full, b"", note=note))
            else:
                out.extend(unpack(full, inner, depth + 1, budget))
    except Exception as e:  # corrupt / unsupported archive
        out.append(Member(name, b"", note=f"cannot open {kind}: {e}"))
    return out


def _take(budget: list[int], size: int) -> bool:
    if size > MAX_MEMBER_BYTES or size > budget[0]:
        return False
    budget[0] -= size
    return True


def _list_archive(kind: str, data: bytes, budget: list[int]):
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    yield info.filename, None, "password-protected (cannot be analysed)"
                elif not _take(budget, info.file_size):
                    yield info.filename, None, f"skipped: too large ({info.file_size} bytes, possible zip bomb)"
                else:
                    yield info.filename, z.read(info), None
    elif kind == "7z":
        import py7zr
        with py7zr.SevenZipFile(io.BytesIO(data)) as z:
            if z.needs_password():
                yield "*", None, "password-protected (cannot be analysed)"
                return
            infos = [i for i in z.list() if not i.is_directory]
            if any(".." in i.filename.replace("\\", "/").split("/") or os.path.isabs(i.filename) or ":" in i.filename for i in infos):
                yield "*", None, "archive contains paths escaping the folder (../ or absolute) — suspicious, not unpacked"
                return
            if sum(i.uncompressed for i in infos) > budget[0]:
                yield "*", None, "skipped: archive too large when unpacked"
                return
            budget[0] -= sum(i.uncompressed for i in infos)
            with tempfile.TemporaryDirectory(prefix="bh7z_") as tmp:
                z.extractall(path=tmp)  # extraction only, nothing is run
                for i in infos:
                    p = os.path.join(tmp, i.filename)
                    if os.path.isfile(p):
                        with open(p, "rb") as f:
                            yield i.filename, f.read(), None
    elif kind == "rar":
        if not SEVENZIP:
            yield "*", None, "RAR needs 7-Zip installed (set BLASTHACK_7Z)"
            return
        with tempfile.TemporaryDirectory(prefix="bhrar_") as tmp:
            arc = os.path.join(tmp, "a.rar")
            with open(arc, "wb") as f:
                f.write(data)
            listing = subprocess.run([SEVENZIP, "l", "-slt", "-p-", arc], capture_output=True, timeout=60)
            text = listing.stdout.decode("utf-8", "replace")
            if "Wrong password" in text or "Encrypted = +" in text:
                yield "*", None, "password-protected (cannot be analysed)"
                return
            entries, cur = [], {}
            for line in text.splitlines():
                if not line.strip():
                    if "Path" in cur:
                        entries.append(cur)
                    cur = {}
                elif " = " in line:
                    k, v = line.split(" = ", 1)
                    cur[k] = v
            if "Path" in cur:
                entries.append(cur)
            for e in entries[1:]:  # first block describes the archive itself
                if e.get("Folder") == "+":
                    continue
                size = int(e.get("Size") or 0)
                if not _take(budget, size):
                    yield e["Path"], None, f"skipped: too large ({size} bytes)"
                    continue
                r = subprocess.run([SEVENZIP, "e", "-so", "-p-", arc, e["Path"]], capture_output=True, timeout=120)
                yield e["Path"], r.stdout, None


# ---------------------------------------------------------------- pattern rules

def R(pattern: str, flags: int = re.I) -> re.Pattern:
    return re.compile(pattern, flags)


# (severity, rule id, description, regex)
SOURCE_RULES: list[tuple[str, str, str, re.Pattern]] = [
    # exfiltration endpoints
    ("high", "exfil.discord_webhook", "Discord webhook: typical channel for stealing data", R(r"discord(?:app)?\.com/api/webhooks/")),
    ("medium", "net.telegram_bot", "Telegram Bot API (check what is sent and whose token it is)", R(r"api\.telegram\.org/bot")),
    ("high", "exfil.paste", "Paste/temporary file services", R(r"pastebin\.com|hastebin|paste\.ee|transfer\.sh|anonfiles|file\.io|0x0\.st|ngrok\.io|ngrok-free")),
    ("medium", "net.raw_ip", "Hardcoded IP address in a URL", R(r"https?://\d{1,3}(?:\.\d{1,3}){3}")),
    ("info", "net.url", "External URL", R(r"https?://[^\s\"'<>)\]]+")),
    # credential / personal data access
    ("high", "steal.browser", "Access to browser passwords/cookies", re.compile(r"Login Data|Local State|\bCookies\b|\\Google\\Chrome|\\Yandex\\YandexBrowser|\\Opera Software|Mozilla\\Firefox\\Profiles|logins\.json|key4\.db")),
    ("high", "steal.discord_token", "Access to Discord local storage (tokens)", R(r"discord\\Local Storage|leveldb|discordcanary|dQw4w9WgXcQ")),
    ("high", "steal.telegram", "Access to Telegram session (tdata)", R(r"tdata\\|Telegram Desktop")),
    ("high", "steal.crypto", "Access to crypto wallets", R(r"wallet\.dat|Exodus|Electrum|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn")),
    ("medium", "steal.samp_cfg", "Reads SA-MP/launcher settings (nickname, servers, saved passwords)", R(r"USERDATA\.DAT|samp\.saw|sa-mp\.cfg|\\GTA San Andreas User Files\\SAMP|arizona.*launcher.*(?:json|cfg)")),
    ("medium", "steal.password_dialog", "Captures input from dialogs (login/password)", R(r"onSendDialogResponse|sampGetCurrentDialogEditboxText|sampGetDialogEditboxText")),
    ("info", "steal.password_word", "Mentions password/token in code", R(r"\b(?:password|passwd|pass|parol|пароль|token)\b")),
    # execution / download / persistence
    ("high", "exec.shell", "Runs OS commands", R(r"os\.execute|io\.popen|ShellExecute[AW]?\b|WinExec|CreateProcess[AW]?\b|system\s*\(|powershell|cmd(?:\.exe)?\s*/c|mshta|rundll32|regsvr32|certutil|bitsadmin")),
    ("high", "exec.download", "Downloads files from the internet", R(r"downloadUrlToFile|URLDownloadToFile[AW]?")),
    ("medium", "net.http_native", "Native HTTP (WinHTTP/WinINet): check where and what is sent",
     R(r"WinHttpOpen\b|InternetOpen(?:Url)?[AW]?\b|HttpSendRequest[AW]?\b")),
    ("high", "persist.autorun", "Autorun/persistence in Windows", R(r"CurrentVersion\\Run|\\Start Menu\\Programs\\Startup|schtasks|HKEY_LOCAL_MACHINE|RegSetValue|RegCreateKey")),
    ("high", "evasion.av", "Tries to disable or hide from antivirus", R(r"Add-MpPreference|DisableRealtimeMonitoring|ExclusionPath|Set-MpPreference")),
    ("medium", "exec.dynamic_code", "Dynamic code execution (load/loadstring/dofile)", re.compile(r"(?<![\w.:])(?<!function )(?:loadstring|load|dofile|loadfile)\s*\(")),
    ("medium", "exec.ffi_load", "Loads native libraries through FFI", R(r"ffi\.load\s*\(|LoadLibrary[AW]?\b")),
    ("medium", "proc.memory", "Writes into other processes' memory / injection", R(r"WriteProcessMemory|CreateRemoteThread|VirtualAllocEx|NtCreateThreadEx|OpenProcess\b")),
    ("medium", "input.keylogger", "Global key interception (possible keylogger)", R(r"SetWindowsHookEx|GetAsyncKeyState.*for|GetKeyboardState")),
    ("medium", "fs.write_outside", "Writes files outside the game folder", R(r"getenv\s*\(\s*['\"](?:APPDATA|LOCALAPPDATA|TEMP|USERPROFILE)|%APPDATA%|%TEMP%|C:\\\\Windows|C:\\\\Users")),
    ("medium", "fs.delete", "Deletes files/folders", R(r"os\.remove\s*\(|DeleteFile[AW]?\b|RemoveDirectory|rmdir\s|del\s+/[fqs]")),
    ("medium", "update.self", "Self-update: downloads code that can change after moderation", R(r"(?:update|autoupdate|version).{0,80}(?:raw\.githubusercontent|pastebin|gist\.github|http)")),
    ("info", "net.http_lib", "Network library (requests/socket/effil/luasocket/curl)", R(r"require\s*\(?\s*['\"](?:requests|socket(?:\.http)?|ssl\.https|effil|lanes|luacurl|copas|websocket)['\"]")),
    # obfuscation
    ("high", "obf.marker", "Known obfuscator marker", re.compile(r"\b(?:Luraph|MoonSec|IronBrew|Moonveil|wearedevs|Jx-Obfuscator)\b|[Oo]bfuscated (?:with|by)|lua-obfuscator|Lua Obfuscator|Prometheus Obfuscator")),
    ("medium", "obf.string_char", "Long string.char(...) chains (hidden strings)", R(r"string\.char\s*\((?:\s*\d+\s*,){20,}")),
    ("medium", "obf.escape_blob", "Long strings of \\ddd / \\xNN escapes (hidden code)", R(r"(?:\\\d{1,3}|\\x[0-9a-f]{2}){40,}")),
    ("medium", "obf.base64_blob", "Large base64 blob", R(r"[A-Za-z0-9+/]{400,}={0,2}", 0)),
    ("medium", "obf.names", "Names like IlIlIl/l1l1/_0x (obfuscated identifiers)", R(r"\b(?:[Il]{6,}|[Il1]{8,}|_0x[0-9a-f]{4,})\b", 0)),
    ("medium", "obf.bytecode_string", "Embedded Lua/LuaJIT bytecode in a string", R(r"\\27LJ|\\027LJ|\\x1bLJ|\\27Lua|\\x1bLua")),
]

# SQL injection: query text built by concatenation/formatting from variables.
SQL_KW = r"(?:SELECT\s.+?\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|REPLACE\s+INTO|WHERE\s)"
# A string literal (either quote style) containing SQL; the other quote may appear inside it.
SQL_LIT = rf"(?:\"[^\"\n]*{SQL_KW}[^\"\n]*\"|'[^'\n]*{SQL_KW}[^'\n]*')"
SQL_RULES: list[tuple[str, str, str, re.Pattern]] = [
    ("high", "sqli.lua_concat", "SQL is built by string concatenation (..) — possible SQL injection",
     R(rf"{SQL_LIT}\s*\.\.\s*[A-Za-z_]")),
    ("high", "sqli.format_s", "SQL with %s placeholder through string.format/format — possible SQL injection",
     R(rf"(?:string\.format|format|sprintf|snprintf|mysql_format)\s*\([^\n]*{SQL_KW}[^\n]*%s")),
    ("high", "sqli.php_superglobal", "PHP: request data inserted into SQL", R(rf"{SQL_KW}[^\n;]*\$_(?:GET|POST|REQUEST|COOKIE)")),
    ("high", "sqli.concat_generic", "SQL is concatenated with a variable (+ / .)", R(rf"{SQL_LIT}\s*[+.]\s*\$?[A-Za-z_]")),
    ("medium", "sqli.exec", "Raw SQL execution (check that parameters are escaped/bound)",
     R(r"db:exec\s*\(|:execute\s*\(|:query\s*\(|mysql_(?:t|p)?query\s*\(|sqlite3?_exec|db_query\s*\(|mysql_query\s*\(")),
]

PE_SUSPICIOUS_IMPORTS = {
    "URLDownloadToFileA": "download", "URLDownloadToFileW": "download", "InternetOpenA": "network", "InternetOpenW": "network",
    "InternetOpenUrlA": "network", "InternetOpenUrlW": "network", "HttpSendRequestA": "network", "HttpSendRequestW": "network",
    "WinHttpOpen": "network", "WinHttpSendRequest": "network", "send": "socket", "connect": "socket", "WSAStartup": "socket",
    "ShellExecuteA": "exec", "ShellExecuteW": "exec", "ShellExecuteExW": "exec", "WinExec": "exec", "CreateProcessA": "exec", "CreateProcessW": "exec",
    "CryptUnprotectData": "decrypts saved browser passwords (DPAPI)", "RegSetValueExA": "registry", "RegSetValueExW": "registry",
    "SetWindowsHookExA": "keyboard hook", "SetWindowsHookExW": "keyboard hook", "GetAsyncKeyState": "keyboard",
    "CreateRemoteThread": "injection", "WriteProcessMemory": "process memory", "VirtualAllocEx": "injection",
    "IsDebuggerPresent": "anti-debug", "CheckRemoteDebuggerPresent": "anti-debug", "NtQueryInformationProcess": "anti-debug",
    "GetClipboardData": "clipboard", "BCryptDecrypt": "decrypts data (browser cookies)",
}
PACKER_SECTIONS = {"UPX0": "UPX", "UPX1": "UPX", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".themida": "Themida", ".winlice": "WinLicense",
                   ".enigma1": "Enigma", ".enigma2": "Enigma", ".MPRESS1": "MPRESS", ".aspack": "ASPack", ".petite": "Petite",
                   ".nsp0": "NsPack", ".adata": "ASProtect", "pebundle": "PEBundle", ".boom": "The Boomerang", ".obsidium": "Obsidium"}


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _snippet(text: str, pos: int, width: int = 160) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start:end if end != -1 else len(text)].strip()
    if len(line) > width:
        rel = pos - start
        line = line[max(0, rel - width // 2): rel + width // 2]
    return line


def scan_text(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for sev, rule, desc, rx in SOURCE_RULES + SQL_RULES:
        hits = list(rx.finditer(text))
        if not hits:
            continue
        limit = 15 if rule == "net.url" else 5
        seen = set()
        for m in hits:
            ln = _line_of(text, m.start())
            if ln in seen:
                continue
            seen.add(ln)
            if len(seen) > limit:
                break
            findings.append(Finding(sev, rule, desc, path, ln, _snippet(text, m.start())))
        if len(hits) > limit:
            findings.append(Finding("info", rule, f"... and {len(hits) - limit} more matches", path))
    # Shape of the code: obfuscated files have huge lines and high entropy.
    lines = text.splitlines() or [""]
    longest = max(len(l) for l in lines)
    if longest > 5000:
        findings.append(Finding("medium", "obf.long_line", f"Line of {longest} chars (minified/obfuscated code)", path))
    ent = entropy(text.encode("utf-8", "ignore")[:2_000_000])
    if ent > 5.8:
        findings.append(Finding("medium", "obf.entropy", f"High entropy of text {ent:.2f} (encrypted/packed data)", path))
    return findings


def ascii_strings(data: bytes, min_len: int = 6) -> str:
    parts = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    wide = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)
    return "\n".join(p.decode("ascii") for p in parts) + "\n" + "\n".join(w.decode("utf-16le", "ignore") for w in wide)


def scan_pe(path: str, data: bytes) -> tuple[dict, list[Finding]]:
    import pefile
    findings: list[Finding] = []
    info: dict = {}
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as e:
        return {"error": f"not a valid PE: {e}"}, [Finding("medium", "pe.invalid", f"Damaged PE: {e}", path)]
    info["machine"] = "x86" if pe.FILE_HEADER.Machine == 0x14c else "x64" if pe.FILE_HEADER.Machine == 0x8664 else hex(pe.FILE_HEADER.Machine)
    info["dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    info["dotnet"] = bool(getattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR", None))
    info["timestamp"] = pe.FILE_HEADER.TimeDateStamp
    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1")
        ent = s.get_entropy()
        sections.append({"name": name, "size": s.SizeOfRawData, "entropy": round(ent, 2)})
        if name in PACKER_SECTIONS:
            findings.append(Finding("high", "pe.packer", f"Packer/protector {PACKER_SECTIONS[name]} (section {name}) — forbidden by the rules: protected from analysis", path))
        elif ent > 7.2 and s.SizeOfRawData > 4096:
            findings.append(Finding("medium", "pe.high_entropy", f"Section {name} has entropy {ent:.2f}: packed/encrypted", path))
    info["sections"] = sections
    imports: dict[str, list[str]] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("latin-1")
        imports[dll] = [i.name.decode("latin-1") for i in entry.imports if i.name]
    info["imports"] = {k: (v[:40] + ([f"... +{len(v) - 40}"] if len(v) > 40 else [])) for k, v in imports.items()}
    flat = {n for v in imports.values() for n in v}
    sus = {n: why for n, why in PE_SUSPICIOUS_IMPORTS.items() if n in flat}
    if sus:
        sev = "high" if any(w in ("download", "decrypts saved browser passwords (DPAPI)", "decrypts data (browser cookies)") for w in sus.values()) else "medium"
        findings.append(Finding(sev, "pe.imports", "Suspicious imports: " + ", ".join(f"{k} ({v})" for k, v in sus.items()), path))
    if len(flat) < 8 and not info["dotnet"]:
        findings.append(Finding("medium", "pe.few_imports", f"Only {len(flat)} imports: sign of a packer/manual import resolution", path))
    if info["dotnet"]:
        findings.append(Finding("info", "pe.dotnet", ".NET assembly: decompile with dnSpy/ILSpy to review the code", path))
    # overlay (data appended after the image) often hides a payload
    overlay = pe.get_overlay_data_start_offset()
    if overlay and len(data) - overlay > 1024:
        findings.append(Finding("medium", "pe.overlay", f"{len(data) - overlay} bytes appended after the PE (overlay)", path))
    findings += [f for f in scan_text(path, ascii_strings(data)) if f.rule not in ("obf.entropy", "obf.long_line", "obf.names", "obf.base64_blob")]
    for f in findings:
        if f.line is not None and f.rule not in ("pe.imports",):
            f.line = None  # line numbers of extracted strings are meaningless
    return info, findings


def analyze_member(m: Member) -> dict:
    kind = sniff(m.data, m.path) if m.data else "archive" if m.note and "archive" in m.note else "unavailable"
    report: dict = {"path": m.path, "type": kind}
    if m.note:
        report["note"] = m.note
    if not m.data:
        findings = []
        if m.note and "password" in m.note:
            findings.append(Finding("high", "archive.encrypted", "Password-protected archive: contents cannot be checked (classic way to hide malware)", m.path))
        report["findings"] = [f.as_dict() for f in findings]
        return report
    report["size"] = len(m.data)
    report["sha256"] = hashlib.sha256(m.data).hexdigest()
    findings: list[Finding] = []
    ext = os.path.splitext(m.path.lower())[1]
    if kind == "text":
        text = decode_text(m.data)
        report["lines"] = text.count("\n") + 1
        findings = scan_text(m.path, text)
    elif kind in ("lua_bytecode", "luajit_bytecode"):
        findings.append(Finding("high", "lua.bytecode", "Compiled Lua bytecode (.luac): source closed — the rules forbid software protected from analysis in pre-moderated sections", m.path))
        findings += [f for f in scan_text(m.path, ascii_strings(m.data, 5)) if f.rule.split(".")[0] in ("exfil", "steal", "exec", "persist", "evasion", "net")]
    elif kind == "pe":
        report["pe"], findings = scan_pe(m.path, m.data)
        if ext in (".scr", ".com", ".pif"):
            findings.append(Finding("high", "pe.ext", f"Executable with extension {ext}", m.path))
    elif kind == "cleo_compiled":
        findings.append(Finding("info", "cleo.compiled", "Compiled CLEO script: decompile with Sanny Builder to review", m.path))
        findings += scan_text(m.path, ascii_strings(m.data, 5))
    else:
        findings += [f for f in scan_text(m.path, ascii_strings(m.data)) if f.severity == "high"]
    if re.search(r"\.(?:lua|txt|png|jpg|pdf|cs)\.(?:exe|scr|bat|cmd|vbs|js)$", m.path, re.I):
        findings.append(Finding("high", "file.double_ext", "Double extension: disguised executable", m.path))
    if ext in (".bat", ".cmd", ".vbs", ".ps1", ".js", ".hta", ".lnk", ".scr"):
        findings.append(Finding("medium", "file.script", f"Windows script/executable file ({ext}) inside the release", m.path))
    report["findings"] = [f.as_dict() for f in findings]
    return report


SEV_ORDER = {"high": 0, "medium": 1, "info": 2}


def analyze(name: str, data: bytes) -> dict:
    members = unpack(name, data)
    files = [analyze_member(m) for m in members]
    counts = {"high": 0, "medium": 0, "info": 0}
    for f in files:
        f["findings"].sort(key=lambda x: SEV_ORDER[x["severity"]])
        for x in f["findings"]:
            counts[x["severity"]] += 1
    return {
        "name": name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "files": files,
        "summary": counts,
        "note": "Static heuristics only, nothing was executed. Read the flagged lines with read_attachment before deciding.",
    }


def read_member(name: str, data: bytes, member: str | None) -> tuple[str, bytes]:
    members = [m for m in unpack(name, data) if m.data]
    if member:
        found = [m for m in members if m.path == member or m.path.endswith("/" + member)]
        if not found:
            raise ValueError(f"No file '{member}'. Files: {[m.path for m in members]}")
        return found[0].path, found[0].data
    if len(members) == 1:
        return members[0].path, members[0].data
    raise ValueError(f"Archive has several files, pass member=. Files: {[m.path for m in members]}")
