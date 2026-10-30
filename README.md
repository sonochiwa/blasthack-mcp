# BlastHack MCP

`blasthack-mcp.exe` is an MCP server that lets Claude help **blast.hk**
moderators review the approval queue.

Reviewing a release means opening every attachment, reading the code for
stealers and checking the topic against the section rules. The server gives
Claude the forum pages, the attached files and the rules, so Claude goes
through the queue one item at a time and proposes a decision with reasons.
Every action on the site is previewed first and sent only after the moderator
confirms it; nothing from an attachment is ever executed.

## Features

- Reads sections, threads and posts; search tells deleted and unapproved
  threads apart and shows who deleted a thread and why.
- Scans attachments in memory for stealers, downloaders, autorun,
  obfuscation, compiled Lua, packers and SQL injection; unpacks zip, 7z and
  rar.
- Shows any lines of an attachment or of a file inside its archive.
- Approves and rejects queue items, edits posts and moves threads, each with
  a dry-run preview.
- Checks on the site that every action took effect and writes it to a
  decision log in Documents.
- Refuses a rejection reason longer than the site accepts and a move that
  would hide an unapproved thread from you.
- Acts as the account whose cookies it is given, with that account's rights.

## Requirements

- Windows 10 or later, 64-bit.
- An MCP client, such as Claude Code or Claude Desktop.
- A blast.hk moderator account.

## Installation

1. Extract `blasthack-mcp.exe` into a permanent folder.
2. Sign in to blast.hk in a browser with "Remember me"; with two-factor
   authentication also tick "Trust this device". Copy the `xf_user` and
   `xf_tfa_trust` cookies from the browser developer tools (F12,
   Application, Cookies).
3. Register the server in Claude Code:

   ```powershell
   claude mcp add blasthack --scope user -e BLASTHACK_COOKIES="xf_user=...; xf_tfa_trust=..." -- "C:\Tools\blasthack-mcp.exe"
   ```

   or in the `mcpServers` section of `claude_desktop_config.json`:

   ```json
   "blasthack": {
     "command": "C:\\Tools\\blasthack-mcp.exe",
     "env": { "BLASTHACK_COOKIES": "xf_user=...; xf_tfa_trust=..." }
   }
   ```

4. Start a new session and ask Claude to call `whoami`.

The cookies give full access to the moderator account: never share them.
Signing out on the site revokes them. `xf_tfa_trust` expires after a while;
the server then reports that two-factor authentication is required, and the
cookie has to be copied again.

## Configuration

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `BLASTHACK_COOKIES` | | Cookie string: `xf_user=...; xf_tfa_trust=...` |
| `BLASTHACK_XF_USER` | | The `xf_user` cookie alone, for accounts without two-factor authentication |
| `BLASTHACK_READONLY` | `0` | `1` refuses every action on the site; reading and scanning still work |
| `BLASTHACK_LOG` | `Documents\blasthack-moderation-log.txt` | Decision log file |
| `BLASTHACK_MAX_ATTACHMENT_MB` | `100` | Largest attachment the server downloads |
| `BLASTHACK_MAX_POST_CHARS` | `6000` | Post length shown in lists before it is cut |

## Release Integrity

Releases are built by GitHub Actions from the tagged commit and carry a
SHA-256 file and a build-provenance attestation:

```powershell
gh attestation verify blasthack-mcp-v1.0.0.zip -R sonochiwa/blasthack-mcp
```

## License

MIT. See [LICENSE](LICENSE).
