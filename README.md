# BlastHack MCP

`blasthack-mcp.exe` is an MCP server that lets an AI assistant, such as
**Claude** or **Codex**, help **blast.hk** moderators review the approval queue.

Reviewing a release means opening every attachment, reading the code for
stealers and checking the topic against the section rules. The server gives
the assistant the forum pages, the attached files and the rules, so it goes
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
- Sends its review instructions as server instructions, as the
  `moderation_guide` tool and as the `review_queue` prompt, so clients that
  ignore server instructions still follow them.

## Requirements

- Windows 10 or later, 64-bit.
- An MCP client, such as Claude Code, Claude Desktop or Codex.
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

   in the `mcpServers` section of `claude_desktop_config.json`:

   ```json
   "blasthack": {
     "command": "C:\\Tools\\blasthack-mcp.exe",
     "env": { "BLASTHACK_COOKIES": "xf_user=...; xf_tfa_trust=..." }
   }
   ```

   or in Codex, in `%USERPROFILE%\.codex\config.toml`:

   ```toml
   [mcp_servers.blasthack]
   command = 'C:\Tools\blasthack-mcp.exe'

   [mcp_servers.blasthack.env]
   BLASTHACK_COOKIES = "xf_user=...; xf_tfa_trust=..."
   ```

4. Start a new session and ask the assistant to call `whoami`. In a client
   that does not show server instructions, start with "read
   moderation_guide and review the queue".

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
| `BLASTHACK_GUIDE` | | Text file that replaces the built-in review instructions |

The built-in review instructions are [cmd/mcp/guide.md](cmd/mcp/guide.md):
Markdown in Russian, compiled into the executable. To change how the
assistant works, copy that file, edit it and point `BLASTHACK_GUIDE` at the
copy, or edit it and build again; a missing or empty file falls back to the
built-in text.

## Release Integrity

Releases are built by GitHub Actions from the tagged commit and carry a
SHA-256 file and a build-provenance attestation:

```powershell
gh attestation verify blasthack-mcp-v1.0.0.zip -R sonochiwa/blasthack-mcp
```

## License

MIT. See [LICENSE](LICENSE).
