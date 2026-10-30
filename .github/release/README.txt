BlastHack MCP v{version}
https://github.com/sonochiwa/blasthack-mcp

MCP server that lets an AI assistant (Claude, Codex or another MCP client)
help blast.hk moderators review the approval queue. Windows 10 or later,
64-bit.

Installation
  Extract blasthack-mcp.exe into a permanent folder, then register it in
  your MCP client with your blast.hk cookies:

  claude mcp add blasthack --scope user
    -e BLASTHACK_COOKIES="xf_user=...; xf_tfa_trust=..."
    -- "C:\Tools\blasthack-mcp.exe"

  Keep the cookies private: they give full access to your account.
  Full instructions: see the link above.

Created by sonochiwa. MIT license.
