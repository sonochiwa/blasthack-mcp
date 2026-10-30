# Changelog

## 1.1.0

- Added the `moderation_guide` tool and the `review_queue` prompt, so Codex and
  other clients that do not show server instructions follow the review rules.
- Added `BLASTHACK_GUIDE` to replace the built-in review instructions without
  rebuilding.
- Changed the review instructions into `cmd/mcp/guide.md`, a Markdown file
  compiled into the executable.

## 1.0.0

- Added a single-file MCP server for blast.hk moderators: forum reading, search
  that tells deleted and unapproved threads apart, and the forum rules.
- Added attachment scanning for stealers, downloaders, obfuscation, packers and
  SQL injection, including zip, 7z and rar archives, without running anything.
- Added approval queue, post edit and thread move tools with dry-run previews,
  checks on the site and a decision log in Documents.
