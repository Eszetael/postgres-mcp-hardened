# .mcpb bundle

A one-file installer for MCP clients that accept `.mcpb` bundles (stdio transport).

1. Copy the release binary for the target platform to `bin/postgres-mcp-hardened`
   (`.exe` on Windows — mcpb appends the extension automatically).
2. Optionally add `icon.png` and reference it from the manifest with `"icon": "icon.png"`.
3. Pack the directory:

   ```bash
   npx @anthropic-ai/mcpb pack .
   ```

The manifest declares one user-supplied configuration value, `DATABASE_URL`, and marks it
sensitive so the client stores it in the OS keychain rather than in plain text.

## It is built by CI, not by hand

Since 0.1.7 the release workflow validates this manifest and packs one bundle per platform from the
binary it has just built, then attaches them to the GitHub release. Doing it by hand is what let the
manifest sit invalid from July until 17 August 2026: `repository` was a string where the schema
requires an object, so `mcpb pack` would have refused — except nobody ever ran it.

`tests/docs_claims.sh` now validates the manifest on every commit (Control F), so the same thing
cannot happen quietly again.
