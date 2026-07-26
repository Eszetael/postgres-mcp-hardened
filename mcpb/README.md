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
