# postgres-mcp-hardened

A maintained, read-only PostgreSQL MCP server — the drop-in replacement for
[`@modelcontextprotocol/server-postgres`](https://www.npmjs.com/package/@modelcontextprotocol/server-postgres),
which was deprecated by its authors and last released in December 2024.

Writes are refused by walking the parsed SQL, not by matching strings. Comments, dollar-quoting and
Unicode tricks do not survive the parse, so they cannot smuggle a statement past the check.

## Replace the deprecated server

```diff
 {
   "mcpServers": {
     "postgres": {
-      "command": "npx",
-      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/mydb"]
+      "command": "npx",
+      "args": ["-y", "postgres-mcp-hardened", "--stdio"],
+      "env": { "DATABASE_URL": "postgres://readonly_user:PASSWORD@localhost:5432/mydb" }
     }
   }
 }
```

The connection string moves from an argument to `DATABASE_URL` on purpose: arguments show up in
`ps` output and in shell history on a shared machine, and a database password does not belong there.

## What it does differently

- **Read-only is enforced twice.** The validator rejects anything that is not a read, and the
  session runs in a `READ ONLY` transaction — so a gap in the first layer is not a breach.
- **Statement timeout and row caps** are set server-side, so a careless question cannot pin your
  database or drag a million rows into a model's context.
- **Every query is written to an audit log** chained by hash, which survives a restart and makes
  a deleted or truncated tail detectable.
- **Optional OAuth (RS256)** with audience and issuer enforced, for running it as a shared HTTP
  endpoint rather than a local process.
- **Signed releases** — every artefact carries a Sigstore signature and a SHA-256, and this package
  refuses to install a binary whose checksum does not match the one recorded at publish time.

## Install

```bash
npx -y postgres-mcp-hardened --stdio       # no install
npm install -g postgres-mcp-hardened       # or keep it around
```

The package fetches a prebuilt binary for your platform from the matching GitHub release:
Linux (x64, arm64), macOS (Intel, Apple Silicon) and Windows (x64). Alpine/musl is not among them —
the Linux builds link against glibc; use the container image `ghcr.io/eszetael/postgres-mcp-hardened`
or build from source with `cargo build --release` in a clone.

Full documentation, configuration reference and the security model:
**https://github.com/Eszetael/postgres-mcp-hardened**

MIT licensed.
