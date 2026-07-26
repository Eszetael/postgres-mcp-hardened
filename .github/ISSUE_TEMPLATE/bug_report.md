---
name: Bug report
about: Something behaves differently from what the documentation says
labels: bug
---

**What happened**

**What you expected**

**Reproduction** — the SQL, the tool call, or the configuration. A failing command is worth more
than a description.

**Environment**
- Server version (`postgres-mcp-hardened --validate "SELECT 1"` prints nothing useful; use the release tag):
- PostgreSQL version and where it runs (RDS, Supabase, Neon, self-hosted, Docker):
- Client (Claude Desktop, Cursor, custom) and transport (stdio or HTTP):

**Server output** — the stderr lines around the failure. Configuration errors print their reason
and exit with status 2; connection failures name the cause on the first query.
