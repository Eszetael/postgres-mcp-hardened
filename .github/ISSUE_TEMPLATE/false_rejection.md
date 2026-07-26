---
name: A read-only query was refused
about: The validator rejected something that only reads
labels: false-positive
---

Fail-closed means we will occasionally refuse a legitimate read. Those reports are valuable —
please include:

**The statement** (exactly, so it can go into the regression corpus):

```sql
```

**What the server said** — run it offline, no database required:

```bash
postgres-mcp-hardened --validate "<your statement>"
```

**Why it is read-only** — especially if it calls a `pg_*` function we do not yet know about. As an
immediate workaround, `MCP_ALLOW_FUNCTIONS=name` permits a specific catalog function.
