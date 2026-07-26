# postgres-mcp-hardened

**The official Postgres MCP server was deprecated in 2024 and still gets ~440k downloads a month. Its entire defence is one database-level read-only transaction — and that alone does not stop every write. This is a maintained Rust replacement with defence in depth.**

A drop-in [Model Context Protocol](https://modelcontextprotocol.io) server that lets an AI agent query PostgreSQL — **read-only, enforced at the database level**, with real SQL validation, timeouts, cost limits, OAuth 2.1, and an audit trail. Speaks **Streamable HTTP** (2026 transport) and stdio.

## Why

`@modelcontextprotocol/server-postgres` is **deprecated on npm** (last publish December 2024) and
still sees **~440,000 downloads a month**. Credit where it is due: its approach is not naive — it
wraps each query in `BEGIN TRANSACTION READ ONLY` and always `ROLLBACK`s, which is a real defence
and one this server now adopts as well.

The problem is that it is the *only* defence, and it is not complete:

- **A read-only transaction does not block every write.** PostgreSQL executes
  `pg_import_system_collations()` inside `SET TRANSACTION READ ONLY` without raising `SQLSTATE 25006`
  — it inserted 874 rows into `pg_collation` in our tests. `gin_clean_pending_list()` rewrites index
  structures; `pg_backup_start()` puts the server into backup mode and survives `DISCARD ALL`. The
  rollback saves you from the first case, not from the side effects that live outside transaction
  semantics.
- **No statement timeout, no cost guard, no row limit** — one query can run until the server gives up.
- **No authentication, no audit trail, no handling of prompt injection** through returned row data.
- 113 lines, unmaintained since 2024, no test suite.

This server keeps the rollback, adds AST validation in front of it, and adds the operational layers
the original never had.

## `postgres-mcp-hardened` vs the archived original

| | archived `server-postgres` | **postgres-mcp-hardened** |
|---|---|---|
| Read-only enforcement | `BEGIN TRANSACTION READ ONLY` + `ROLLBACK` — one layer, and PostgreSQL lets some writes through it | **AST validation (sqlparser)** *plus* the same read-only transaction and rollback, *plus* a denylist for functions that write despite it |
| Multi-statement / `DROP` via CTE | reaches the database and is stopped only by the transaction | rejected by the parser, before it reaches the database |
| Statement timeout | none | `statement_timeout` + `idle_in_transaction_session_timeout` enforced |
| Runaway / expensive queries | run unbounded | **`EXPLAIN` cost guard** rejects them before execution |
| Prompt injection via row data | raw output | wrapped `trusted="false"` + delimiter escaping |
| Error messages | leak schema (`relation X does not exist`) | structured, non-leaking, actionable |
| Auth | none | **OAuth 2.1** (RS256 JWT, scope + audience + issuer) |
| Audit | none | tamper-evident hash-chained log |
| Schema as MCP resources | ✅ | ✅ — plus comments, primary and foreign keys |
| Tests / CI | none | 25 tests, fuzz harness, clippy + `cargo audit` + container build on every push |
| Transport | stdio / deprecated SSE | **Streamable HTTP** + stdio |
| Maintained | ❌ deprecated since 2024 | ✅ |

## Install

```bash
cargo install postgres-mcp-hardened   # (name pending final publish)
```

### Use it in Claude Desktop / Cursor (stdio)

```json
{
  "mcpServers": {
    "postgres": {
      "command": "postgres-mcp-hardened",
      "args": ["--stdio"],
      "env": { "DATABASE_URL": "postgres://readonly_user:YOUR_PASSWORD@localhost:5432/mydb" }
    }
  }
}
```

### Or run it as a remote server (Streamable HTTP)

```bash
DATABASE_URL="postgres://readonly_user:YOUR_PASSWORD@host:5432/mydb" \
MCP_ADDR="0.0.0.0:8080" \
postgres-mcp-hardened
# POST /mcp   ·   GET /health   ·   GET /ready   ·   GET /metrics
```

> **TLS:** connections to PostgreSQL are encrypted whenever the server supports it, and
> `sslmode=require`, `verify-ca` and `verify-full` are all accepted (the certificate chain *and*
> the hostname are always verified, so `require` behaves like `verify-full`) — so managed Postgres (RDS, Supabase, Neon, Render)
> works out of the box. Certificates are **always verified**; for a private CA, point
> `MCP_SSLROOTCERT` at the PEM bundle. There is no "trust anything" switch.
>
> **Tip:** point `DATABASE_URL` at a **least-privilege read-only role**. The server enforces read-only itself, but a scoped DB role is defense-in-depth.

## Migrating from the deprecated server

The most-discussed problems reported against `@modelcontextprotocol/server-postgres` were
reproduced against this server; here is how each behaves:

| What people reported | Here |
|---|---|
| Two instances (prod + dev) are indistinguishable, the client picks one | Resource URIs carry the database name (`postgres:///mydb/public/orders/schema`) and `MCP_SERVER_LABEL` names the instance in the client UI |
| One database per instance, because the connection string is a command-line argument | `MCP_DATABASE_URLS="prod=…;dev=…"` serves several databases from one server; every tool takes an optional `database`, and resources span all of them |
| `no pg_hba.conf entry … SSL off` | The error says the server requires TLS and names the fix (`?sslmode=require`) |
| Read-only bypassed by injecting `COMMIT` / `END` | Rejected — the multi-statement gate works on tokens, before the parser, and `COMMIT` alone is refused as a write |
| `spawn npx ENOENT`, Node version problems | A single static binary; no Node, no npx, no `node_modules` |
| Hangs indefinitely against RDS with no output or error | Bounded: an unreachable host answers in ~8 s with the reason, never silently |
| `self-signed certificate in certificate chain` | Point `MCP_SSLROOTCERT` at the CA bundle; the error names that variable |
| Connection string only as a command-line argument | `DATABASE_URL` **or** the positional argument — the original invocation keeps working |
| `INVALID_URL` with special characters in the password | The error says which characters to percent-encode, and how |
| Partition children flood the table and resource lists | Hidden by default; `MCP_SHOW_PARTITIONS=1` brings them back |
| `-32601 Method not found`, `Unexpected end of JSON input` | `ping` and resources implemented; multi-line JSON is buffered until complete; batches are refused with a clear error rather than silence |
| No row limit — one query floods the context | Auto-`LIMIT`, an 8 MB byte cap, and an explicit `truncated` flag |

## Resources

Every table and view is exposed as an MCP **resource** (`postgres:///<schema>/<table>/schema`), so a
client can browse the schema without issuing a query — the same capability the deprecated server
offered, plus column comments, primary keys and **foreign keys** in the payload.

## Tools

- **`query`** — run a read-only SQL query (validated, auto-`LIMIT`, cost-guarded).
- **`list_schemas`**, **`list_tables`**, **`describe_table`** — progressive schema discovery
  (parameterized, injection-safe). `describe_table` returns the **schema comments**
  (`COMMENT ON TABLE/COLUMN`), primary keys, **foreign keys** and defaults, so the agent reads what a
  column *means* and what it points at instead of guessing from its name — and a missing table is an
  error, not an empty column list.

## Security model

- **Encrypted transport:** TLS to PostgreSQL via rustls (no OpenSSL in the image), certificate
  verification always on, private CAs via `MCP_SSLROOTCERT`.
- **Read-only, two ways:** every statement is parsed with `sqlparser` and rejected unless it's a `SELECT`/`WITH`/`EXPLAIN`/`SHOW`; the DB session is additionally set `default_transaction_read_only = on`.
- **Anti-DoS:** enforced `statement_timeout`, auto-injected `LIMIT`, and an `EXPLAIN`-based cost guard that rejects expensive plans before they run.
- **Prompt-injection aware:** row data is returned inside a `trusted="false"` provenance block with delimiters escaped, so a malicious cell can't hijack the agent.
- **No schema leaks:** database errors are mapped to structured, actionable messages that never echo table/column names.
- **OAuth 2.1:** optional RS256 bearer-token validation (signature, `exp`, `aud`, `iss`) with scope enforcement; disabled when unconfigured for local/self-host use.
- **Audit:** every tool decision is logged as a tamper-evident, hash-chained JSON line (no raw SQL).
- **Runtime:** ships as a distroless, non-root container (~34 MB, built and smoke-tested in CI).

## Configuration

| Env | Purpose |
|-----|---------|
| `DATABASE_URL` | PostgreSQL connection string (use a read-only role) |
| `MCP_ADDR` | HTTP listen address (default `127.0.0.1:8080`) |
| `MCP_MAX_COST` | reject queries whose `EXPLAIN` cost exceeds this (default 1,000,000) |
| `JWT_PUBKEY_PEM`, `JWT_AUD`, `JWT_ISS` | enable OAuth 2.1 token validation (omit to disable auth) |
| `MCP_AUDIT_LOG` | path to the append-only audit log (hash-chained); verify with `--verify-audit <file> [--expect-last <hash>]` |
| `MCP_AUDIT_HMAC_KEY` / `MCP_AUDIT_HMAC_KEY_FILE` | key that turns the audit chain into HMAC-SHA256 — keep it off the host so the log cannot be rewritten (a trailing newline in the file is ignored) |
| `MCP_AUDIT_HMAC_KEYS_OLD` | comma-separated previous keys, so a log that survived a key rotation still verifies |
| `MCP_DATABASE_URLS` | several databases from one server: `prod=postgres://…;dev=postgres://…` (tools then take a `database` argument) |
| `MCP_SERVER_LABEL` | name shown in the client UI, e.g. `production` → `postgres-mcp-hardened (production)` |
| `MCP_SHOW_PARTITIONS` | `1` to list partition children as well (hidden by default) |
| `MCP_ALLOW_FUNCTIONS` | comma-separated catalog functions to permit that we do not know to be read-only |
| `MCP_SSLROOTCERT` | path to a PEM CA bundle for TLS to PostgreSQL (e.g. the AWS RDS bundle); system and Mozilla roots are trusted by default |
| `MCP_MAX_INFLIGHT_PER_CLIENT` | max concurrent requests from one client (default 4; `0` disables) |
| `MCP_RATE_RPM` | per-client request rate limit (default 120/min; `0` disables) |
| `MCP_RATE_BURST` | burst allowance for that limit (default `MCP_RATE_RPM / 4`, min 5) |
| `MCP_TRUST_PROXY` | set to `1` only behind a reverse proxy — then the rate limiter keys on `X-Forwarded-For` instead of the peer address |

## License

MIT — see [LICENSE](./LICENSE).
