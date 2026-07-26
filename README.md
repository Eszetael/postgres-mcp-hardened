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

## Testing

Beyond unit tests, the repository carries two harnesses that run in CI on every change:

- `--fuzz` — a deterministic fuzzer that mutates a corpus of known writes with transformations
  that do not change SQL meaning (comments, case, dollar-quoting, invisible Unicode, parentheses)
  and asserts that none of them ever becomes an allowed statement.
- `tests/acceptance.sh` — an end-to-end suite that starts its own PostgreSQL and checks 43
  behaviours: every write-bypass reported against the deprecated server (including the
  `COMMIT`/`END` injection), truthful results, schema introspection, protocol conformance,
  configuration mistakes failing loudly, audit tamper detection, fair use under load, and
  multi-database deployments.

## Every reported problem, answered

[`docs/COMMUNITY_ISSUES.md`](docs/COMMUNITY_ISSUES.md) is the complete ledger: every problem
reported against the deprecated server and every open issue against the maintained alternatives,
each with what happens here — including the handful we could not fix in code, said plainly.

## What we learned from the alternatives

Every server in this space has an issue tracker, and those trackers are a map of what goes wrong.
The ones we deliberately built against:

- **A published image that lags the code.** The most-supported open complaint against the leading
  alternative. Our container is built and pushed from the same tag that produces the binaries, so
  it cannot drift.
- **A hardcoded query timeout.** Also among their most requested settings. `MCP_STATEMENT_TIMEOUT`
  is configurable and validated at startup.
- **Unrestricted access by default.** Some servers default to read/write and rely on the operator
  to restrict it. This one has no write path at all.
- **Credentials in the client configuration.** `MCP_PASSWORD_FILE` keeps the password out of it.
- **Tables in a non-default schema silently not found.** `MCP_SEARCH_PATH` fixes the lookup, and
  the tools take an explicit `schema` anyway.
- **Deprecated transport.** SSE was replaced by Streamable HTTP in the 2025-06-18 specification;
  we speak the current one.

## Troubleshooting

Answers to the questions people actually asked about the deprecated server, so nobody has to open
an issue to find them.

**`spawn npx ENOENT` / "which Node version do I need?"** — none. This is a single static binary.
Download it from the releases page (or `cargo install postgres-mcp-hardened`) and point your client
at the file. There is no `node_modules`, no `npx`, nothing to keep up to date.

**"The server starts but nothing is listening on a port."** — that is stdio mode, which is correct
for Claude Desktop and Cursor: the client talks to the process over its standard input and output,
not over a socket. If you want a network endpoint, start it without `--stdio`; it then prints
`MCP HTTP listening on http://…` and speaks Streamable HTTP.

**"Can my client on another machine reach the database?"** — yes: run the server next to the
database in HTTP mode, expose it, and enable OAuth (`JWT_PUBKEY_PEM`, `JWT_AUD`, `JWT_ISS`). The
database credentials then never leave the host the server runs on.

**"Could not attach to MCP server."** — the process exited before the handshake. Run the same
command in a terminal: a configuration mistake prints its reason and exits with status 2 rather
than dying quietly, and a connection problem is reported on the first query with the cause.

**`self-signed certificate in certificate chain` / `unable to verify the first certificate`** —
your provider uses a private CA (Supabase, GCP and RDS all do). Download their CA bundle and set
`MCP_SSLROOTCERT` to it. The error message names the step for your provider. We do not offer a
"trust anything" switch.

### Managed providers

This server **always verifies the database certificate**, including with `sslmode=require`. That is
a deliberate deviation from libpq, where `require` encrypts without verifying and a machine in the
middle can therefore read and rewrite every query and result without anyone noticing. The cost of
being strict is that a provider with a private CA needs one extra step; the cost of being lax is
that you never find out. If you disagree with the trade-off, `verify-full` with the bundle below is
the same amount of work and leaves no doubt either way.

| Provider | What to expect |
|---|---|
| **Supabase** | Private CA. Dashboard → Project Settings → Database → SSL configuration → download the certificate, then set `MCP_SSLROOTCERT` to it. The direct host (`db.<ref>.supabase.co`) is **IPv6-only** — on an IPv4 network use the Supavisor pooler string (port 6543), which also fits serverless and short-lived connections. |
| **Amazon RDS / Aurora** | Private CA: `https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`. IAM authentication works — put the generated token in the password field, and remember it expires in 15 minutes. |
| **Google Cloud SQL** | Private CA: Connections → Security → `server-ca.pem`. Through the Cloud SQL Auth Proxy, connect to the proxy on localhost and TLS is the proxy's business. |
| **Azure Database for PostgreSQL** | Public CA — nothing to download. Azure rotated its root to DigiCert Global Root G2 during Q1 2026; we ship the Mozilla root store, so the rotation needs nothing from you. |
| **Neon** | Public CA (ISRG Root X1, Let's Encrypt) — nothing to download. Pooled and direct endpoints both work. |
| **DigitalOcean** | Private CA: download the certificate from the cluster's Overview page. |

Not sure which case you are in? Ask the server itself, before configuring anything:

```bash
echo | openssl s_client -starttls postgres -connect YOUR_HOST:5432 2>/dev/null \
  | openssl x509 -noout -issuer
```

A well-known issuer (DigiCert, ISRG, Google Trust Services) means it will just work; anything
naming your provider means you need their bundle.

With a connection pooler (Supavisor, PgBouncer) in transaction mode, note that this server sets
`statement_timeout` and `idle_in_transaction_session_timeout` per session and runs every query in an
explicit read-only transaction. Both are compatible with transaction pooling; session-level
`SET` outside a transaction is not, which is why we do neither.

**`no pg_hba.conf entry … no encryption`** — the server accepts only TLS connections for that
host and user. Add `?sslmode=require` to the connection string.

**`INVALID_URL` / `invalid connection string`** — a password containing `@`, `:`, `/`, `#` or `?`
must be percent-encoded (`@` → `%40`, `:` → `%3A`, `/` → `%2F`, `#` → `%23`).

**"My table has hundreds of partitions and the list is unusable."** — partition children are hidden
by default; the parent is listed. Set `MCP_SHOW_PARTITIONS=1` if you need them.

**"I need production and staging at the same time."** — either run one server per database (they
are distinguishable: set `MCP_SERVER_LABEL`), or configure both in one server with
`MCP_DATABASE_URLS` and pass `database` in the tool arguments.

## Resources

Every table and view is exposed as an MCP **resource** (`postgres:///<schema>/<table>/schema`), so a
client can browse the schema without issuing a query — the same capability the deprecated server
offered, plus column comments, primary keys and **foreign keys** in the payload.

## Tools

- **`explain_query`** — the execution plan; with `analyze` it runs the statement and reports real
  timings and buffer usage, which is safe here because the statement is validated read-only and runs
  inside a transaction that is always rolled back. The plan comes with a `summary`: which node spent
  the time (self time, not inclusive), and where the planner's row estimate was furthest from
  reality — because a bad estimate is usually why the plan is bad.
- **`database_health`** — cache hit ratio, connections (this database and the cluster), the longest
  running statement and the longest abandoned transaction as separate figures, vacuum backlog,
  invalid indexes, sequences near their ceiling, replication lag, **tables that have never been
  analysed** (no planner statistics — the usual reason a database looks healthy and runs slowly), and
  the window the counters cover. Anything the role cannot see is declared rather than returned as a
  confident zero.
- **`analyze_indexes`** — unused indexes, duplicates, and tables scanned sequentially often enough
  that an index would pay off.
- **`top_queries`** — the heaviest statements, from `pg_stat_statements`.
- **`query`** — run a read-only SQL query (validated, auto-`LIMIT`, cost-guarded). The response
  states what it did: `returnedRows`, `appliedLimit`, `truncated`, plus `requestedLimit` when a
  larger request was capped at the 10000-row maximum, `offset` when paging, and `redactedColumns`
  when masking is configured — so an agent never has to guess whether it received the whole answer.
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
- **Sensitive columns — defence in depth, and honest about it:** `MCP_REDACT_COLUMNS` masks values
  at every depth and refuses to run a query that references those columns, including the ways round
  it that an adversarial panel actually found — renaming (`SELECT password AS pw`), wrapping
  (`md5(password)`), serialising the whole row (`row_to_json(t)`, `t::text`, `json_agg(t)`), and
  naming the column as a string rather than an identifier (`to_jsonb(t) ->> 'password'`,
  `#>> '{password}'`, `$.password`), whole-row wildcards (`ROW(t.*)::text`) and positional renaming
  (`(SELECT * FROM staff) AS x(c1, …, c9)`). It is still name-based filtering, and name-based
  filtering cannot be a boundary against the whole SQL language — three adversarial rounds each got
  past it through a shape nobody had listed.

  So the server stops asserting and **asks the database**: at startup it reports every table where
  the connected role can still read a redacted column, with the exact statements that fix it, and
  `MCP_REDACT_REQUIRE_REVOKE=1` turns that report into a refusal to run. Note the fix is a table-level
  `REVOKE` followed by a `GRANT` of the columns that stay — a bare `REVOKE SELECT (password) ON staff`
  is silently a no-op while the role holds SELECT on the whole table. With column-level grants
  PostgreSQL then refuses `SELECT *` on that table, so callers name columns instead; `describe_table`
  lists them and marks the redacted one.
- **Prompt-injection aware:** row data is returned inside a `trusted="false"` provenance block with delimiters escaped, so a malicious cell can't hijack the agent.
- **A browser cannot reach it:** a request carrying an `Origin` is refused with 403 unless the
  operator listed that origin, and on a loopback listener a `Host` that is not localhost is refused
  too — the shape a DNS-rebinding attack takes when it aims at a database server on your laptop.
- **The audit knows the configuration:** the chain opens with a `startup` record naming the version,
  the transport and every setting in force, with connection passwords stripped and secrets reduced to
  fingerprints, plus a `config_fp` an operator can pin across restarts. A log that says what happened
  but not under which settings cannot answer the first question an incident asks.
- **A misspelt setting is fatal:** `MCP_REDACT_COLUMN` (singular) used to start the server with
  redaction quietly switched off. Unknown `MCP_*` variables now stop startup and name the intended
  spelling; `MCP_X_*` is reserved for the operator's own use.
- **No schema leaks:** database errors are mapped to structured, actionable messages that never echo table/column names.
- **OAuth 2.1:** optional RS256 bearer-token validation (signature, `exp`, `aud`, `iss`) with scope enforcement; disabled when unconfigured for local/self-host use.
- **Audit:** every tool decision is logged as a tamper-evident, hash-chained JSON line (no raw SQL).
- **Supply chain:** dependency licences, sources and advisories enforced in CI (`cargo deny`,
  `cargo audit`); a CycloneDX SBOM is attached to every release.
- **Runtime:** ships as a distroless, non-root container (~34 MB, built and smoke-tested in CI).

## Footprint

Measured on an ordinary VPS against a 16k-row sample database, so you can check the "written in
Rust" claim rather than take it:

| | |
|---|---|
| Resident memory, idle | 5.2 MB |
| Resident memory, after a benchmark run | 9.2 MB |
| Median request latency | ~8 ms — including the `curl` process the measurement spawns, so the server's own share is lower |
| Start to first validated statement | 7 ms |
| Binary | 11 MB, static, no runtime to install |
| Container image | ~34 MB distroless, non-root |

A twelve-minute soak of mixed traffic (reads, refusals, errors, aborted requests, session churn)
left resident memory flat and file descriptors unchanged.

## Configuration

| Env | Purpose |
|-----|---------|
| `DATABASE_URL` | PostgreSQL connection string (use a read-only role) |
| `MCP_ADDR` | HTTP listen address (default `127.0.0.1:8080`) |
| `MCP_MAX_COST` | reject queries whose `EXPLAIN` cost exceeds this (default 1,000,000) |
| `JWT_PUBKEY_PEM`, `JWT_AUD`, `JWT_ISS` | enable OAuth 2.1 token validation (omit to disable auth); the key may be the PEM text or a path to a PEM file |
| `MCP_AUDIT_LOG` | path to the append-only audit log (hash-chained); verify with `--verify-audit <file> [--expect-last <hash>]` |
| `MCP_AUDIT_HMAC_KEY` / `MCP_AUDIT_HMAC_KEY_FILE` | key that turns the audit chain into HMAC-SHA256 — keep it off the host so the log cannot be rewritten (a trailing newline in the file is ignored) |
| `MCP_AUDIT_HMAC_KEYS_OLD` | comma-separated previous keys, so a log that survived a key rotation still verifies |
| `MCP_REDACT_COLUMNS` | columns to keep out of results, e.g. `password, ssn, card_number` — masked at any depth and refused if referenced. Defence in depth, not a boundary: pair it with `REVOKE SELECT (col)` |
| `MCP_BEARER_TOKEN` | shared token required on every request, for deployments without an identity provider. Ignored when OAuth is configured — accepting it as an alternative would give its holder full scope and leave the audit with no identity |
| `MCP_STATEMENT_TIMEOUT` | query time limit (PostgreSQL interval, default `30s`) |
| `MCP_SEARCH_PATH` | schemas to search when a table name is unqualified, e.g. `analytics, public` |
| `MCP_PASSWORD_FILE` | read the database password from a file instead of putting it in the connection string |
| `MCP_DATABASE_URLS` | several databases from one server: `prod=postgres://…;dev=postgres://…` (tools then take a `database` argument) |
| `MCP_SERVER_LABEL` | name shown in the client UI, e.g. `production` → `postgres-mcp-hardened (production)` |
| `MCP_SHOW_PARTITIONS` | `1` to list partition children as well (hidden by default) |
| `MCP_ALLOW_FUNCTIONS` | comma-separated catalog functions to permit that we do not know to be read-only |
| `MCP_SSLROOTCERT` | path to a PEM CA bundle for TLS to PostgreSQL (e.g. the AWS RDS bundle); system and Mozilla roots are trusted by default |
| `MCP_MAX_INFLIGHT_PER_CLIENT` | max concurrent requests from one client (default 4; `0` disables) |
| `MCP_RATE_RPM` | per-client request rate limit (default 120/min; `0` disables) |
| `MCP_RATE_BURST` | burst allowance for that limit (default `MCP_RATE_RPM / 4`, min 5) |
| `MCP_METRICS_TOKEN` | token required on `/metrics`. Without it, `/metrics` follows whatever the server itself requires: open when the server has no authentication, the bearer token when one is set, and closed when OAuth is configured (a JWT is the wrong shape for a scraper — set this instead) |
| `MCP_REDACT_REQUIRE_REVOKE` | `1` to refuse to serve while the database still lets the role read a redacted column — turns the setting above from advisory into a guarantee |
| `MCP_STRUCTURED_CONTENT` | `1` to also return MCP `structuredContent`; off by default because a client that ignores it pays for every result twice. The provenance marker travels inside the object, but the delimiter escaping that protects the text block does not apply — a client that pastes structured output straight into a prompt loses that layer |
| `MCP_RESERVED_AUTH_SLOTS` | database slots kept for authenticated traffic so an anonymous flood cannot take the pool (default: a quarter) |
| `MCP_PUBLIC_URL` | this server's public base URL, used in the OAuth discovery metadata |
| `MCP_AUTH_SERVERS` | authorization server URLs advertised in that metadata |
| `MCP_ALLOWED_ORIGINS` | browser origins permitted to call this server, e.g. `https://my-client.example`. Empty means no browser page may reach it: a page the user is merely visiting can make their browser POST to `localhost`, which is DNS rebinding's whole trick |
| `MCP_ALLOWED_HOSTS` | extra `Host` values accepted when listening on loopback (localhost and 127.0.0.1 always are) |
| `MCP_TRUST_PROXY` | set to `1` only behind a reverse proxy — then the rate limiter keys on `X-Forwarded-For` instead of the peer address |

## License

MIT — see [LICENSE](./LICENSE).
