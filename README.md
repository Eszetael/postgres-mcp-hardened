# postgres-mcp-hardened

> ### 🚧 Version 0.1.7 — the release where the guard itself turned out to have holes
>
> Published: binaries for five platforms with checksums, Sigstore signatures and build provenance;
> `.mcpb` bundles for one-click install (new here, and the Windows one would not have started before
> this release); an image on `ghcr.io` for amd64 and arm64; a package on npm; and an entry in the
> official MCP registry.
>
> **0.1.7 closes six ways past the read-only and redaction controls, all of them demonstrated against
> a running server rather than argued.** Four went around column names instead of dressing them up:
> `get_raw_page` returned 8,192 bytes of a table with the redacted values in plain ASCII;
> `SELECT * FROM pg_stats` returned real column values without naming the column at all; TOAST and
> `pg_largeobject` are the same door from the storage side. The other two were writes through
> extensions the deny list could not see, because it reasons about the `pg_*` catalog namespace and
> `pg_cron` lives in a schema of its own — `cron.schedule('nightly','0 0 * * *','DROP TABLE users')`
> was allowed. The pattern underneath all four redaction findings is now written down where the
> feature is described: a column filter protects columns, so anything reading *underneath* columns is
> outside what it can promise.
>
> One limit was found and **not** closed, and is named in [`THREAT_MODEL.md`](THREAT_MODEL.md) with
> the three repairs that were tried and what each one broke: the cost guard is the most expensive part
> of a request, because `EXPLAIN VERBOSE` prints constants the planner folded.
>
> Twelve claims this page used to make about itself were measured and found wrong — the download
> figure, the binary size, the memory, the per-query overhead, the test count, and one that was off by
> a whole MCP revision. Each is corrected below with its method, and five new gates check the classes
> they belonged to on every commit.
>
> **What is actually proven**, in the sense that something other than an opinion checks it: the
> read-only rules (a fuzz harness over 200k mutations, an adversarial corpus of every bypass found
> so far, PostgreSQL 13–18); the authorisation path end to end; protocol conformance, checked by the
> official MCP SDK rather than by our own tests; the release path, whose signatures have been
> verified by hand — including that a tampered file and a wrong identity are both rejected; and the
> published binary itself, downloaded from the release page and run against a live database.
>
> **What is not**: nobody outside this project has run it against their own data. That is the whole
> reason this is 0.1.x and not 1.0. Every adversarial round run against this code so far has found
> something real, including rounds run after the previous one came back clean — the day of the
> release itself produced four, one of which handed a superuser role to anyone who could create a
> table. The honest reading is that the next round would find something too.
>
> Known limits, and the places we were wrong, are written down rather than tidied away:
> [`THREAT_MODEL.md`](THREAT_MODEL.md), [`docs/AUDIT_2026-07-26.md`](docs/AUDIT_2026-07-26.md).
> If you find something, [`SECURITY.md`](SECURITY.md) says how to say so.
>
> The design, and the two defects the first day in public turned up, are written up here:
> [**Rebuilding the Deprecated PostgreSQL MCP Server in Rust**](https://dev.to/eszetael_lab/rebuilding-the-deprecated-postgresql-mcp-server-in-rust-safe-by-default-1eb).


**The official Postgres MCP server was deprecated in 2024 and still gets 437k downloads a month. Its entire defence is one database-level read-only transaction — and that alone does not stop every write. This is a maintained Rust replacement with defence in depth.**

A drop-in [Model Context Protocol](https://modelcontextprotocol.io) server that lets an AI agent query PostgreSQL — **read-only, enforced at the database level**, with real SQL validation, timeouts, cost limits, OAuth 2.1, and an audit trail. Speaks **Streamable HTTP** and stdio, and negotiates the MCP revision: `2026-07-28` (current, and the default since upstream released it on 2026-08-03), `2025-11-25`, and `2025-06-18` — what most shipping clients still speak today. A client asks for what it knows; it is not negotiated down.

## Try to break it — one command, no database

The read-only guard has an offline mode. Hand it a statement and it says what it decided: no
database, no configuration, nothing installed permanently.

```sh
npx postgres-mcp-hardened --validate "/* comment */ DROP TABLE users"
# REJECT: non-read-only statement: Drop

npx postgres-mcp-hardened --validate "SELECT 1; DROP TABLE users"
# REJECT: multiple statements are forbidden

npx postgres-mcp-hardened --validate "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"
# REJECT: non-read-only statement: non-read-only query (CTE / SELECT INTO / FOR UPDATE)

npx postgres-mcp-hardened --validate "SELECT * FROM orders WHERE id = 1"
# ALLOW
```

**If something that writes comes back `ALLOW`, that is the most valuable thing anyone can send us.**
It needs no working exploit and no write-up — one line of SQL and "this should not be allowed" is a
complete report. Anything that gets past the guard goes through [`SECURITY.md`](SECURITY.md);
everything else is an ordinary issue, and the bar for opening one is *this looks wrong to me*, not
*I am certain*.

The fuzzer is deterministic and prints its seed, so whatever it finds reproduces on a machine that
has never seen yours — a million mutations take about a minute:

```sh
npx postgres-mcp-hardened --fuzz 1000000
# fuzz: 1000000 iterations, seed 1592594996, slowest validation 8 ms
# RESULT: 0 invariant violations
```

For the whole thing against a real database, `docker compose -f examples/docker-compose.yml up -d`
brings up PostgreSQL with sample data and the server in front of it, connecting as a role that holds
`SELECT` and nothing else.

Every bypass found so far lives in the `MUST_REJECT` corpus in `src/validate.rs` and runs on every
commit, recorded with what it cost rather than tidied away. Yours would join them.

## Why

`@modelcontextprotocol/server-postgres` is **deprecated on npm** (last publish December 2024) and
still sees **475,790 downloads in the 30 days to 9 August 2026**. Credit where it is due: its approach is not naive — it
wraps each query in `BEGIN TRANSACTION READ ONLY` and always `ROLLBACK`s, which is a real defence
and one this server now adopts as well.

The problem is that it is the *only* defence, and it is not complete:

- **A read-only transaction does not block every write, and a rollback does not undo everything it
  lets through.** Two separate facts, and the second is the one that matters.

  `gin_clean_pending_list()` runs inside `SET TRANSACTION READ ONLY` and its work **survives the
  rollback**: an index with 25 pending pages has 0 after the transaction is rolled back.
  `pg_backup_start()` puts the session into backup state, survives `DISCARD ALL`, and with the
  default `fast => false` waits for a spread checkpoint while forcing `full_page_writes` on, which
  is a real cost on a busy server. `pg_import_system_collations()` also executes without raising
  `SQLSTATE 25006`, but be careful how much weight you put on it: **that one IS undone by a
  rollback**, so against a server that always rolls back it is a curiosity rather than a bypass.

  Reproduce it, but read the two preconditions first, because without them you will see a zero or an
  error and conclude we made this up. All three need superuser or ownership of the object. And the
  import only restores collations that are *missing*, so something has to be removed first:

  ```sql
  -- as superuser, and note these are three separate transactions: a statement that errors
  -- inside a block aborts the whole block, so they cannot be run as one.
  DELETE FROM pg_collation WHERE oid IN (SELECT oid FROM pg_collation ORDER BY oid DESC LIMIT 200);

  BEGIN READ ONLY;
    DELETE FROM pg_collation WHERE collname LIKE 'zu%';  -- ERROR: cannot execute DELETE ...
  ROLLBACK;

  BEGIN READ ONLY;
    SELECT pg_import_system_collations('pg_catalog');    -- 200, no error
  COMMIT;                                                -- and now the rows are there
  ```

  Both are writes, both are inside a read-only transaction, and one is refused while the other is
  not. That asymmetry is why this server does not treat the transaction as its only defence. It is
  also why the *role* matters more than any of this: every example above needs privileges a
  least-privilege reader does not have, and this server refuses to start as a network listener when
  the role it was given can write. What it cannot control is which connection string somebody pastes
  into a client config, and the usual answer is whichever one they already had.

- **No statement timeout, no cost guard, no row limit** — one query can run until the server gives up.
- **No authentication, no audit trail, no handling of prompt injection** through returned row data.
- One source file of 143 lines, unmaintained since December 2024, no test suite.

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
| Tests / CI | none | unit + end-to-end suites against live PostgreSQL, a deterministic fuzz harness, conformance driven by the official MCP SDK, clippy + `cargo audit` + container build on every push |
| Transport | stdio / deprecated SSE | **Streamable HTTP** + stdio |
| Maintained | ❌ deprecated since 2024 | ✅ |

## Install

Five ways in, in the order most people want them.

**One click**, for a client that accepts `.mcpb` bundles: download
`postgres-mcp-hardened-<your-platform>.mcpb` from the
[latest release](https://github.com/Eszetael/postgres-mcp-hardened/releases/latest) and open it. The
bundle asks for the connection string and stores it in the OS keychain rather than in a plain-text
config file. Nothing to install, nothing to edit.

**Through npm** — shortest, and the one your MCP client config can point at directly. There is no
Node runtime involved at run time: the package is a launcher that fetches the native binary for your
platform and verifies its checksum before running it.

```jsonc
{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": ["-y", "postgres-mcp-hardened", "--stdio"],
      "env": { "DATABASE_URL": "postgres://readonly_user:PASSWORD@localhost:5432/mydb" }
    }
  }
}
```

The connection string goes in `env`, not in `args`, on purpose: arguments show up in `ps` output and
in shell history on a shared machine, and a database password does not belong there.

**A binary from the releases page** — one file, nothing to keep up to date, and the option to take if
your machine has no Node at all. (Not a *static* binary, as this page claimed until 0.1.7: the
`-gnu` and macOS targets link the system C library like any other native program. There is simply
nothing to install alongside it.) Every release carries builds for Linux, macOS and Windows
on x86-64 and arm64, each with a checksum and a signature; verifying them is the next section.

**As a container**, if that is how you run things. The image is distroless and runs as a non-root
user, and the same signatures cover it as cover the binaries.

```bash
docker run --rm -p 127.0.0.1:8080:8080 --memory=512m \
  -e DATABASE_URL="postgres://readonly_user:PASSWORD@db-host:5432/mydb" \
  -e MCP_ADDR=0.0.0.0:8080 \
  -e MCP_BEARER_TOKEN="$(openssl rand -hex 32)" \
  ghcr.io/eszetael/postgres-mcp-hardened:latest
```

`--memory` is not decoration. The server idles at 7.7 MB and a normal request costs single-digit
megabytes, but a caller can write `SELECT repeat('x', 100000000)` and drive peak memory to 400 MB —
not through the result, which stays bounded at 300 bytes, but through the cost guard's own
`EXPLAIN`, which PostgreSQL fills with the constant it folded while planning. That is a named
residual risk in [`THREAT_MODEL.md`](THREAT_MODEL.md), with the three repairs that were tried and
what each one broke. Until it is closed, the memory limit is the thing that holds, so set one:
`--memory` here, `MemoryMax=` under systemd.

`MCP_ADDR` must bind `0.0.0.0` and not `127.0.0.1`, or the server listens on an interface that only
exists inside the container and the published port answers nothing. The other easy one: `localhost`
in `DATABASE_URL` means *the container*, not your machine, so a PostgreSQL running on the host needs
`host.docker.internal` (Docker Desktop) or the host's address on the bridge (`172.17.0.1` by default
on Linux). Both of these were walked end to end against the published image before being written
here, including that a read returns rows and `DROP TABLE` comes back as
`-32602 non-read-only statement: Drop`.

**From source** — `cargo build --release` in a clone. Not `cargo install`: this crate is not on
crates.io, and an instruction that fails is worse than one that is missing.

### Checking what you downloaded

Every released binary is signed with [Sigstore](https://www.sigstore.dev/) keyless signing — there
is no private key for us to lose, and the certificate names the workflow, repository and tag that
produced the file. Each artefact ships with a `.sig` and a `.pem` beside it:

```bash
F=postgres-mcp-hardened-x86_64-unknown-linux-gnu.tar.gz
cosign verify-blob "$F" --bundle "$F.bundle" \
  --certificate-identity-regexp '^https://github.com/Eszetael/postgres-mcp-hardened/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Pin the identity, not just the signature. Without `--certificate-identity-regexp` and
`--certificate-oidc-issuer` the check answers "somebody signed this", which is not the question.
A verified certificate names the workflow, the repository and the tag that built the file — you
can read it with `base64 -d "$F.pem" | openssl x509 -noout -text` (cosign writes the certificate
base64-encoded, which surprises people who try `openssl` on it directly).

Older cosign builds predate `--bundle`; separate `.sig` and `.pem` files are published alongside
for them, used as `--signature "$F.sig" --certificate "$F.pem"`. Current cosign marks those flags
deprecated, so prefer the bundle.

Public releases additionally carry SLSA build provenance, verifiable with
`gh attestation verify <file> --repo Eszetael/postgres-mcp-hardened`.

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
> works out of the box. Certificates and host names are **always verified** — *verified* (acceptance: "a certificate naming another host is refused, by name"); for a private CA, point
> `MCP_SSLROOTCERT` at the PEM bundle. There is no "trust anything" switch.
>
> **Tip:** point `DATABASE_URL` at a **least-privilege read-only role**. The server enforces read-only itself, but a scoped DB role is defense-in-depth.

### Or run it on a container platform (Apify Standby)

The server needs no code changes to run as an Apify Actor in Standby mode. It reads the port the
platform assigns from `ACTOR_WEB_SERVER_PORT` and binds `0.0.0.0` there — that port wins over
`MCP_ADDR`, loudly, on stderr, because binding anywhere else means the run is never marked ready and
the failure looks like a mysterious timeout. `GET /` answers the platform's readiness probe
(`x-apify-container-server-readiness-probe`) without touching the database: container readiness is
not database readiness, and a probe that waits on a busy pool turns a slow database into a container
that never starts.

| Endpoint | Method | Purpose |
|---|---|---|
| `/mcp` | POST | the MCP endpoint (Streamable HTTP). `DELETE` ends a session. |
| `/` | GET | readiness probe; otherwise a signpost naming the real endpoint |
| `/health` | GET | the process is alive |
| `/ready` | GET | the process **and** a database connection are available |
| `/metrics` | GET | counters (needs `MCP_METRICS_TOKEN`) |
| `/.well-known/mcp/server-card.json` | GET | what a registry reads: revisions, transports, tools |

**Input** is a JSON-RPC request in the POST body — `initialize`, `tools/list`, `tools/call`,
`resources/list`, `resources/read`, `server/discover`. **Output** is a JSON-RPC response; from
`2025-11-25` a refused statement comes back as a tool execution error (`isError: true`) with the
reason in the content, so the model can rewrite the query. `tools/list` is the authoritative
description of every argument.

**Authentication there is the platform's, not ours.** Apify checks the caller's token before routing
to the container, so the server does not additionally demand `MCP_BEARER_TOKEN` — requiring a second
secret would mean an agent that finds this server cannot call it. That exemption is narrow: it needs
**both** `APIFY_IS_AT_HOME` and `ACTOR_WEB_SERVER_PORT`, one alone changes nothing, and the server
card then reports `"type": "apify-platform"` rather than claiming a lock we do not hold. Everywhere
else the server still refuses to start on a network address with no authentication. Set
`MCP_BEARER_TOKEN` as well if you want a second lock on the same door.

The other start gate is unchanged and matters more here: a role that can write is refused a network
listener. Point `DATABASE_URL` at a read-only role — `--print-setup-sql` writes the statements.

## Migrating from the deprecated server

The most-discussed problems reported against `@modelcontextprotocol/server-postgres` were
reproduced against this server; here is how each behaves:

| What people reported | Here |
|---|---|
| Two instances (prod + dev) are indistinguishable, the client picks one | Resource URIs carry the database name (`postgres:///mydb/public/orders/schema`) and `MCP_SERVER_LABEL` names the instance in the client UI |
| One database per instance, because the connection string is a command-line argument | `MCP_DATABASE_URLS="prod=…;dev=…"` serves several databases from one server; every tool takes an optional `database`, and resources span all of them |
| `no pg_hba.conf entry … SSL off` | The error says the server requires TLS and names the fix (`?sslmode=require`) |
| Read-only bypassed by injecting `COMMIT` / `END` | Rejected — the multi-statement gate works on tokens, before the parser, and `COMMIT` alone is refused as a write |
| `spawn npx ENOENT`, Node version problems | A single native binary; no Node, no npx, no `node_modules` |
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
- `tests/acceptance.sh` — an end-to-end suite that starts its own PostgreSQL and checks 312
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
- **Deprecated transport.** HTTP+SSE was replaced by Streamable HTTP in **2025-03-26**, three
  revisions ago (this page said 2025-06-18 until 0.1.7, which was wrong by one revision; the
  specification's own changelog for 2025-03-26 records the replacement). We speak the current
  transport.

## Troubleshooting

Answers to the questions people actually asked about the deprecated server, so nobody has to open
an issue to find them.

**`spawn npx ENOENT` / "which Node version do I need?"** — none. This is a single native binary, with no runtime to install beside it.
Download it from the releases page and point your client
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

When the database has not answered, `resources/list` returns an **empty list with the reason in
`_meta`** rather than a protocol error. A catalogue inspecting this server starts it with no
database at all and calls `resources/list` straight after `initialize`; answering that with an error
reads as a server that does not work. The empty list is not a claim that there are no tables —
`initialize` says the database has not answered, `security_posture` gives the detail, and the reason
travels with the list itself. A database that *does* answer and refuses is still an error, because
reporting "no resources" for a missing privilege is the silent failure this server exists to avoid.
*verified* (acceptance: "a host can inspect the server with no database and mcp-proxy in front")

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
- **`security_posture`** — what this deployment is actually able to do to your database, asked of
  PostgreSQL rather than assumed: whether the role can write, bypass row-level security or reach
  server files; whether the transport is authenticated; whether the audit chain is keyed; whether the
  connection is encrypted. Returns a grade — the worst finding, never an average — and, for anything
  wrong, the command that fixes it. The same summary reaches the model through `initialize`, because
  under stdio nobody sees stderr and the agent is the only messenger the operator has.
- **`query`** — run a read-only SQL query (validated, auto-`LIMIT`, cost-guarded). The response
  states what it did: `returnedRows`, `appliedLimit`, `truncated`, plus `requestedLimit` when a
  larger request was capped at the 10000-row maximum, `offset` when paging, and `redactedColumns`
  when masking is configured — so an agent never has to guess whether it received the whole answer.
- **`list_schemas`**, **`list_tables`**, **`describe_table`** — progressive schema discovery
  (parameterized, injection-safe). `describe_table` returns the **schema comments**
  (`COMMENT ON TABLE/COLUMN`), primary keys, **foreign keys** and defaults, so the agent reads what a
  column *means* and what it points at instead of guessing from its name — and a missing table is an
  error, not an empty column list.

## Protocol revisions

The server answers `initialize` with the revision the client asked for when it implements it, and
with its newest otherwise. Over HTTP the revision comes from the `MCP-Protocol-Version` header, per
request — one client's negotiation cannot change the contract another client is served under.

If a request carries no header, the server does not fall straight back to the oldest contract. It
reads the revision **this** session agreed on at `initialize`, which is what the transport
specification asks for: the default applies only "if the server does not receive an
`MCP-Protocol-Version` header, and has no other way to identify the version — for example, by
relying on the protocol version negotiated during initialization". A session is that other way, so a
client that negotiated `2025-11-25` and then omitted the header keeps the contract it agreed to
rather than being silently demoted.

A header we cannot parse is a different matter from a header that is absent, and the specification
is explicit about it: "If the server receives a request with an invalid or unsupported
`MCP-Protocol-Version`, it **MUST** respond with `400 Bad Request`." A version we do not implement —
`2025-03-26` or `not-a-date` — is refused with `400`
and the list of revisions we do speak, rather than served under a contract the client never agreed
to. Falling back is for silence, not for disagreement.

Only a request with neither a header nor a session falls back, and it falls back to `2025-06-18` —
the oldest revision this server implements — rather than the `2025-03-26` the specification names.
That revision is not implemented here, and answering under a contract the server cannot honour would
be worse than answering under the oldest one it can.

The difference that matters is where a refusal goes. Under `2025-06-18` "this statement is not
read-only" was a JSON-RPC error: the client saw a broken call and the model often never saw the
reason. From `2025-11-25` (SEP-1303) it arrives as a tool execution error — `isError: true` with the
reason in the content — so the model rewrites the query instead of handing the user a failure. What
does not change is the audit: the refusal is recorded by the code that refuses, and the acceptance
suite asserts both halves together, so friendlier errors can never quietly mean a quieter log.

`Mcp-Method` and `Mcp-Name` are held to **agreement, not presence**. The draft requires them; earlier
revisions do not, and demanding them would break every client shipping today. But a gateway that
routes or authorises on `Mcp-Method` while the server executes the body has decided about a
different request than the one that runs — and that is true whatever revision is in force. So a
header that is present must match the body under every revision, while a client that sends none is
untouched.

Protocol failures stay protocol failures. A malformed envelope, an unknown method or a missing token
is not something a model can fix by rewriting SQL, and a client's error handling expects those where
they have always been.

### The next revision, before it lands

`2026-07-28` is the largest break MCP has had: no `initialize`, no session header, no `ping`. That
identifier comes from `LATEST_PROTOCOL_VERSION` in the draft schema, and it is not a release date —
MCP names a revision for the last date a backwards-incompatible change was made, so it describes the
draft's history rather than a schedule. Every request carries its own protocol version in `_meta`,
and a new `server/discover` replaces the handshake. We implemented it early behind a switch, because
a draft moves and a server advertising support for a moving target will be wrong in public. Upstream
cut `schema/2026-07-28` on 2026-08-03 — the released schema differs from the draft we had verified
against in four documentation URLs and nothing else — so the switch is gone and this is what the
server speaks by default. Clients on `2025-11-25` and `2025-06-18` are answered as before.

`server/discover` answers under **every** revision, because the specification
expects clients to use it as a backwards-compatibility probe — which only works if older servers
answer it. Ours answers with the revisions we speak and, in `_meta`, the full security posture. That
is deliberate: a client can learn it is talking to a server connected as a superuser *before* it
sends a query, as structured data rather than prose a model has to notice.

Two of the draft's rules are security controls here, not formalities. `Mcp-Method` and `Mcp-Name`
must agree with the request body, and we refuse the mismatch (`-32020`) — the headers exist so a
gateway can route and authorise without parsing the body, and if header and body may disagree, then
the thing that authorised and the thing that executes saw two different requests. And a client
stating a version we do not implement is told so (`-32022`) rather than quietly served under a
contract it never agreed to.

## What the safety costs

Measured, not asserted: `tests/bench/`, against the `pg` driver running the same query on the same
machine (PostgreSQL 18.6 in Docker, 50k-row table, 300 sequential requests, rate limit off).
Re-measured 2026-08-17 on a shared VPS at load average 2.6 — median of two runs:

| query | driver | this server | difference |
|---|---|---|---|
| point lookup | 0.43 ms | 5.9 ms | +5.5 ms |
| small scan | 1.0 ms | 8.3 ms | +7.3 ms |
| aggregate | 4.7 ms | 11.3 ms | +6.6 ms |

An earlier table here said +3.6/+5.2/+3.7 and "about 4 ms". Those came from a quieter machine, and
the driver floor moved with them — 0.28 ms against today's 0.43 for the same lookup — so it was the
hardware talking, not the code. Two things were checked before changing the number, because the
obvious suspect was our own build: the 0.1.6 binary, built before `lto` was switched on, measures
+5.4/+7.8/+5.9 on this machine within the same hour. Identical. The release profile halved the
binary and cost nothing here.

Expect **5 to 8 ms per query**, and treat any single figure on this page as a reading from one
machine on one day. The shape matters more than the size: the overhead is nearly constant. If the AST validation were the cost, it would grow with the query. It does not. The time
goes on round trips — the session is reset, the timeouts and read-only flag are set, a read-only
transaction is opened, the cost guard plans the statement, then the query runs and the transaction
is rolled back. Five or six exchanges where the driver has one.

That is a deliberate trade and you can see exactly what it buys. For an agent making tens of calls
it is invisible; if you are putting this in front of a latency-critical serving path, you are using
the wrong tool, and it is not one.

Under concurrency the interesting number is not throughput but what happens past the limits: at 8
concurrent clients it served 373 requests/second and turned away 192 more with "too many requests in
flight", which is the in-flight cap doing its job rather than a queue growing until something falls
over.

## Would this index help? — answered without creating one

The one capability the leading alternative is genuinely known for is index tuning: it can tell you
an index would pay off before you build it. It gets there by defaulting to a connection that can
create real indexes — safe only if you remembered to restrict it.

`simulate_index` answers the same question from a connection that cannot write anything.
[hypopg](https://github.com/HypoPG/hypopg) registers a hypothetical index in backend memory: the
planner sees it, storage never does, and it is gone when the call returns. You get the plan and cost
with and without, and — separately — whether the planner actually reached for it, because a cost
that barely moves and an index the planner ignored are different answers.

The tool takes a table and a list of columns. **Not a `CREATE INDEX` statement.** The definition is
assembled server-side from identifiers the catalogue confirmed exist, quoted by PostgreSQL itself,
so there is no path from a tool argument to arbitrary DDL — a column name carrying SQL dies on the
catalogue lookup, and there is a test that fires exactly that. The numbers are planner estimates:
treat a large improvement as a reason to test the index, not as proof.

## Conformance is checked by somebody else's client

Every other test here is our harness talking to our server. If we misread the specification, we
misread it the same way in both halves and everything passes. So CI also drives the server with the
**official MCP SDK** — the client library the ecosystem uses — over stdio and Streamable HTTP:
handshake, tool listing and schemas, a read, a refused write arriving as a tool execution error
rather than a protocol one, resource listing and reading. A protocol mistake shows up as a client
that cannot talk to us. `tests/conformance/`.

## Working on this

```bash
git config core.hooksPath .githooks   # once, per clone
```

`.githooks/pre-push` runs format, clippy, the unit tests and the documentation-claim checks before
anything leaves your machine. It exists because of a specific mistake: a commit went out with a
failing clippy lint, and the first anyone knew of it was a failure email. Note that `cargo test`
passes on that code — clippy lints are not compiler errors — so "it builds locally" is not the
same answer as "CI will be green".

It deliberately skips the acceptance suite and the PostgreSQL matrix: those need Docker and about
twenty minutes, and a hook people cannot afford to run is a hook people bypass. CI runs everything.
`git push --no-verify` when you want to see something fail in CI on purpose.

## Setting up the role

```bash
DATABASE_URL=postgres://admin@host/mydb postgres-mcp-hardened \
  --print-setup-sql --role mcp_reader --schemas public --redact ssn,email > setup.sql
# read it, then:
psql -v pw="$(openssl rand -base64 24)" -f setup.sql mydb
```

Run with a connection string and the table and column lists come from the catalogue; without one you
get the same document with placeholders. The difference matters most for redaction: the columns to
grant back have to be read from the database, because writing them from memory is how a column meant
to stay hidden gets handed back.

The output ends with checks that return no rows when it worked, and a reminder that the server itself
will tell you what the role can do the moment you point it at the database.

## Limiting what the server can reach

`MCP_ALLOW_SCHEMAS` and `MCP_ALLOW_TABLES` restrict which relations a query may touch. Either one
turns the allowlist on; `schema.*` and `schema.table` both work.

```bash
MCP_ALLOW_TABLES='public.customers,public.orders,analytics.*'
```

The check reads the **query plan**, not the SQL. That is the whole design: the planner has already
applied `search_path`, resolved every alias, expanded views to base tables, and knows that a CTE
named `customers` is not the table `customers` — so `WITH customers AS (SELECT 1) SELECT * FROM
customers` runs and touches nothing, while `WITH x AS (SELECT * FROM salaries) SELECT * FROM x`
is refused. Reading the statement instead is what lost three rounds of adversarial review.

Two consequences worth knowing before you turn it on:

- **A partition rides on its parent.** You allow `events`; PostgreSQL decides which children to read.
- **A view needs its base tables allowed too**, because the plan names those. Allow both, and let the
  database privileges keep the base table unreachable directly — that is the boundary in any case.

`pg_catalog` and `information_schema` are outside the surface unless `MCP_ALLOW_CATALOG=1`: an agent
that can still read the catalog can enumerate exactly what the allowlist was meant to hide. The
schema tools keep working, because they run fixed queries rather than caller SQL.

That covers three routes to the same facts, because for a while it covered only one. A catalogue view
plans to scans over real relations and the plan names them — but `pg_settings` plans to a single
`Function Scan` on `pg_show_all_settings`, naming no relation at all, and `current_setting()` is a
scalar call that never appears as a scan. Both used to return the server's configuration under an
active allowlist. Functions whose name begins with `pg_`, plus `current_setting`, `inet_server_addr`
and `inet_server_port`, are now refused alongside the catalogue relations, and `MCP_ALLOW_CATALOG=1`
opens all of them together. Ordinary set-returning functions — `generate_series`, `jsonb_each`,
`unnest`, `regexp_split_to_table` — carry no such prefix and are unaffected. `current_user`,
`session_user`, `current_database` and `version` stay readable on purpose: an agent already knows what
it connected to and as whom.

## The corpus of things that got through

Every shape that defeated a control during review lives in `tests/adversarial/`, with the round in
which it stopped working. It runs on every build, and — because the cases are written against
placeholders rather than our fixture — you can point it at your own database:

```bash
ADV_URL='postgres://…' \
  ADV_TABLE=people ADV_TABLE2=orders ADV_REDACT_COL=ssn \
  ./tests/adversarial/run.sh
```

`ADV_TABLE` needs the sensitive column, `ADV_TABLE2` is any other readable table, `ADV_REDACT_COL`
is the column to redact. All three matter: this example omitted `ADV_TABLE2` until 0.1.7, so it kept
its default of `film` — a table from the Pagila sample database — and following the instruction
exactly produced three "mismatches" that were only a missing relation. The harness now checks the
three up front and says which one is wrong, because a security corpus that reports a typo as a
failed control teaches you to ignore the failures that matter.

A security claim you can only check by reading our source is a claim you have to take on trust, and
this project's own history is the argument against that.

## Security model

The full statement of what this server guarantees, what it does not, and which control enforces
which promise is in [THREAT_MODEL.md](THREAT_MODEL.md) — including the controls that have been
defeated in review and are therefore described as depth rather than as boundaries.

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
  filtering cannot be a boundary against the whole SQL language — four adversarial rounds each got
  past it through a shape nobody had listed.

  The fourth, in 0.1.7, did not find a new *shape* of name. It went around names altogether:
  `SELECT get_raw_page('people', 0)` hands back 8192 bytes of the table as the disk holds it, and
  every value on that page is in there, including the redacted one. Demonstrated, not theorised —
  with `MCP_REDACT_COLUMNS=ssn`, `SELECT ssn FROM people` was refused while the raw page came back
  with the social security numbers in plain ASCII. `pageinspect` and its relatives are now refused
  as a category of their own, because "this returns storage rather than columns" is a different
  problem from "this writes", and telling an operator which one they hit is worth a separate
  message.

  The same round found the quieter version of it. PostgreSQL's planner keeps a sample of each
  column's real values, and `pg_stats` publishes them: with 3,000 rows, `SELECT * FROM pg_stats
  WHERE tablename='people'` returned `{123-45-6789,555-00-1111,987-65-4321}` while `SELECT ssn FROM
  people` was refused. That query never names the redacted column, so a name-based rule has nothing
  to act on. The value-bearing statistics columns — `most_common_vals`, `histogram_bounds`,
  `most_common_elems`, `stavalues1`…`stavalues5` — now join whatever you configure, whenever you
  configure anything. The rest of the view is untouched: `n_distinct`, `null_frac` and `correlation`
  are what the index advice below is built from and they carry no values, so removing the whole
  relation would have broken ten columns to fix four.

  Two more doors turned out to open on the same room. A value too long for its row is stored in a
  TOAST table, and that table is readable by name: `SELECT chunk_data FROM pg_toast.pg_toast_16384`
  returned the redacted text in the clear. `pg_largeobject` is the same thing for large objects — the
  bytes underneath `lo_get`. Both are refused now, as *relations* rather than functions, with a
  message that says why: they hold physical storage rather than columns. The catalogue that merely
  describes the database is untouched — `pg_tables`, `pg_stat_activity`, `pg_largeobject_metadata`,
  and the statistics columns index advice needs.

  All four say the same thing, and it describes this feature's limit better than any list of patches:
  **a column filter protects columns, so anything that reads underneath columns is outside what it
  can promise.** Raw pages, planner samples, TOAST chunks and large-object bytes are four doors into
  that space, all four found in a single afternoon by looking for the shape rather than the names.
  The honest assumption is that there are more, which is why the database role and the read-only
  transaction are the real boundary and this stays what it says it is: defence in depth.

  So the server stops asserting and **asks the database**: at startup it reports every table where
  the connected role can still read a redacted column, with the exact statements that fix it, and
  `MCP_REDACT_REQUIRE_REVOKE=1` turns that report into a refusal to run. Note the fix is a table-level
  `REVOKE` followed by a `GRANT` of the columns that stay — a bare `REVOKE SELECT (password) ON staff`
  is silently a no-op while the role holds SELECT on the whole table. With column-level grants
  PostgreSQL then refuses `SELECT *` on that table, so callers name columns instead; `describe_table`
  lists them and marks the redacted one.
- **Prompt-injection aware:** row data is returned inside a `trusted="false"` provenance block with delimiters escaped, so a malicious cell can't hijack the agent.
- **It generates the role you should be running as:** `--print-setup-sql` writes the DDL for a role
  that inherits nothing, bypasses nothing, creates nothing, reads only the relations you name, and —
  where you have named sensitive columns — has them revoked in the order that actually works. It
  prints; it never executes. Applying this needs administrative rights, and a tool whose whole
  identity is "read-only" has no business holding an administrator's password.
- **It will not expose a role that can write:** when the listen address is reachable from the
  network, the server asks PostgreSQL what the connected role is actually allowed to do — superuser,
  `BYPASSRLS`, membership of `pg_write_all_data` and friends, and write privileges on a bounded sample
  of tables — and refuses to start if the answer is more than "reader", naming each reason and
  pointing at `--print-setup-sql`. It refuses an unauthenticated network listener for the same reason.
  Loopback and stdio are left alone: there the caller is the operator. The overrides
  (`MCP_ALLOW_EXCESSIVE_ROLE`, `MCP_ALLOW_ANONYMOUS_NETWORK`) take the literal value
  `i-accept-the-risk` so they cannot be switched on by a typo, and they are recorded in the audit log.
  This server enforces read-only itself, but that enforcement is code, and code has been wrong before;
  a role that cannot write is the part no bug of ours can undo.
- **A browser cannot reach it:** a request carrying an `Origin` is refused with 403 unless the
  operator listed that origin, and on a loopback listener a `Host` that is not localhost is refused
  too — the shape a DNS-rebinding attack takes when it aims at a database server on your laptop.
- **The audit knows the configuration:** the chain opens with a `startup` record naming the version,
  the transport and every setting in force, with connection passwords stripped and secrets reduced to
  fingerprints, plus a `config_fp` an operator can pin across restarts. A log that says what happened
  but not under which settings cannot answer the first question an incident asks.
- **The audit notices being shortened:** a hash chain proves entries were not *altered*, but a log
  with its tail cut off is internally consistent — recomputing it finds nothing wrong. Alongside
  `MCP_AUDIT_LOG` the server therefore keeps `<log>.hwm`, a one-line record of the last sequence
  number and hash it wrote, updated only after the entry is durably appended. On start the two are
  compared, and a disagreement is reported: entries missing from the end, a rewritten last entry, or
  a log that has gone away entirely. This is not proof of tampering — an unclean shutdown looks the
  same — but a tamper-*evident* trail owes you the question, not the verdict. Keep the sidecar with
  the log when you archive or move it; deleting it only loses the truncation check, never an entry.
  The offline verifier is unchanged and still needs an external anchor:
  `--verify-audit <file> --expect-last <hash>`.
  *verified* (acceptance: "a shortened log is noticed at startup, without any external anchor")
- **A wrong setting is fatal, not merely wrong:** an unparsable listen address, an audit file that
  cannot be written, `sslmode=disable` to a database on another machine, a metrics token that is also
  the database credential, a boolean spelt `yes` — each used to be accepted and quietly do something
  other than what was meant. Startup now stops and names the setting.
- **A misspelt setting is fatal — somebody else's setting is not:** `MCP_REDACT_COLUMN` (singular)
  used to start the server with redaction quietly switched off, so a near miss of a real setting
  still stops startup and names the intended spelling. A name that resembles nothing we define was
  set by another program sharing the environment: it is reported and ignored. `mcp-proxy`, which
  every catalogue puts in front of a server to inspect it, exports `MCP_PROXY_DEBUG` — until 0.1.6
  that one variable made this server exit before reading a request. `MCP_X_*` remains reserved for
  the operator's own use. *verified* (acceptance: "a misspelling is still fatal")
- **No schema leaks:** database errors are mapped to structured, actionable messages that never echo table/column names.
- **OAuth 2.1:** optional RS256 bearer-token validation (signature, `exp`, `aud`, `iss`) with scope enforcement; disabled when unconfigured for local/self-host use.
- **Audit:** every tool decision is logged as a tamper-evident, hash-chained JSON line (no raw SQL).
- **Supply chain:** dependency licences, sources and advisories enforced in CI (`cargo deny`,
  `cargo audit`); a CycloneDX SBOM is attached to every release.
- **Runtime:** ships as a distroless, non-root container — **14.8 MB to download**, 41 MB on disk for `linux/amd64` at 0.1.6, built and smoke-tested in CI. Both numbers, because a single one is always the flattering one: `docker images` shows the second, your bandwidth pays the first.

## Footprint

Measured on an ordinary VPS against a 16k-row sample database, so you can check the "written in
Rust" claim rather than take it:

| | |
|---|---|
| Resident memory, idle | 7.7 MB — median of five separate starts, all within 0.1 MB of each other |
| Resident memory, after 200 requests | 9.4 MB, and flat afterwards |
| Median request latency | ~8 ms — including the `curl` process the measurement spawns, so the server's own share is lower |
| Start to first validated statement | 5 ms — median of five `--validate` runs, 5 to 7 ms observed |
| Binary | 9.2 MB (linux x86_64, 0.1.7 onward). Nothing to install alongside it — no Node, no Python, no shared library we ship. It is *not* statically linked: like any `-gnu` target it uses the system `libc`, `libm` and `libgcc_s`. |
| Container image | 12.6 MB compressed, 31.8 MB unpacked (linux/amd64, 0.1.7), distroless, non-root |

Two lines here were wrong until 0.1.7. Idle memory said 5.2 MB and measures 7.7 — five starts under
identical conditions landed within 0.1 MB of one another, so the old figure is not noise, it is a
different measurement whose method was not written down. The binary line said "11 MB, static", and the file people actually
downloaded was 18.9 MB and dynamically linked. The size was never measured on a release build,
because this crate had no `[profile.release]` at all, so more than five megabytes of debug symbols
shipped to every user. Setting `strip`, `lto` and `codegen-units = 1` took it to 9.2 MB. The word
"static" was simply not true of any of the five targets we publish, none of which is a `musl` build.
The image shrank with the binary, from 14.8 MB compressed in 0.1.6 to 12.6 MB — both figures read
from the registry manifest of the published image rather than from a local build, because a local
build is not what anybody pulls.

A twelve-minute soak of mixed traffic (reads, refusals, errors, aborted requests, session churn,
unauthenticated requests) served **51,499 requests** and ended with **the same 15 open file
descriptors it started with**. Resident memory went from 8.1 MB to 11.2 MB, and the shape of that is
the interesting part: 8.1 to 10.7 happened inside the first 400 requests, and the remaining 51,000
added 0.5 MB in a curve that flattened as it went. That is an allocator settling, not a leak. This
page used to say memory stayed "flat", which was true of everything after the first few seconds and
not true of the number, so here is the number.

Reproduce it with `tests/soak.sh` rather than believing the paragraph.

## Configuration

| Env | Purpose |
|-----|---------|
| `DATABASE_URL` | PostgreSQL connection string (use a read-only role) |
| `MCP_ADDR` | HTTP listen address (default `127.0.0.1:8080`) |
| `MCP_MAX_COST` | reject queries whose `EXPLAIN` cost exceeds this (default 1,000,000) |
| `JWT_PUBKEY_PEM`, `JWT_AUD`, `JWT_ISS` | enable OAuth 2.1 token validation (omit to disable auth); the key may be the PEM text or a path to a PEM file |
| `MCP_AUDIT_LOG` | path to the append-only audit log (hash-chained); verify with `--verify-audit <file> [--expect-last <hash>]`. The server also writes `<log>.hwm` beside it — the last sequence number and hash, used at startup to notice a shortened log |
| `MCP_AUDIT_HMAC_KEY` / `MCP_AUDIT_HMAC_KEY_FILE` | key that turns the audit chain into HMAC-SHA256 — keep it off the host so the log cannot be rewritten (a trailing newline in the file is ignored) |
| `MCP_AUDIT_HMAC_KEYS_OLD` | comma-separated previous keys, so a log that survived a key rotation still verifies. *verified* (acceptance: "a chain spanning a key rotation verifies with both keys") |
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
| `MCP_RATE_RPM_STDIO` | the same limit for stdio (default 600/min): an agent exploring a schema legitimately makes dozens of calls a minute, but a runaway loop against a production database is still what a DBA fears most |
| `MCP_CLIENT_ID` | a name for this client in the audit log over stdio, e.g. `claude-desktop@ada-laptop`; without it the identity falls back to the operating system's user and process |
| `MCP_RATE_BURST` | burst allowance for that limit (default `MCP_RATE_RPM / 4`, min 5) |
| `MCP_METRICS_TOKEN` | token required on `/metrics`. Without it, `/metrics` follows whatever the server itself requires: open when the server has no authentication, the bearer token when one is set, and closed when OAuth is configured (a JWT is the wrong shape for a scraper — set this instead) |
| `MCP_REDACT_REQUIRE_REVOKE` | `1` to refuse to serve while the database still lets the role read a redacted column — turns the setting above from advisory into a guarantee |
| `MCP_STRUCTURED_CONTENT` | `1` to also return MCP `structuredContent`; off by default because a client that ignores it pays for every result twice. The provenance marker travels inside the object, but the delimiter escaping that protects the text block does not apply — a client that pastes structured output straight into a prompt loses that layer |
| `MCP_RESERVED_AUTH_SLOTS` | database slots kept for authenticated traffic so an anonymous flood cannot take the pool (default: a quarter) |
| `MCP_PUBLIC_URL` | this server's public base URL, used in the OAuth discovery metadata |
| `MCP_AUTH_SERVERS` | authorization server URLs advertised in that metadata |
| `MCP_PROTOCOL_PREVIEW` | **Retired.** It gated `2026-07-28` while that revision was a draft; upstream released it on 2026-08-03 and the server now speaks it by default. The name stays recognised so an existing config line is not reported as a misspelling, and startup says once that it no longer does anything |
| `MCP_ALLOW_SCHEMAS` | schemas a query may reach, e.g. `public,analytics`; setting either this or the next turns the allowlist on |
| `MCP_ALLOW_TABLES` | relations a query may reach, e.g. `public.orders,analytics.*` |
| `MCP_ALLOW_CATALOG` | `1` to keep `pg_catalog` reachable while an allowlist is active |
| `MCP_ALLOW_PLAINTEXT_DB` | set to `i-accept-the-risk` to allow `sslmode=disable` to a database that is not on this machine |
| `MCP_ALLOW_EXCESSIVE_ROLE` | set to `i-accept-the-risk` to serve a network listener with a role that can write |
| `MCP_ALLOW_ANONYMOUS_NETWORK` | set to `i-accept-the-risk` to serve a network listener with no authentication |
| `MCP_ALLOWED_ORIGINS` | browser origins permitted to call this server, e.g. `https://my-client.example`. Empty means no browser page may reach it: a page the user is merely visiting can make their browser POST to `localhost`, which is DNS rebinding's whole trick |
| `MCP_ALLOWED_HOSTS` | extra `Host` values accepted when listening on loopback (localhost and 127.0.0.1 always are) |
| `MCP_FUZZ_VERBOSE` | development only: makes `--fuzz` print each mutation it tried |
| `MCP_TRUST_PROXY` | set to `1` only behind a reverse proxy — then the rate limiter keys on `X-Forwarded-For` instead of the peer address |

## License

MIT — see [LICENSE](./LICENSE). The core is MIT and stays that way.

## Commercial and team use

Pointing this at a production database *inside an organisation* raises questions the MIT core does
not answer: policy bound to an identity rather than to a scope, an audit log shipped somewhere it
cannot be quietly edited, evidence a compliance reviewer will accept, a deployment somebody is on
the hook for.

A team edition covering those is being scoped right now, and what goes into it is not decided. If
that is what your organisation needs, write to <eskulapstudio@gmail.com> and say what would have
to be in it. There is nothing to buy yet — the answers are what decides whether it gets built at
all, and in what order.
