---
name: postgres-mcp-hardened
description: Use this skill whenever a user wants an AI agent to query a PostgreSQL database — especially when they ask for read-only or safe database access, want to connect Claude/Cursor/Copilot to Postgres via MCP, mention giving an agent a database connection string, are setting up a Postgres MCP server, are migrating off the deprecated `@modelcontextprotocol/server-postgres`, need an audit trail of what an agent queried, or ask how to let an agent explore a schema without risking a write. Also use it when a user reports an agent accidentally running a destructive query against Postgres, or asks how to limit which tables/schemas an agent can reach. Triggers include "postgres mcp", "database MCP server", "read-only SQL for an agent", "agent ran DROP TABLE", "audit log database queries", "connect agent to RDS/Supabase/Neon".
---

# postgres-mcp-hardened

A Rust MCP server that gives an AI agent **enforced read-only** access to PostgreSQL —
validation happens in the server, not just via a database-level read-only transaction (the
deprecated official server's only defence, which a `COMMIT`/`END` injected mid-session can
survive). Repository: https://github.com/Eszetael/postgres-mcp-hardened. npm package:
`postgres-mcp-hardened`. Distroless container: `ghcr.io/eszetael/postgres-mcp-hardened`.

## When to reach for this vs. something else

- An agent needs to run `SELECT` queries, explore a schema, or diagnose performance, and must
  **not** be able to write — reach for this.
- A human is writing the SQL and pasting results in themselves — a plain `psql` session is
  simpler; this skill is for when the **agent** holds the connection.
- The user already has `@modelcontextprotocol/server-postgres` configured and asks why an agent
  bypassed its read-only guarantee, or why two database instances look identical to the
  client — see "Migrating from the deprecated server" below; this server was built by
  reproducing each reported failure against itself.
- The user wants an agent to run migrations, seed data, or otherwise write — this is the wrong
  tool. It refuses writes by design, at two independent layers, and that refusal is not
  configurable away except through an explicit, logged override meant for a human operator, not
  an agent.

## Setting it up

### 1. Pick an install method

| Situation | Command |
|---|---|
| Node is available | `npx postgres-mcp-hardened --stdio` |
| No Node on the machine | download the matching binary from the [releases page](https://github.com/Eszetael/postgres-mcp-hardened/releases) — a single native file, nothing else to install |
| Already running things in containers | `ghcr.io/eszetael/postgres-mcp-hardened:latest` |

Do not suggest `cargo install` — the crate is not published to crates.io; `cargo build
--release` from a clone is the source-build path.

### 2. Create a read-only database role

Never point this server at a role that can write — the server itself refuses to serve a network
listener with such a role unless a human explicitly overrides it (see Safety rules). Generate
the role instead of writing it by hand:

```bash
DATABASE_URL=postgres://admin@host/mydb postgres-mcp-hardened \
  --print-setup-sql --role mcp_reader --schemas public --redact ssn,email > setup.sql
# read it, then:
psql -v pw="$(openssl rand -base64 24)" -f setup.sql mydb
```

Run with a connection string and the generated SQL reads real table/column names from the
catalogue (needed for redaction grants to be correct). Without one, the same document comes back
with placeholders to fill in by hand.

### 3. Choose stdio (local client) or HTTP (shared/remote)

**Local — Claude Desktop, Cursor, Claude Code** (stdio transport):

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

Put the connection string in `env`, never in `args` — arguments are visible in `ps` output and
shell history on a shared machine.

**Remote — a server other people's agents connect to** (Streamable HTTP):

```bash
DATABASE_URL="postgres://readonly_user:YOUR_PASSWORD@host:5432/mydb" \
MCP_ADDR="0.0.0.0:8080" \
MCP_BEARER_TOKEN="$(openssl rand -hex 32)" \
postgres-mcp-hardened
```

A network listener with no authentication is refused at startup unless overridden (see Safety
rules below) — set `MCP_BEARER_TOKEN` or `JWT_PUBKEY_PEM`/`JWT_AUD`/`JWT_ISS` for OAuth 2.1.

**Docker specifics**, if that's the install method: `MCP_ADDR` must bind `0.0.0.0`, not
`127.0.0.1`, or the published port answers nothing. `localhost` in `DATABASE_URL` means *the
container*; a Postgres on the host needs `host.docker.internal` (Docker Desktop) or the bridge
address (`172.17.0.1` by default on Linux). Set `--memory` (512m is a reasonable default) — the
idle footprint is 7.7 MB, but a crafted query can drive the planner's cost estimate memory up;
this is a named, open risk in the project's own threat model, and the memory limit is what holds
until it's closed.

### 4. Verify before trusting it

```bash
postgres-mcp-hardened --validate "SELECT 1"              # -> ALLOW
postgres-mcp-hardened --validate "DROP TABLE users"       # -> REJECT: non-read-only statement: Drop
```

Then start it and run one real query through the MCP client to confirm the connection itself
works end to end, not just the validator.

## The tools it exposes

- **`query`** — run a read-only SQL statement. Validated, auto-`LIMIT`ed, cost-guarded. The
  response says whether results were truncated, so the agent never has to guess if it saw
  everything.
- **`list_schemas`**, **`list_tables`**, **`describe_table`** — progressive schema discovery.
  Use these *before* writing a query against an unfamiliar database rather than guessing table
  names — they respect the same allowlist as `query`, so what they show is what's actually
  reachable.
- **`explain_query`** — the execution plan; add `analyze` to actually run the statement and
  report real numbers against the estimate. Reach for this before a query that looks expensive,
  not after it times out.
- **`database_health`** — cache hit ratio, connection counts (this database and the cluster),
  longest-running queries.
- **`analyze_indexes`** — unused indexes, duplicates, tables that would benefit from one.
- **`top_queries`** — the heaviest statements, from `pg_stat_statements` if it's enabled.
- **`security_posture`** — what this deployment can actually do to the database: the role's
  privileges, whether an allowlist is active, whether auth is configured. Run this first when
  asked to audit a deployment rather than one someone else set up.

## Reading a REJECT

A `REJECT` from `query` or `--validate` means the statement cannot be made read-only — not that
the agent phrased it wrong. Do not retry by obfuscating the statement (comments, encoding,
alternate casing); the validator folds all of those and the project ships an adversarial corpus
and a fuzzer specifically to keep it that way. If a write is genuinely needed, that is a decision
for the human operator, through a different, writable connection — not something to route around
from the agent side.

## Env vars worth knowing

| Variable | What it does |
|---|---|
| `DATABASE_URL` | connection string — use the read-only role from step 2 |
| `MCP_ADDR` | HTTP listen address (stdio mode ignores this) |
| `MCP_ALLOW_SCHEMAS` / `MCP_ALLOW_TABLES` | restrict which relations a query may touch, e.g. `public,analytics` or `public.orders,analytics.*`; setting either turns the allowlist on |
| `MCP_REDACT_COLUMNS` | columns kept out of results at any depth, e.g. `password,ssn` — defence in depth, pair with `REVOKE SELECT (col)` on the role |
| `MCP_STATEMENT_TIMEOUT` | query time limit (default `30s`) |
| `MCP_SSLROOTCERT` | CA bundle for a private TLS chain (e.g. the AWS RDS bundle) |
| `MCP_AUDIT_LOG` | path to a hash-chained, append-only audit log; verify it later with `--verify-audit` |

Full reference: the project's README has ~25 more, covering OAuth, HMAC-signed audit chains,
rate limiting, and multi-database setups (`MCP_DATABASE_URLS`).

## Troubleshooting

| Symptom | What it means |
|---|---|
| `no pg_hba.conf entry … SSL off` | add `?sslmode=require` to `DATABASE_URL` |
| `spawn npx ENOENT` | switch to the binary or Docker install — no Node dependency that way |
| `self-signed certificate in certificate chain` | set `MCP_SSLROOTCERT` to the CA bundle |
| `INVALID_URL` with special characters in the password | percent-encode the password in the connection string |
| Hangs with no output against RDS | shouldn't happen — an unreachable host answers in ~8s by design; check security groups first |

## Safety rules — do not override these for an agent

Two startup gates exist and both refuse to start a **network** listener (stdio/loopback is
exempt, since only a local process can reach it):

- A role that can write. The override is `MCP_ALLOW_EXCESSIVE_ROLE=i-accept-the-risk`.
- No authentication configured. The override is `MCP_ALLOW_ANONYMOUS_NETWORK=i-accept-the-risk`.

Both overrides are recorded in the audit log and exist for a human doing local testing, not for
an agent to set on its own initiative. If a setup task requires one, say so explicitly to the
user and let them decide — do not silently add either flag to make a deployment "just work".
