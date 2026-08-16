# Every reported problem, and what this server does about it

This project started by reading other people's issue trackers rather than guessing what a Postgres
MCP server should do. Below is the complete ledger: every problem reported against the deprecated
`@modelcontextprotocol/server-postgres`, and every open issue against the actively maintained
alternatives, with what happens here.

Reaction counts are 👍 on the linked issues, summed per row where a row cites several, and they
indicate how many other people hit the same thing. **Counted on 2026-08-16.** They drift: between
26 July and 16 August four of the thirty-eight moved by one, and one of those moved *up*. The date
is here so the number can be checked against something rather than trusted.
Where a row says “verified”, it names the check in `tests/acceptance.sh` that proves it on every CI
run. `tests/docs_claims.sh` fails the build if a claim names a check that does not exist.

## The deprecated `@modelcontextprotocol/server-postgres`

| Reported | 👍 | Here |
|---|---|---|
| [#1219](https://github.com/modelcontextprotocol/servers/issues/1219) Cannot run two instances (prod + dev) — the client picks one | 13 | Both run; resource URIs carry the database name and `MCP_SERVER_LABEL` names the instance. One server can also serve both via `MCP_DATABASE_URLS`. *verified* (acceptance: "several databases from one server") |
| [#1285](https://github.com/modelcontextprotocol/servers/issues/1285) Hangs indefinitely against RDS, no output, no error | 7 | Bounded: an unreachable host answers in ~8 s naming the cause. Lazy pool, 5 s checkout, 3 s diagnostic probe. |
| [#697](https://github.com/modelcontextprotocol/servers/issues/697) One database per instance because the URL is a CLI argument | 5 | `MCP_DATABASE_URLS="prod=…;dev=…"`; every tool takes an optional `database`. *verified* (acceptance: "several databases from one server") |
| [#866](https://github.com/modelcontextprotocol/servers/issues/866) Example code runs arbitrary SQL — security implications | 5 | The premise of this project: AST validation, an always-rolled-back read-only transaction, and a denied administrative-function space. *verified, 15 attacks* |
| [#600](https://github.com/modelcontextprotocol/servers/issues/600) `no pg_hba.conf entry … SSL off` | 4 | The error states that the server requires TLS and names the fix (`?sslmode=require`). Both PostgreSQL wordings recognised. |
| [#1014](https://github.com/modelcontextprotocol/servers/issues/1014) `Unexpected end of JSON input` | 4 | Multi-line messages are buffered until complete; malformed input returns a parse error instead of silence. *verified* (acceptance: "multi-line message is assembled") |
| [#845](https://github.com/modelcontextprotocol/servers/issues/845) / [#842](https://github.com/modelcontextprotocol/servers/issues/842) Connection string from the environment | 3 | `DATABASE_URL`, the positional argument, or `MCP_PASSWORD_FILE` for the password alone. |
| [#1121](https://github.com/modelcontextprotocol/servers/issues/1121) / [#1885](https://github.com/modelcontextprotocol/servers/issues/1885) / [#1873](https://github.com/modelcontextprotocol/servers/issues/1873) Self-signed certificate, unable to verify the first certificate | 3 | `MCP_SSLROOTCERT` takes the provider CA bundle, and the error names the exact step for your provider (Supabase, RDS, Cloud SQL, DigitalOcean) instead of "TLS handshake failed". Verified against a live Supabase instance. A Supabase host that never answers also gets told that the direct endpoint is IPv6-only and the pooler is the IPv4 route. |
| [#1047](https://github.com/modelcontextprotocol/servers/issues/1047) `-32601 Method not found` | 1 | `ping` and resources implemented; an unknown method returns a clean, correct error. *verified* (acceptance: "ping") |
| [#102](https://github.com/modelcontextprotocol/servers/issues/102) "Could not attach to MCP server" | 0 | A configuration mistake exits with status 2 and prints its reason; a connection problem is reported on the first query with the cause. *verified* (acceptance: "refuses to start:") |
| [#1063](https://github.com/modelcontextprotocol/servers/issues/1063) Partition tables flood the resource list | 0 | Children hidden by default, parent listed; `MCP_SHOW_PARTITIONS=1` restores them. *verified* (acceptance: "partition children hidden") |
| [#1310](https://github.com/modelcontextprotocol/servers/issues/1310) `npx` start "works" but nothing listens on a port | 0 | A single binary, no npx. stdio has no port by design; HTTP mode prints its address. Explained in Troubleshooting. |
| [#1929](https://github.com/modelcontextprotocol/servers/issues/1929) `INVALID_URL` in Docker | 0 | The real cause is a password containing `@ : / #`; the error names the characters and their encodings. |
| [#1713](https://github.com/modelcontextprotocol/servers/issues/1713) Can a client on another machine reach the database? | 0 | Yes: HTTP transport with OAuth 2.1 or a shared bearer token; credentials stay on the server host. |
| [#1889](https://github.com/modelcontextprotocol/servers/issues/1889) Read-only bypassed by injecting `COMMIT` / `END` | 0 | Rejected on tokens before parsing. Reproduced on a live database: the deprecated server's own sequence writes a row; all eight variants are refused here. *verified* (acceptance: "transaction control refused") |
| [#71](https://github.com/modelcontextprotocol/servers/issues/71) `spawn npx ENOENT` | 0 | No Node, no npx, no `node_modules`. |
| [#12](https://github.com/modelcontextprotocol/servers/issues/12), [#6](https://github.com/modelcontextprotocol/servers/issues/6) Housekeeping (version bump, add a README) | 0 | Not applicable — noted so the ledger is complete rather than selective. |

## Open issues against maintained alternatives

Their trackers describe what still goes wrong in this space. Each was checked against this server.

| Reported | 👍 | Here |
|---|---|---|
| [crystaldba#98](https://github.com/crystaldba/postgres-mcp/issues/98) A new connection pool per client, never cleaned up | 10 | One pool per configured database, shared by every session: 20 client sessions used one connection. *verified* (acceptance: "20 client sessions share one pool") |
| [crystaldba#141](https://github.com/crystaldba/postgres-mcp/issues/141) / [#162](https://github.com/crystaldba/postgres-mcp/issues/162) The published image lags the code | 14 | The container is built and pushed from the same tag that produces the binaries, amd64 and arm64. |
| [crystaldba#99](https://github.com/crystaldba/postgres-mcp/issues/99) Hardcoded query timeout | 9 | `MCP_STATEMENT_TIMEOUT`, validated at startup. |
| [crystaldba#71](https://github.com/crystaldba/postgres-mcp/issues/71) Table and column comments missing from metadata | 3 | `describe_table` and the resources return `COMMENT ON` text, primary keys and foreign keys. *verified* (acceptance: "column comments are exposed") |
| [crystaldba#171](https://github.com/crystaldba/postgres-mcp/issues/171) / [dbhub#66](https://github.com/bytebase/dbhub/issues/66) Is there a bearer token for the server itself? | 1 | `MCP_BEARER_TOKEN`, compared in constant time, alongside or instead of OAuth 2.1. *verified* (acceptance: "request with the token is served") |
| [crystaldba#164](https://github.com/crystaldba/postgres-mcp/issues/164) Default unrestricted mode allows arbitrary SQL | 2 | There is no write path to enable. |
| [crystaldba#97](https://github.com/crystaldba/postgres-mcp/issues/97) / [#176](https://github.com/crystaldba/postgres-mcp/issues/176) Keep the password out of the config | 2 | `MCP_PASSWORD_FILE` reads it from a file (a mounted secret, for instance). |
| [crystaldba#167](https://github.com/crystaldba/postgres-mcp/issues/167) Redact sensitive columns so they never reach the model | 1 | `MCP_REDACT_COLUMNS`: masked in results *and* refused if referenced — renaming or wrapping the column does not get past it. *verified* (acceptance: "renaming a redacted column is refused") |
| [crystaldba#153](https://github.com/crystaldba/postgres-mcp/issues/153) Allow `EXPLAIN ANALYZE` for SELECT in restricted mode | 1 | `explain_query` with `analyze` — safe here because the statement is validated read-only and the transaction is always rolled back. *verified* (acceptance: "explain_query analyze reports real timings") |
| [crystaldba#175](https://github.com/crystaldba/postgres-mcp/issues/175) Docker setup accumulates orphaned containers | 1 | The documented configuration points the client at the binary; the container-per-session pattern is called out in the examples. |
| [crystaldba#68](https://github.com/crystaldba/postgres-mcp/issues/68) "Received request before initialization was complete" | 1 | Requests are handled independently of handshake ordering; a tool call without a prior `initialize` is served. |
| [crystaldba#181](https://github.com/crystaldba/postgres-mcp/issues/181) Tables in a custom schema are not found | 0 | `MCP_SEARCH_PATH`; the fix had to reach the cost guard too, which runs on its own connection. *not yet covered by a test* |
| [crystaldba#145](https://github.com/crystaldba/postgres-mcp/issues/145) DNS-rebind protection breaks it in Docker | 2 | Not applicable: no such framework layer here. |
| [crystaldba#182](https://github.com/crystaldba/postgres-mcp/issues/182) Helm chart | 0 | Not planned for 0.1. Said plainly rather than left implied. |

## What we could not answer with code

Two of the reports above are environment problems on the reporter's machine (Node not on `PATH`,
a client spawning containers). They disappear here because there is no Node and the documented
configuration does not spawn containers — but there was nothing to fix in the server itself, and
this ledger says so rather than claiming credit.
