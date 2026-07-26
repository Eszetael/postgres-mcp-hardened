# Security Policy

This project *is* a security tool — reports are taken seriously.

Before reporting, [THREAT_MODEL.md](THREAT_MODEL.md) says what is in scope: it names the adversaries
we design against, the assumptions the operator has to make true, and the controls we already
describe as depth rather than as boundaries.

## Reporting a vulnerability

Please report suspected vulnerabilities privately by email to
**eskulapstudio@gmail.com** with `[SECURITY]` in the subject. Do not open a
public issue for undisclosed vulnerabilities.

Include: affected version, a description, and a reproduction (a SQL payload or
request that bypasses a control is ideal). We aim to acknowledge within 72 hours.

## Scope of interest

The safety model is the product. We especially want reports on:

- **Read-only bypasses** — any statement that mutates data yet passes validation
  (parser gaps, PostgreSQL-specific syntax, CTE tricks).
- **Cost-guard / timeout evasion** — a query that hangs or exhausts resources
  despite the `EXPLAIN` cost guard and `statement_timeout`.
- **Prompt-injection via row data** — output that escapes the `trusted="false"`
  provenance block.
- **Schema/error leakage** — an error path that echoes table or column names.
- **Auth** — token validation or scope-enforcement flaws.

## Deployment hardening (please read)

Point `DATABASE_URL` at a **dedicated, least-privilege role** — not a superuser. The server
enforces read-only itself, but the database role is the backstop that survives any bug in
our validator.

This matters more than it looks: **a PostgreSQL read-only transaction does not block every
write.** `SET default_transaction_read_only = on` refuses INSERT/UPDATE/DELETE/DDL, but a
handful of system functions write anyway — for example `pg_import_system_collations()` inserts
hundreds of rows into `pg_collation`, and `gin_clean_pending_list()` rewrites index structures,
both without raising `SQLSTATE 25006`. This server rejects those in its own validator (whole
administrative function families are denied, not just the names we happened to think of), but
if you connect as a superuser you are relying on that validator alone. A role without
`EXECUTE` on administrative functions — and without write privileges on your tables — is the
difference between one layer of defense and three.

`sslmode=verify-full` is recommended for any connection that leaves the host; certificates are
always verified, and a private CA (e.g. the AWS RDS bundle) goes in `MCP_SSLROOTCERT`.

On a **shared cluster**, remember that a broadly-privileged role can read `pg_stat_activity` and
other catalogs — which exposes the SQL text and metadata of *other databases* on the same instance.
That is PostgreSQL's own privilege model, not something this server can filter away without
breaking legitimate schema discovery. Another reason the connection role should be narrow.

If you rely on the audit log during an incident, set `MCP_AUDIT_HMAC_KEY` and keep the key off the
host. Without it the chain is still hash-linked, but anyone who can write the file can delete
entries and recompute the chain so that it verifies.

Verify a log with `postgres-mcp-hardened --verify-audit <file>`. Be precise about what that proves:

- **Modified entry** — detected (hash mismatch, with the line number).
- **Entry removed from the middle** — detected (broken link and a gap in `seq`).
- **Tail cut off, or the file emptied** — *not* detectable from the file alone: what remains is
  internally consistent, and cutting it needs no key. The only defence is an anchor kept elsewhere.
  Every verification prints the last hash for exactly this purpose — store it outside the host
  (your log pipeline already receives it on stderr) and pass it back with `--expect-last <hash>`.
  Then truncation and wiping are both caught.
- **Key rotation** — supported: each entry carries a short key fingerprint (never the key), and
  old keys go in `MCP_AUDIT_HMAC_KEYS_OLD`, so a rotated log still verifies end to end instead of
  looking like sabotage.

## The server checks its own role before exposing itself

Pointing `DATABASE_URL` at a superuser and binding to `0.0.0.0` is the configuration that turns every
other control into a single point of failure. The server now asks PostgreSQL what the role may do —
`rolsuper`, `rolbypassrls`, `REPLICATION`, membership of the predefined write roles, and write
privileges over a bounded sample of tables — and refuses to start when the listener is reachable from
the network and the answer is more than "reader". `--print-setup-sql` generates the role to use.

Membership is tested with `pg_has_role(..., 'MEMBER')`, not `'USAGE'`: a role with `NOINHERIT` does
not hold its groups' privileges until it runs `SET ROLE`, but it can run `SET ROLE` — so a `USAGE`
test reports "safe" about a role that is one statement away from being unsafe.

## What `MCP_REDACT_COLUMNS` is, and is not

It masks matching columns at every depth of the result and refuses a query that references them —
including by alias, inside a function, as a whole-row serialisation (`t::text`, `row_to_json(t)`,
`json_agg(t)`) or under a name given as a string (`to_jsonb(t) ->> 'password'`, `#>> '{password}'`,
`'$.password'`). Every one of those was a working bypass before an adversarial review, and each is
covered by a check in `tests/acceptance.sh`.

It is still filtering by name, and SQL has more ways to name a value than any filter can enumerate.
Treat it as defence in depth. The control that does not depend on our cleverness is the one the
database enforces:

```sql
REVOKE SELECT (password) ON staff FROM your_mcp_role;
```

**That statement alone does nothing while the role holds SELECT on the whole table** — PostgreSQL
treats the table-level grant as covering every column, so the column-level REVOKE is silently a
no-op. This server printed exactly that advice until an end-to-end test followed it and the value
came straight back. The working form is:

```sql
REVOKE SELECT ON staff FROM your_mcp_role;
GRANT SELECT (staff_id, first_name, last_name, ...) ON staff TO your_mcp_role;
```

At startup the server generates these statements for your schema, naming every table where the role
can still read a redacted column. `MCP_REDACT_REQUIRE_REVOKE=1` makes it refuse to serve until they
have been run. With column-level grants PostgreSQL refuses `SELECT *` on that table, so callers must
name columns — `describe_table` lists them and marks the redacted one.

With that in place a bypass returns a permission error instead of a secret, and the setting above
becomes what it should be: a second layer, and a clear signal of intent to whoever reads the config.

## Found a way through?

Open a pull request with the line that proves it — `tests/adversarial/corpus/` is where every
bypass this project has suffered already lives, with the round in which it stopped working. An
accepted report becomes a permanent test, credited to whoever found it. The corpus runs on every
build and anyone can run it against their own database:

```bash
ADV_URL='postgres://…' ADV_TABLE=people ADV_REDACT_COL=ssn ./tests/adversarial/run.sh
```

## Supported versions

The latest published release is supported. This is pre-1.0; APIs may change.
