# Security Policy

This project *is* a security tool — reports are taken seriously.

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

## Supported versions

The latest published release is supported. This is pre-1.0; APIs may change.
