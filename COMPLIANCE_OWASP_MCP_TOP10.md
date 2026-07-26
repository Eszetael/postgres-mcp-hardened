# OWASP MCP Top 10 (2025) — Compliance Mapping

How this hardened, read-only PostgreSQL MCP server addresses each vector of the
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/). Status is stated honestly:
**Addressed**, **Partial** (with what remains), or **N/A** (not a property of a single server).

| # | Vector | Status | How this server addresses it |
|---|--------|--------|------------------------------|
| MCP01 | Token Mismanagement & Secret Exposure | ✅ Addressed | No hardcoded secrets — `DATABASE_URL` and the optional JWT public key come from env/config. OAuth uses **RS256** (asymmetric: no shared secret to leak). Errors are structured and non-leaking (no tokens, schema, or values in messages). Tokens are never logged. |
| MCP02 | Privilege Escalation via Scope Creep | ✅ Addressed (+ deploy note) | Read-only enforced at **two layers**: AST validator rejects any write/DDL/side-effect, and the DB session sets `default_transaction_read_only=on`. OAuth scope is `mcp:query`. No wildcard permissions. **Recommended:** connect via a dedicated read-only DB role (least privilege beyond the session flag). |
| MCP03 | Tool Poisoning | ✅ Mostly | The 4 tools are **statically compiled**, not dynamically fetched or mutable at runtime → cannot be poisoned remotely. Output is flagged untrusted (see MCP06). Zero-width, bidi-override and word-joiner Unicode ("ASCII smuggling" / "Trojan Source") is stripped from returned string values. |
| MCP04 | Supply Chain Attacks & Dependency Tampering | ✅ Addressed | Single **static binary**, **distroless non-root** image, minimal audited crate set (no `node_modules`/`pip` chain). Release binaries are built in CI with `--locked` (the audited `Cargo.lock`, not a fresh resolve) and published with SHA-256 checksums on GitHub Releases. Hand-rolled protocol core = tiny dependency surface, no typosquat exposure. |
| MCP05 | Command Injection & Execution (RCE) | ✅ N/A by design | The server executes **no shell commands and no arbitrary code** — only read-only SQL validated by AST. `COPY … TO PROGRAM`, `DO` blocks, and side-effecting functions (`pg_read_file`, `dblink_exec`, `lo_export`, …) are rejected. There is no command-execution path. |
| MCP06 | Prompt Injection via Contextual Payloads | ✅ Addressed (server side) | Every result is wrapped in a structured block flagged `trusted="false"` with provenance; delimiters are escaped so a cell value cannot break out of the block. (The consuming agent/middleware must honor the untrusted flag.) |
| MCP07 | Insufficient Authentication & Authorization | ✅ Addressed | Optional **OAuth 2.1** (RS256 JWT; validates signature + `exp` + `aud` + `iss` + `scope`). Missing/invalid token → **HTTP 401 with `WWW-Authenticate`** per RFC 9728 (not 403), enabling proper OAuth discovery. Does not assume the network is trusted. |
| MCP08 | Lack of Audit and Telemetry | ✅ Addressed (differentiator) | **Hash-chained audit log** — every decision (`allowed` / `denied_cost` / `denied_validation` / `denied_auth` / `denied_scope` / `denied_rate`) is recorded with a sequence number and, whenever the caller is authenticated, their identity (`sub`) — including the insider case of a valid token exceeding its scope. Set `MCP_AUDIT_HMAC_KEY` to chain with **HMAC-SHA256**; keep the key off the host and the log cannot be rewritten. Verify with `--verify-audit`, which detects modified entries and removals, supports key rotation, and prints the last hash as the anchor you keep elsewhere — **tail truncation is only detectable against that anchor** (`--expect-last`), and we say so rather than implying otherwise. Failed audit writes raise `mcp_audit_write_failed_total` and a stderr warning. Prometheus `/metrics` for telemetry. |
| MCP09 | Shadow MCP Servers | ◻ N/A | An organizational governance concern (unmanaged instances), not a property of a single server. Mitigated indirectly by shipping one versioned artifact per release, with SHA-256 checksums and an SBOM. Releases are signed with Sigstore (keyless cosign) and carry SLSA build provenance — a claim that only becomes true of a release once one has been published, so check the assets rather than this sentence. |
| MCP10 | Context Injection & Over-Sharing | ✅ Addressed | Read-only; returns only the data the query selects; per-process session isolation; no cross-request or cross-session state retention. |

## Defense in depth (summary)

1. **AST validation** (`sqlparser`, not string matching) — rejects writes, DDL, multi-statement,
   data-modifying CTEs, `SELECT INTO`, `EXPLAIN ANALYZE <write>`, `FOR UPDATE`, and a denylist of
   side-effecting functions.
2. **DB-enforced read-only session** (`default_transaction_read_only=on`) — backstop if the parser ever misses.
3. **Per-session `statement_timeout`** — bounds runaway/expensive queries.
4. **Pre-execution `EXPLAIN` cost guard** — rejects plans above a configurable cost.
5. **Provenance-wrapped, delimiter-escaped output** (`trusted="false"`).
6. **Structured non-leaking errors** (SQLSTATE-mapped).
7. **Optional OAuth 2.1 (RS256)** with RFC 9728 discovery.
8. **Tamper-evident hash-chained audit.**
9. **Per-client rate limit + concurrency cap** — a token bucket keyed on the peer address, applied
   *before* token verification, so a flood of requests (valid or not) cannot burn CPU on signature
   checks or starve the connection pool. Excess → HTTP 429 with `Retry-After`.
10. **Canonical-form gate + deterministic fuzzing** — the exact text sent to the database is
    re-validated before execution, and the validator is continuously fuzzed with semantics-preserving
    mutations (comments, case, dollar-quoting, invisible Unicode) that must never turn a write into an
    allowed statement.

_Read-only by design: no INSERT/UPDATE/DELETE support — that is the point. Validated end-to-end against a
real production-shaped database (pagila: 22 tables, 16k+ rows, exotic types)._
