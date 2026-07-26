# Changelog

## 0.1.0 (unreleased)

First release — a secure, read-only PostgreSQL MCP server in Rust; a hardened
alternative to the deprecated `@modelcontextprotocol/server-postgres`.

- **Read-only, enforced three ways:** every query runs inside an explicit
  `BEGIN TRANSACTION READ ONLY` that is always rolled back, so nothing this server does
  can ever be committed — on top of the AST validation and the session flag.
- **Read-only, enforced twice:** SQL parsed to an AST (`sqlparser`) — only
  `SELECT`/`WITH`/`EXPLAIN`/`SHOW` pass, multi-statement rejected at the *token*
  level (no parser grammar can swallow a trailing statement), and the read-only
  rules are applied to **every** query node, including derived tables and
  subqueries — plus the DB session set `default_transaction_read_only = on`.
- **Canonical-form gate:** the exact text sent to the database is re-validated
  before execution, so the server can never validate one statement and run another.
- **Deterministic fuzz harness** (`--fuzz`): the corpus of known writes is mutated
  with semantics-preserving transformations (comments, whitespace, case,
  dollar-quoting, invisible Unicode, parentheses); a mutant that becomes allowed,
  a panic, or an unsafe canonical form fails the build.
- **Anti-DoS:** a per-client token-bucket rate limit applied *before* token
  verification (so a flood of bad tokens cannot burn CPU on signature checks),
  a concurrency cap, enforced `statement_timeout` + `idle_in_transaction_session_timeout`,
  auto-injected `LIMIT`, and an `EXPLAIN (FORMAT JSON)` cost guard that rejects
  expensive plans before execution.
- **Audit verification built in:** `--verify-audit <file>` walks the chain with the same code
  that wrote it, names the first modified line, spots removed entries through a sequence gap,
  verifies across key rotations, and prints the last hash as an off-host anchor
  (`--expect-last` then catches a truncated or wiped log). A tamper-evident log you cannot
  check is a claim, not a control — and one that hides its own limits is worse.
- **TLS to PostgreSQL** (rustls, no OpenSSL): accepts every `sslmode` a cloud provider hands you
  (`require`, `verify-ca`, `verify-full`, `allow`), honours it, always verifies the
  server certificate, and accepts a private CA bundle via `MCP_SSLROOTCERT`.
- **Fair-use limits:** per-client request rate *and* a cap on concurrent in-flight
  requests, so one client cannot occupy the whole connection pool with slow queries.
- **Honest results:** `truncated` / `appliedLimit` are reported, `numeric` keeps full
  precision, and the untrusted-output block is escaped without altering the data.
- **Prompt-injection aware:** row data wrapped in a `trusted="false"` provenance
  block with delimiters escaped. Optional MCP `structuredContent`
  (`MCP_STRUCTURED_CONTENT=1`) carries the same provenance marker inside the object,
  because a client reading structured output never sees the text block.
- **Written for agent callers:** every tool has a `title`, the full 2025-06-18 annotation
  set, and a description that states its limits up front — the row cap, the `offset`
  needed to page past it, that `description` is null until somebody writes a
  `COMMENT ON`, and which of `top_queries`/`explain_query` answers which question.
- **Diagnostics that mean what they say:** index duplicates are grouped by the actual
  partial-index predicate and uniqueness (indexes over disjoint rows are no longer
  called duplicates, and a `UNIQUE` index is never offered up as a redundant copy);
  connection counts are scoped to the current database; an abandoned transaction is
  reported as idle-in-transaction rather than as a multi-hour running query; every check
  respects the caller's table privileges; and sequences the role cannot read are declared
  instead of silently dropped from the results.
- **No schema leaks:** database errors mapped to structured, non-leaking messages.
- **OAuth 2.1** (RS256 JWT: signature + `exp` + `aud` + `iss` + scope), optional.
- **Tamper-evident audit log** (hash-chained), **Prometheus `/metrics`**,
  **`/health` + `/ready`** probes.
- **Transports:** Streamable HTTP + stdio. Ships as a distroless, non-root container.
- **Sensitive-column redaction** (`MCP_REDACT_COLUMNS`): values masked in results and the column
  refused if referenced under any alias or expression.
- **Shared bearer token** (`MCP_BEARER_TOKEN`) for deployments without an identity provider.
- **Operational tools**: `explain_query` (optionally with real timings), `database_health`,
  `analyze_indexes`, `top_queries`.
- **Configurable** query timeout, `search_path`, and a password read from a file rather than the
  connection string.
- **Several databases from one server** (`MCP_DATABASE_URLS`) — every tool takes an optional
  `database`, resources span all connections and their URIs carry the database name, so a
  production and a development connection can never be confused.
- **Schema as MCP resources** — every table and view is readable as
  `postgres:///<schema>/<table>/schema`, matching what the deprecated server offered and adding
  comments, primary keys and foreign keys.
- Tools: `query`, `list_schemas`, `list_tables`, `describe_table` (parameterized).
  `describe_table` surfaces `COMMENT ON` documentation, primary keys and defaults —
  the cheapest available cure for a model guessing what a column means.
- **Session lifecycle** per Streamable HTTP: sessions are issued on `initialize`, unknown
  or expired ids get `404`, and `DELETE /mcp` terminates a session explicitly.
