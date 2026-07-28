# Changelog

## 0.1.0 (unreleased)

First release — a secure, read-only PostgreSQL MCP server in Rust; a hardened
alternative to the deprecated `@modelcontextprotocol/server-postgres`.

- **Speaks three MCP revisions:** `2025-06-18` (what shipping clients speak), `2025-11-25`
  (current — refusals arrive as tool execution errors, so the model rewrites the query instead of
  the user seeing a broken call), and `2026-07-28` behind `MCP_PROTOCOL_PREVIEW=1` while it is
  still a draft upstream. `server/discover` answers under every revision, and carries the security
  posture as structured data — so a client can learn it is talking to a superuser connection
  before it sends a query.
- **An unsupported protocol version is refused, not downgraded.** `MCP-Protocol-Version:
  not-a-date` used to get `200` and the oldest contract; the transport specification makes `400 Bad
  Request` a MUST here, and for good reason — the client goes on believing it negotiated something
  the server never agreed to, and nothing in the exchange says otherwise. The refusal carries the
  list of revisions the server does speak. Falling back is for a header that is absent, not one
  that disagrees.
- **The server card advertises what the server speaks.** `/.well-known/mcp/server-card.json` named
  `2025-06-18` while the server has spoken `2025-11-25` since it shipped, so a registry or an agent
  reading the card had no way to learn otherwise. It now reports the newest revision and the full
  list, and takes its version from the package manifest instead of a literal that drifts.
- **A session remembers what it negotiated.** A client that agreed on a revision at `initialize` and
  then omitted the `MCP-Protocol-Version` header used to be served the oldest contract instead.
  The transport specification allows that default only when the server has no other way to
  establish the version, and names the session as exactly that other way; the session now carries
  the negotiated revision and the header-less request is answered under it. Only a request with
  neither header nor session falls back, and it falls back to the oldest revision this server
  implements rather than to a revision it does not.
- **Two of the draft's rules are treated as security controls:** `Mcp-Method`/`Mcp-Name` must
  agree with the request body, and a mismatch is refused and audited — the headers exist so a
  gateway can authorise without parsing the body, and if the two may disagree then whatever
  authorised and whatever runs saw different requests. A protocol version we do not implement is
  refused rather than silently served under a contract nobody agreed to.
- **The audit notices being shortened, not only altered:** a hash chain proves entries were not
  rewritten, but a log with its tail cut off is internally consistent and recomputing it finds
  nothing wrong — the previous code even carried a comment claiming otherwise, while reading its
  resume state from the very file it was guarding. A sidecar `<log>.hwm` now records the last
  sequence number and hash the server wrote, updated only after the entry is durably appended, and
  a mismatch at startup is reported: entries missing from the end, a rewritten last entry, or a log
  that has gone. Separately, a missing audit file and an unreadable one no longer share a code path
  — deleting the trail used to be indistinguishable from a first run.
- **The catalog path streams:** `describe_table`, `list_tables`, `explain_query` and the other
  non-SELECT tools buffered every row before the byte ceiling was applied, so the ceiling trimmed
  the answer while the peak stayed unbounded. They now stream through a portal like the query path
  and stop at the limit.
- **Signed releases:** every artefact is signed with Sigstore keyless signing, verifiable with
  `cosign verify-blob` against the workflow identity; public releases additionally carry SLSA
  build provenance. Release actions are pinned to commit hashes, not moving tags.
- **Index tuning without write access:** `simulate_index` uses hypopg to ask the planner what a
  query would cost if an index existed, then throws the hypothesis away. The tool takes a table and
  columns rather than DDL, and builds the definition from catalogue-verified, PostgreSQL-quoted
  identifiers.
- **One authorisation policy, not one per mechanism:** the same methods require credentials whether
  the deployment uses a shared token or OAuth. `resources/read` and `resources/list` need a read
  scope, because table and column names are data. The single exception is `server/discover`, which
  the specification expects clients to probe before they know whether a token is wanted — and which
  therefore never carries the security posture when authentication is configured.
- **Nothing hidden in a statement:** characters that are invisible, or that look like a space
  without being one, are refused outside string literals — `setval\u{2060}(...)` reads as `setval(`
  to a person and parses as something else, which is how a write function walks past a rule that
  names it. Inside a literal they are left alone, because a zero-width joiner is how emoji are
  built and honest queries contain them. Refused rather than stripped: editing the statement would
  mean validating one text and executing another.
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
