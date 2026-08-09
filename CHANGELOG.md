# Changelog

## 0.1.1 — 2026-08-09

Everything here was found on the day 0.1.0 went out, by reading the code rather than by a test
noticing. None of it changes what the server refuses; all of it changes what it tells you.

- **Resource URIs encode the names they carry.** A table named `a/b/schema` was listed as
  `postgres:///db/app/a/b/schema/schema` and then refused with "unknown resource" — a resource
  offered and immediately withdrawn. Names are percent-encoded on the way out and decoded on the way
  in; a malformed escape is refused rather than guessed at, because a guessed name reads a different
  table.
- **`cargo install postgres-mcp-hardened` was in the README and does not work** — the crate is not
  on crates.io. Removed from both places it appeared, and the installation section now describes the
  three routes that do exist.
- **Release path took every artefact of the run**, not just the binaries. Which artefacts exist
  depends on what has finished, so a re-run saw one more than the first attempt and stopped before
  publishing. Both the signing and the npm jobs now name what they need.

## 0.1.0 — 2026-08-09

First release — a secure, read-only PostgreSQL MCP server in Rust; a hardened
alternative to the deprecated `@modelcontextprotocol/server-postgres`.

- **Speaks three MCP revisions, newest by default:** `2026-07-28` (current — stateless, no
  handshake, no session header; every request carries its version in `_meta`), `2025-11-25`
  (refusals arrive as tool execution errors, so the model rewrites the query instead of the user
  seeing a broken call) and `2025-06-18`. `server/discover` answers under every revision, and
  carries the security posture as structured data — so a client can learn it is talking to a
  superuser connection before it sends a query.

  `MCP_PROTOCOL_PREVIEW` gated the newest revision while it was a draft. Upstream cut
  `schema/2026-07-28` on 2026-08-03 — the released schema differs from the draft we had verified
  against in four documentation URLs and nothing else — so the switch is retired and the revision
  is the default. A client speaking it was being negotiated *down* to `2025-11-25` until then,
  which is the behaviour we exist to replace. The variable stays recognised so an existing config
  line is not reported as a misspelling; startup says once that it no longer does anything.

- **The handshake is exempt from the header requirement, never from header agreement.** From
  `2026-07-28` a Streamable HTTP POST must carry `Mcp-Method`. Applying that to `initialize` closes
  a loop: `initialize` is where a client learns what the server speaks, so refusing it for breaking
  a rule of the revision it is still negotiating leaves the client no way to find out. Headers that
  *are* sent must still match the body — a gateway that authorises on `Mcp-Method` while we execute
  something else is the hole that check exists to close.

- **Unknown command-line options are refused, and `--help`/`--version` answer.** The binary used to
  scan for the flags it knew and ignore the rest: `--version` started an HTTP listener instead of
  printing a version, and a typo in `--stdio` turned a local stdio server into a network listener —
  a hang to the client that spawned it, and an unasked-for open port on a shared machine.
- **Runs on a container platform without code changes (Apify Standby).** The assigned port is read
  from `ACTOR_WEB_SERVER_PORT` and wins over `MCP_ADDR` — said out loud on stderr, because binding
  elsewhere means the run is never marked ready and the symptom is an unexplained timeout. `GET /`
  answers the readiness probe without touching the database. Authentication there belongs to the
  platform, which checks the caller's token before routing; the server stops demanding its own only
  when **both** `APIFY_IS_AT_HOME` and `ACTOR_WEB_SERVER_PORT` are present, and then reports
  `"type": "apify-platform"` instead of claiming a lock it does not hold. One marker alone changes
  nothing, and the refusal to expose a role that can write is untouched.
- **`Mcp-Method`/`Mcp-Name` are checked whenever they are sent, not only from the revision that
  requires them.** The reason the check exists — a proxy authorising on the header while the server
  runs the body decides about a different request — does not depend on which revision is in force,
  yet the check did. Requiring the headers early would break every current client, so they are held
  to agreement rather than presence: send them and they must match, send none and nothing changes.
- **The command-line gates exit with the verdict they print.** `--validate` printed `REJECT:` and
  exited `0`, so `if server --validate "$sql"` read a refused write as permitted; `--canon` did the
  same on an error. `--verify-audit tampered.log | head -1` exited `0` as well, because a closed pipe
  was treated as "the reader has seen enough" without asking what the verdict had been — silently
  passing in the one case where the answer matters most.
- **The generated setup script can no longer be turned into arbitrary DDL.** `--print-setup-sql`
  writes SQL an operator pastes into `psql` as a superuser. A schema name went into the
  `search_path` line as a raw single-quoted literal, so `--schemas "public'; DROP DATABASE postgres; --"`
  produced a script containing a live `DROP DATABASE`. Two other sites in the same file already
  escaped correctly — the pattern was known and applied to some of them. Escaping now goes through
  one function, and names carrying a quote, a semicolon or a backslash are refused outright: the
  escaping is the fix, the character check is the second lock.
- **A truncated write-check no longer passes as a clean bill of health.** The query behind "this role
  cannot write" stops at 5 000 relations and has no `ORDER BY`, so the sample is arbitrary — yet the
  verdict ignored whether it had been truncated. A role writable only to tables outside that
  arbitrary subset was reported as a reader, and the server exposed itself to the network on the
  strength of it. Absence of a finding meant "we did not find", and it was reported as "there is
  none". The unverified case is now named as unverified.
- **Membership in a *custom* role with dangerous attributes is seen.** The check asked about eight
  built-in role names and nothing else, while role attributes stop being un-inherited the moment a
  user types `SET ROLE` — the same reasoning already written down for `NOINHERIT`, applied to a list
  and not to the rest of the database. Both found by an independent reviewer, both proved against a
  live database rather than by reading the query.
- **The version refusal carries `requested`, not only `supported`.** The finalized draft puts both in
  `data`, and the shape matters more than it looks: its backward-compatibility rules tell a client to
  recognise a *modern* server by recognising this error object. A value carried only in the message is
  a value a client cannot read — leaving it out would have made this server look legacy to exactly the
  clients that arrived speaking the new revision.
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
