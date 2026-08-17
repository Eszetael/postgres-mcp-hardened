# Changelog

## 0.1.7 — 2026-08-17

Two days of walking every path this project documents, as a stranger would, from an empty directory.
Seven defects, and not one of them in the security core: that survived eight redaction bypasses, five
TLS scenarios, every startup gate and the whole audit chain without a scratch. Every defect was on
the surface — in a path somebody described and never walked to the end.

- **One-click install never worked.** The `.mcpb` manifest had existed since July and nobody had ever
  packed it, so nobody discovered that it fails the official schema validation: `repository` was a
  string where an object is required. The release workflow now validates the manifest and packs a
  bundle per platform from the binary it has just built, and `docs_claims.sh` validates it on every
  commit. The README leads with it, because "open this file" is a lower bar than "edit this JSON".
- **A correctly configured local server could not reach grade A, whatever the operator did.** Startup
  accepts an unencrypted connection to a database on this machine — the threat is somebody on the
  wire, and a loopback socket has no wire — but the posture grader did not know that rule and
  reported it as a finding, suggesting `sslmode=verify-full`, which breaks a local PostgreSQL that
  has no certificate. One predicate, `db_is_local`, now answers that question for both.
- **A password containing `@` sent the operator to check their firewall.** The message about
  percent-encoding hung off a parse failure, and a password with `@` does not fail to parse: the
  driver takes the last `@` as the separator and fails at connect time instead. Named outright now,
  with `MCP_PASSWORD_FILE` offered as the way to avoid the question.
- **TLS demanded from a local database blamed a missing CA.** A local PostgreSQL ships with
  `ssl = off` — the official Docker image and the distribution packages all do — and our own VS Code
  example demanded `sslmode=verify-full` from `localhost`, so it did not work as written.
- **Two example configurations were unusable as written.** `claude_desktop_config.json` named
  `/usr/local/bin/postgres-mcp-hardened`, which nothing in the documentation puts there, producing the
  `ENOENT` this project criticises in the server it replaces. The compose file's own header omitted
  the bearer token that the same file configures.
- **Every tool parameter now carries a description.** An external review of the tool surface scored
  the four tools with undescribed parameters lowest of the ten, every time for the same reason: a
  bare `{"type": "string"}` tells an agent nothing about where the value comes from. Each parameter
  now says, and each tool names a sibling and when to prefer it — `query` says outright not to
  hand-write catalog queries, because `list_tables` and `describe_table` already return that.
- **The README named the wrong current protocol revision** for ten days after `2026-07-28` became the
  default, and the stale sentence had already been copied into a published article.

Everything above is now pinned by a test. The suite grew from 280 acceptance cases to 288 and gained
two controls: one that verifies claims about *other people's* repositories (every cited issue must
exist; a drifted reaction count warns rather than failing, because that is the world moving and not
a defect here), and one that validates the `.mcpb` manifest against the official schema.

Key rotation and the audit sidecar — the two strongest promises the project makes — had no test at
all until now. Both do.

## 0.1.6 — 2026-08-15

The first outside environment to run this server found two defects in an afternoon, and both had
the same shape: the server was hostile to being *inspected*. Every catalogue, registry and gateway
starts a server with no database attached, puts `mcp-proxy` in front of it, and asks `initialize`,
`tools/list`, `resources/list` before a human ever sees it. This server failed that sequence twice,
which is why it could not be listed anywhere — including in the directory that reported it.

- **Somebody else's environment variable no longer stops startup.** `mcp-proxy` exports
  `MCP_PROXY_DEBUG`; 0.1.5 saw an unknown `MCP_*` name and exited 2 before reading a request. The
  check that did this is worth keeping — `MCP_REDACT_COLUMN`, one letter short of the real setting,
  would start the server with redaction silently off — so the two cases are now separated by the
  distinction the code was already computing. A near miss of a known setting (edit distance ≤ 3)
  is still fatal and still names the intended spelling. A name that resembles nothing we define is
  reported and ignored. `MCP_X_*` was supposed to cover this, but a reservation only helps programs
  that have read our source, and `mcp-proxy` never will.
- **`resources/list` answers when the database does not.** It returned a protocol error, which a
  host reads as a dead server. It now returns an empty list with the reason under a namespaced
  `_meta` key. This is not a claim that the schema is empty: `initialize` already reports that the
  database has not answered, `security_posture` gives the detail, and the reason now travels with
  the list itself. A database that answers and *refuses* — a missing privilege, say — is still an
  error, because reporting "no resources" for a permission problem is exactly the silent failure
  this project refuses everywhere else.
- **The acceptance suite now runs that inspection.** One case drives the whole sequence with
  `MCP_PROXY_DEBUG` set and a connection string pointing at a closed port, and asserts the empty
  list carries its reason. A second case asserts the misspelling still exits 2, so the fix cannot
  quietly loosen the check it came from.
- Worth recording, because it is the argument for publishing at all: none of this was findable from
  here. Six releases, 113 unit tests, an adversarial corpus and 2.4 million fuzzed mutations all
  passed on a machine where the environment was ours and the database was up. The defects needed
  somebody else's environment, and they appeared within a day of asking for one.

## 0.1.5 — 2026-08-09

Three releases were spent discovering the registry's rules one refusal at a time. This one stops
that: the rules were read out of the registry's own validator source and encoded as a check that
runs on every commit.

- **The OCI package carries its version in the identifier**, `ghcr.io/…/postgres-mcp-hardened:0.1.5`,
  and no longer has a `version` field — the registry refuses one that does.
- **The registry job now waits for the container job.** It *downloads* the image to read the
  ownership label, so the image for the version being released has to exist; with `needs: [npm]` it
  started while arm64 was still compiling under emulation, and would have failed on an image that
  was not there yet. Found by reading the job graph, not by spending a fourth version on it.
- **`check_registry_identity.py` now encodes the full rule set** for both package types: forbidden
  fields, supported registries, the image tag matching the released version, and the ownership
  markers. Each rule was verified to fail on its own violation.
- Worth recording, because it looks like a control and is not: `POST /v0/validate` answered
  `valid: true` for the manifest publishing rejected. It runs schema and semantic checks; the
  per-registry rules only run during publish. A green there is necessary, not sufficient.

## 0.1.4 — 2026-08-09

The registry has three ownership checks, not one. 0.1.3 fixed the first and was refused by the
second; the third was found by reading the specification instead of waiting for the next tag.

- **`mcpName` in the published npm package.** The registry reads the marker from the package on
  npm, not from this repository — and npm packages are immutable, so a missing field costs a whole
  version number. That is what happened to 0.1.3.
- **`io.modelcontextprotocol.server.name` on the container image.** Same proof, different carrier:
  a `LABEL` in the Dockerfile rather than a flag in the workflow, so a build from any context
  carries it. Verified empirically that it survives alongside the labels the release adds.
- **`scripts/check_registry_identity.py` now checks all three markers** — manifest name, npm
  `mcpName`, image label — against one source, on every commit.

## 0.1.3 — 2026-08-09

The registry entry 0.1.2 promised, and a defect the registry failure led me to while I was in there.

- **The registry manifest names the account that may publish it.** `0.1.2` reached npm, was signed,
  and was then refused by the MCP registry: the manifest said `io.github.eszetael`, the permission
  reads `io.github.Eszetael`. One capital letter, and the only check that knew the rule ran on a
  tag — after the version number was already spent. `scripts/check_registry_identity.py` now runs on
  every commit and compares the manifest against the repository itself, along with the versions in
  `Cargo.toml`, `npm/package.json` and every package entry.
- **A rehearsal no longer moves the container tag people pull.** `type=raw,value=latest` carried no
  condition, so every `-rc` run retagged `latest`: on 9.08 it pointed at `0.1.2-rc3`. The npm job
  had the guard and a comment explaining it — the rule existed and was applied to one of the three
  channels we publish through. `scripts/check_prerelease_guards.py` now checks all of them on every
  commit, and fails just as loudly if a channel disappears from the file entirely.
- **The generated `setup.sql` gives the role a `search_path` that resolves.** Every schema is now
  its own literal. Joining them — `SET search_path = 'a,b'` — is accepted by PostgreSQL and names a
  single schema called `a,b`; the role then fails every unqualified query with "relation does not
  exist", which reads as a missing grant or an empty database. Verified against PostgreSQL 16 both
  ways. Anyone with one schema never saw it: the defect needs a comma to exist.
- **A quote in `MCP_SEARCH_PATH` is doubled, not deleted.** Deleting it produced a statement that
  PostgreSQL accepts and that names a *different* schema than the one configured — `we"ird` silently
  became `weird`, and the queries then answered from the wrong data without an error anywhere.
  Startup already refuses such a value, so no shipped build could reach this; it is fixed as the
  second layer, because the first one is a single call site that a future early-return would skip.

## 0.1.2 — 2026-08-09

- **Every GitHub Action is pinned to a commit, not a tag.** These workflows hold `contents: write`
  and publish binaries under our name; a tag can be moved to a different commit by whoever controls
  the action, which makes it an unreviewed dependency with permission to publish. Dependabot still
  proposes the bumps — they now arrive as reviewable pull requests instead of arriving silently.
  Pinned to the versions already in use (checkout 4.3.0, upload-artifact 4.6.2 and so on), verified
  against each action's own `package.json`: this is a pin, not a hidden upgrade.
- **The release now registers itself with the official MCP registry**, authenticated by OIDC rather
  than a stored secret, and only after the npm registry confirms the version is installable.

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
