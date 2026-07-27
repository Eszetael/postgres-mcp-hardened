# Threat model

## What this server is, and what it is not

It is a **privilege reducer and a witness**. It narrows what an AI agent can do to a database, and
it writes down what was attempted. It is not a firewall, and it is not a substitute for the database
refusing things itself.

That distinction is not modesty. Over three rounds of adversarial review, protection built on
"we will reject the bad query" was defeated four separate ways — a row cast to text, a qualified
wildcard inside a function argument, a column name assembled from `chr(112)`, a positional alias
list that renames columns without ever naming them. Each time the validator was extended; each time
a neighbouring shape got through. SQL has more ways to name a value than any filter can enumerate.

So the design changed. The controls that matter are the ones the server **cannot undo**: a privilege
the connected role does not hold. Everything else is depth, and this document says which is which.

## What we are protecting

| Asset | Why it matters |
|---|---|
| Row data | The obvious one, and the reason redaction exists at all. |
| Schema knowledge | Table and column names are reconnaissance; they are also how an agent works. |
| Database availability | A query that never ends is an outage. |
| Credentials | The connection string, the bearer token, the audit key. |
| **The audit log itself** | If it can be rewritten, everything above becomes deniable. |

## Trust boundary

```
  user ── LLM ── MCP client │ transport │ THIS SERVER │ PostgreSQL
                            └── untrusted ──┘         └── the real boundary
```

Everything left of the server is untrusted, including the model. **Especially** the model: it is the
component an attacker reaches by putting text in a row.

Everything the server returns is untrusted too, in the other direction — database content is wrapped
in a `trusted="false"` block precisely because a cell can contain instructions.

## Adversaries

**A. An agent under prompt injection — the primary one.** A row, a web page or a document tells the
model what to do next. It has legitimate credentials, unlimited patience, and perfect recall of SQL
syntax. It is not trying to break the transport; it is asking politely, in a shape nobody listed.
Everything in this project that looks paranoid exists because of this adversary.

**B. A curious legitimate user.** No malice; will still read the salary column if asked to "check
the data". Redaction and the surface allowlist address this one, and for them name-based filtering is
genuinely useful — an honest person does not go looking for `to_jsonb(t) ->> 'password'`.

**C. A network attacker on an exposed port.** Addressed by refusing to start unauthenticated on a
non-loopback address, by `Origin`/`Host` checks, and by rate and concurrency limits.

**D. An insider with a valid token.** Scope enforcement narrows what the token can do; the audit
records who did what. This is the case the identity fields exist for.

**E. Someone who can write to the host filesystem.** **Out of scope**, with one exception: if
`MCP_AUDIT_HMAC_KEY` is held off the host, they can destroy the log but cannot forge it. Everything
else on a compromised host is lost, and we do not pretend otherwise.

**F. A malicious dependency.** Addressed by `cargo audit`, `cargo deny`, a pinned toolchain and
`--locked` builds. Partially: this is a real risk we mitigate rather than eliminate.

**G. A database superuser.** **Out of scope.** If the connection role is a superuser, this server is
one bug away from irrelevant — which is why it refuses to expose one to the network at all.

## What the operator must make true

These are not recommendations. They are the assumptions the rest of this document rests on, and the
server checks each one rather than assuming it.

| Assumption | How to make it true | How you know |
|---|---|---|
| The role cannot write | `--print-setup-sql` | refuses to start on a network listener otherwise |
| Sensitive columns are unreadable | table-level `REVOKE` + column `GRANT` (generated) | startup check names every table where they are still readable |
| The transport is authenticated when exposed | `MCP_BEARER_TOKEN` or OAuth | refuses to start on a network listener otherwise |
| The audit cannot be rewritten | `MCP_AUDIT_HMAC_KEY` off the host, `--expect-last` anchor | `--verify-audit` |
| Traffic to the database is encrypted | `sslmode=verify-full` | certificate verification is always on |

## Controls, and what defeats each

| Control | Where | What defeats it |
|---|---|---|
| AST read-only validation | `validate.rs` | a construct the parser models differently than PostgreSQL executes it — this is the class that has been defeated before |
| Hidden-character refusal | `validate.rs` | nothing known, but it is a rule about *rendering*, and rendering is a moving target: it asks the standard library's Unicode tables rather than listing characters, because two earlier attempts each missed the next character along |
| Deny-listed function families | `validate.rs` | a function that takes SQL as text and is not in a denied family (this is why `*_to_xml*` is denied wholesale) |
| `BEGIN TRANSACTION READ ONLY` + rollback | `db.rs` | functions that write outside transactional control (`pg_import_system_collations` and relatives — hence the family denial above) |
| Column redaction | `validate.rs`, `db.rs` | **name-based filtering, defeated four ways in review. Depth, not a boundary.** The boundary is the column privilege. |
| Role privileges | PostgreSQL | a `SECURITY DEFINER` function, which runs as its owner — the one thing that defeats even this, and the reason the surface allowlist refuses functions it cannot see inside |
| Surface allowlist | `surface.rs`, the query plan | anything the plan does not name: a function body is opaque to the planner, so calls outside `pg_catalog` are refused while an allowlist is active |
| Start-up gate | `posture.rs` | an operator setting `i-accept-the-risk` — recorded in the audit |
| Cost guard and timeouts | `tools.rs`, session settings | a query cheap to plan and expensive to run; `statement_timeout` is the backstop |
| Rate and concurrency limits | `ratelimit.rs`, `pipeline.rs` | many source addresses; per-IP limiting does not isolate an actor, and we say so in the code |
| Provenance wrapper | `tools.rs` | a client that renders `structuredContent` straight into a prompt — off by default, documented |
| Hash-chained audit | `audit_log.rs` | truncating the tail, unless an anchor is kept elsewhere |
| Request/header agreement | `protocol.rs` | nothing, for a gateway that authorises on `Mcp-Method`/`Mcp-Name` — but only from `2026-07-28`, where those headers exist. Earlier revisions have no such headers, so a gateway on those transports must read the body |
| Scope enforcement | `authz.rs` | a token issued with more scope than its holder needs — we check the scope, not the wisdom of whoever minted it. It now covers `resources/*` as well as `tools/call`: schema reads are data |
| Origin refusal | `http.rs` | a non-browser client, which never sends `Origin` — this defends against a page in someone's browser reaching a loopback server, not against a program |

## Residual risks, unfixed and named

- **A parse failure is not a control, and we relied on one without knowing.** Upgrading `sqlparser`
  from 0.49 to 0.62 showed that several writes were being refused because the old library could not
  parse them, not because any rule here rejected them. The rules have since been fixed, but the
  lesson generalises: anywhere this validator's safety depends on the parser *failing*, a better
  parser removes the protection. The fuzz harness is the only thing that finds these, and it finds
  them only for constructs someone thought to mutate.

- **A new tool is a new way round every gate the old ones pass through.** `simulate_index` planned
  the caller's query on its own connection and so never reached the cost guard, which is where the
  surface allowlist lives — it would happily plan against a table the allowlist forbids and hand back
  the table name, its columns, the filter and the planner's row estimates. The identical hole had
  been found and closed for EXPLAIN months earlier. It is fixed, and the lesson is structural: the
  controls are attached to a code path, not to the server, so anything that opens a new path has to
  be walked against the list of them deliberately.

- **A gateway that authorises on headers, on an older revision.** `Mcp-Method`/`Mcp-Name` only
  exist from `2026-07-28`. If you put an authorising proxy in front of this server on `2025-11-25`
  or `2025-06-18`, the proxy has nothing to route on but the body — and if it decides without
  parsing it, it is deciding about a request it has not seen. We refuse the mismatch where the
  headers exist; we cannot invent them where they do not.

- **Side channels.** Query cost and timing reveal information about data the caller may not read.
  Unaddressed; addressing it properly would mean refusing legitimate work.
- **`EXPLAIN` output.** A plan contains row estimates for tables the caller can see. This is
  inherent to giving anyone a planner.
- **The model downstream.** Once data reaches the model, this server has no say in where it goes.
  Redaction and the surface allowlist are the only levers, and both act before the data leaves.
- **Reconnaissance without an allowlist.** With no surface allowlist configured, `query` reaches
  everything the role can see, including `pg_catalog`.
- **Expensive but legitimate queries.** The cost guard uses estimates; a bad estimate is exactly
  when it fails, and bad estimates are common on databases nobody has analysed.
- **Functions are refused under an allowlist.** Not narrowed — refused, unless named in
  `MCP_ALLOW_FUNCTIONS`. A function body does not appear in a query plan, so there is nothing to
  check; a review used one to read a table the role had been explicitly denied. This is a real cost
  of turning the allowlist on, and it is the honest price of the guarantee.
- **Views need their base tables allowed too.** The plan names base tables, not the view, so allowing
  only the view refuses the query. Allow both — and let the database privileges keep the base table
  unreachable directly, which is the boundary anyway. Verified by running it, after this document
  claimed the opposite.

## What would change our mind

Every claim here is meant to be falsifiable, and the corpus in `tests/adversarial/` exists so that
falsifying one is a pull request rather than an argument. If you can make this server return a value
from a redacted column against a role that has been set up as `--print-setup-sql` describes, that is
not a bug report — it is a hole in this document, and we would like to know.

Reports: see `SECURITY.md`. An accepted report becomes a line in the corpus, credited.

## History

- **2026-07-26** — first version, written after three adversarial rounds moved the design from
  "reject bad queries" to "hold fewer privileges, and prove it".
