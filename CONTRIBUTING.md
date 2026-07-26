# Contributing

The bar here is unusual, so it is worth stating plainly before you spend time on a change.

## What this project optimises for

Being correct about the database and honest about itself, in that order. A feature that is useful
but can mislead an agent — a truncated result that looks complete, a number that lost digits, a
control that a rename walks past — will not be merged, however convenient it is.

## Before opening a pull request

```bash
git config core.hooksPath .githooks   # once, per clone
```

That hook runs the fast half of CI before a push and refuses one that would go out red. Worth
knowing why it checks clippy separately from the tests: `cargo test` passes on code clippy
rejects, because clippy lints are not compiler errors — "it builds locally" has never been the
same claim as "CI will be green".


- `cargo test` and `cargo clippy --all-targets -- -D warnings` are clean.
- `cargo fmt` has been run.
- `./tests/acceptance.sh` passes (it starts its own PostgreSQL through Docker).
- Anything touching the validator also survives `./target/release/postgres-mcp-hardened --fuzz 300000`.

## Adding a rule to the validator

Add the attack to the `MUST_REJECT` corpus in `src/validate.rs` *and* to the fuzz corpus in
`src/fuzz.rs`. A fix that patches the reported example but not the neighbouring variant is the
failure mode we care most about: ask what happens if the input is renamed, cast, wrapped in a
function, nested one level deeper, or written with different whitespace.

## Claims in the documentation

Every behavioural claim in `README.md`, `SECURITY.md` and `COMPLIANCE_OWASP_MCP_TOP10.md` should be
reproducible with a command. If you change behaviour, change the sentence describing it in the same
commit. Documentation that overstates what the code does is treated as a defect, not a rough edge.

## Reporting a vulnerability

Please do not open a public issue — see [SECURITY.md](SECURITY.md).
