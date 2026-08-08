**What changes, and what breaks if it is wrong**

<!-- One or two sentences. The second half matters more than the first: a reviewer who knows the
failure mode can look for it. "Adds X" tells us less than "if this is wrong, a write reaches the
database / a truncated result looks complete". -->

**How you know it works**

<!-- The command and its output, not a description of the command. If a test now fails without your
change and passes with it, say so — that is the strongest thing you can write here, and it is worth
more than any amount of explanation. -->

---

Checks (see [CONTRIBUTING.md](../CONTRIBUTING.md) for why each one is here):

- [ ] `cargo test` and `cargo clippy --all-targets -- -D warnings` are clean
- [ ] `cargo fmt` has been run
- [ ] `./tests/acceptance.sh` passes (it starts its own PostgreSQL through Docker)
- [ ] validator changes also survive `./target/release/postgres-mcp-hardened --fuzz 300000`
- [ ] a validator fix adds the attack to **both** `MUST_REJECT` in `src/validate.rs` and the fuzz
      corpus in `src/fuzz.rs` — patching the reported example but not its neighbouring variant is
      the failure mode this project cares most about
- [ ] any behavioural sentence in `README.md` / `SECURITY.md` that your change makes untrue is
      changed in the same commit

**If you found a way to get a write past the validator, do not open a pull request** — report it
privately first, see [SECURITY.md](../SECURITY.md).

<!-- Reviewer's note, said out loud so it is not a surprise: a change can be correct, useful and
still declined, if it lets the server mislead the agent using it. A number that lost digits, a
result cut without saying so, a refusal that a rename walks past — those are worse here than a
missing feature, because the caller has no way to notice them. -->
