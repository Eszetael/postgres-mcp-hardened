# The adversarial corpus

Every shape that got past a control during review, kept as a runnable test — including the ones that
worked, and the round in which they stopped working.

This exists because the alternative does not survive contact with reality. A security claim that can
only be checked by reading our source is a claim you have to take on trust, and this project's own
history is the argument against that: three separate rounds of review defeated the column-redaction
control, each time through a shape nobody had thought to list. Publishing the list is not a
confession, it is the only form of the claim that can be falsified.

## Running it against your own database

```bash
cargo build --release
ADV_URL='postgres://reader:pw@localhost:5432/yourdb' \
  ADV_TABLE=people ADV_TABLE2=orders ADV_REDACT_COL=ssn \
  ./tests/adversarial/run.sh
```

It starts a server against the connection string you give it, sends every case, and prints a line
per case. A mismatch is an exit code, not a warning.

Point it at your own data if you like — nothing here writes, and the whole point is that you do not
have to believe us. If a case that says `deny` comes back allowed on your PostgreSQL version or your
schema, that is a finding, and we would like the line.

The cases are written against placeholders, so they run on any schema:

| variable | default | what it names |
|---|---|---|
| `ADV_TABLE` | `staff` | a table holding the column you want kept out of results |
| `ADV_TABLE2` | `film` | any table the role can read |
| `ADV_REDACT_COL` | `password` | the column that must not come back |

Set them to relations you actually have. If you leave the defaults against a schema without those
tables, the cases will pass for the wrong reason — refused because the table does not exist, which
proves nothing.

## Format

One case per line, tab-separated:

```
expect<TAB>SQL<TAB>why this case exists
```

`expect` is one of:

| value | meaning |
|---|---|
| `deny` | must be refused, always |
| `allow` | must work — the corpus guards against over-refusal as much as under-refusal |
| `deny-under-redaction` | must be refused while `MCP_REDACT_COLUMNS` names a column in the query's table |

The third field is not decoration. A case whose reason nobody recorded is a case that gets deleted
during the next refactor by someone who cannot tell whether it still matters.

## Adding a case

If you find a way through, open a pull request with the line. That is the whole process — an
accepted report becomes a permanent test, credited to whoever found it. See `SECURITY.md` for what
counts as in scope, and `THREAT_MODEL.md` for what we already say is depth rather than a boundary
(there is no point reporting that `MCP_REDACT_COLUMNS` is bypassable on a role that still holds
`SELECT` on the column — that is documented, and the fix is `--print-setup-sql`).

## The files

| file | what it probes |
|---|---|
| `redaction_evasion.txt` | reaching a column the operator marked sensitive |
| `write_smuggling.txt` | changing data through a server that only reads |
| `catalog_functions.txt` | functions that write, touch the filesystem, hold locks, or take SQL as text |
| `output_injection.txt` | database content trying to act on the model rather than inform it |
