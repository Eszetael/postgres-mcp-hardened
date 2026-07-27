# What does the safety cost?

Not "is it fast" — the useful question is how much slower this is than talking to PostgreSQL
directly, because that difference IS the price of the guarantees.

```bash
cd tests/bench && npm install
DBURL=postgres://... MCPURL=http://127.0.0.1:8080/mcp TOK=... N=300 node bench.mjs
```

The floor is the `pg` driver issuing the same query against the same database on the same machine.
Everything above it is what this server adds: HTTP and JSON-RPC, the AST validation, the canonical
re-validation, the cost guard's planning pass, the row cap, the audit write, and a session that is
reset and wrapped in a read-only transaction for every single request.

Run it with `MCP_RATE_RPM=0`. With the limit on, a benchmark looks exactly like the runaway loop the
limit exists to stop, and you end up measuring the rate limiter. That is not a flaw in either.

Deliberately NOT a CI gate. Shared runners give numbers that move for reasons that have nothing to
do with this code, and a check that cries wolf is a check people switch off. It is here to be run
when a change might plausibly have cost something.
