# Examples

| File | What it is |
|---|---|
| `docker-compose.yml` | PostgreSQL with sample data plus the server, ready in one command |
| `seed.sql` | The sample schema, including the least-privilege `reader` role |
| `claude_desktop_config.json` | A stdio configuration for Claude Desktop or Cursor |
| `vscode_mcp.json` | The same for VS Code (`.vscode/mcp.json`), with the password prompted rather than written down |
| `setup-role.sh` | Prints the DDL for the read-only role, for you to read and then run with your own `psql` |

## One command

```bash
docker compose -f examples/docker-compose.yml up -d
```

Then ask it something:

```bash
curl -s -H content-type:application/json http://127.0.0.1:8080/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"query","arguments":{"sql":"SELECT name, country FROM people"}}}'
```

Two things worth trying, because they are the point of this server:

```bash
# A write is refused before it reaches the database
... "arguments":{"sql":"DROP TABLE people"}          # → non-read-only statement

# A redacted column cannot be read, renamed or wrapped
... "arguments":{"sql":"SELECT ssn FROM people"}      # → column ssn is redacted
... "arguments":{"sql":"SELECT * FROM people"}        # → ssn comes back as [redacted]
```

## Note for desktop clients

Point the client at the binary directly, as in `claude_desktop_config.json`. Wrapping it in
`docker run` per session is possible but leaves a container behind on every restart with some
clients — a problem reported against other servers in this space.
