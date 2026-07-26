#!/usr/bin/env bash
# Create the read-only role this server should connect as.
#
# The generator prints SQL and never runs it, deliberately: executing it would mean handing
# administrator credentials to a tool whose entire identity is that it is read-only, and putting
# those credentials in a config file and a shell history along the way. So the DDL goes through
# YOUR psql, under YOUR credentials, and you get to read it before it runs.
#
#   ./examples/setup-role.sh 'postgres://postgres@localhost/mydb' > setup.sql
#   less setup.sql          # read it. this is the whole point.
#   psql 'postgres://postgres@localhost/mydb' -f setup.sql
#
# Pass the schemas and any sensitive columns the same way you would to the server:
#   MCP_ALLOW_SCHEMAS=public MCP_REDACT_COLUMNS='ssn,card_number' ./examples/setup-role.sh ...
set -euo pipefail

if [ $# -lt 1 ]; then
  sed -n '2,16p' "$0" >&2
  exit 64
fi

BIN="${BIN:-postgres-mcp-hardened}"
command -v "$BIN" >/dev/null || { echo "cannot find $BIN — set BIN=/path/to/postgres-mcp-hardened" >&2; exit 127; }

# The generator needs to see the database to name the tables it is granting on. It connects
# read-only, like everything else here.
DATABASE_URL="$1" "$BIN" --print-setup-sql

cat >&2 <<'NOTE'

Written to stdout. Before you run it:
  - read the REVOKE lines. Column-level protection needs the table-level SELECT revoked FIRST,
    or the GRANT that follows is a no-op and the column stays readable. That mistake was in our
    own documentation until a test executed the advice and the secret came back.
  - the role is created NOINHERIT and NOBYPASSRLS on purpose. Do not "fix" that.
After running it, point the server at the new role and ask it for `security_posture`. It will
tell you what it can still reach.
NOTE
