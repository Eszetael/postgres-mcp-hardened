#!/usr/bin/env bash
set -euo pipefail

# ADV_URL must be set to a live PostgreSQL connection string
if [ -z "${ADV_URL:-}" ]; then
  echo "Usage: ADV_URL=postgresql://user:pass@host/db [ADV_TABLE=t] [ADV_TABLE2=t] [ADV_REDACT_COL=col] $0"
  echo "Run adversarial tests against a live postgres-mcp-hardened server."
  exit 2
fi

# Which relations the cases run against. Defaults match the project's own fixture; override them to
# run the corpus on your data.
ADV_TABLE="${ADV_TABLE:-staff}"            # a table holding the sensitive column
ADV_TABLE2="${ADV_TABLE2:-film}"           # any readable table
ADV_REDACT_COL="${ADV_REDACT_COL:-password}"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$PROJECT_DIR/target/release/postgres-mcp-hardened"
if [ ! -x "$BIN" ]; then
  echo "ERROR: binary not found at $BIN" >&2
  exit 1
fi

# A free port, from the one helper the whole suite uses. This file had the right idea first and its
# own copy of it; the copy also handed out ephemeral-range ports, which the acceptance suite had
# already learned to avoid. One helper, one set of hard-won constraints.
ADV_PORT=$("$PROJECT_DIR/tests/free_port.sh")

# Start the server with the adversarial database and redaction settings
# MCP_ADDR, not PORT — and loopback, so the start-up gate does not refuse a role it would be right
# to refuse on a network listener. The corpus is about query handling, not deployment shape.
DATABASE_URL="$ADV_URL" \
MCP_REDACT_COLUMNS="$ADV_REDACT_COL" \
MCP_ADDR="127.0.0.1:$ADV_PORT" \
MCP_RATE_RPM=0 \
"$BIN" >/dev/null 2>&1 &
MCP_PID=$!

# Ensure the server is killed when this script exits
cleanup() {
  # `|| true` on both: `wait` on a process we just killed returns 143, and under `set -e` the EXIT
  # trap's last status becomes the script's. The corpus passed 82 of 82 and the job still went red.
  kill "$MCP_PID" 2>/dev/null || true
  wait "$MCP_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Poll health endpoint until the server is ready (max 30s)
for i in $(seq 1 30); do
  if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$ADV_PORT/health" | grep -q '200'; then
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "ERROR: server did not become healthy" >&2
    exit 1
  fi
  sleep 1
done

TOTAL=0
MISMATCHES=0
CORPUS_DIR="$PROJECT_DIR/tests/adversarial/corpus"
shopt -s nullglob

# Process each corpus file
for file in "$CORPUS_DIR"/*.txt; do
  fname=$(basename "$file")
  while IFS= read -r line || [ -n "$line" ]; do
    # Skip empty lines and comments
    [ -z "$line" ] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue

    # Parse TAB-separated fields: expect, sql, comment
    IFS=$'\t' read -r expect sql comment <<< "$line"

    # The corpus is written against placeholders so it runs on ANY schema, not only ours. A corpus
    # that names our fixture tables would be a demonstration; one you can point at your own database
    # is evidence.
    sql=${sql//\{\{T2\}\}/$ADV_TABLE2}
    sql=${sql//\{\{T\}\}/$ADV_TABLE}
    sql=${sql//\{\{COL_UPPER\}\}/$(printf '%s' "$ADV_REDACT_COL" | tr '[:lower:]' '[:upper:]')}
    sql=${sql//\{\{COL\}\}/$ADV_REDACT_COL}

    TOTAL=$((TOTAL + 1))

    # Safely encode the SQL into JSON using Python (handles quotes, escapes, etc.)
    sql_json=$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))' <<< "$sql")

    # Build JSON-RPC body
    body='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{"sql":'"$sql_json"'}}}'

    # Send request to the live server
    response=$(curl -s -X POST "http://127.0.0.1:$ADV_PORT/mcp" \
      -H "Content-Type: application/json" \
      -d "$body")

    # Classify response: REFUSED if error or isError field present, otherwise ALLOWED
    if [ -z "$response" ]; then
      # No answer at all is not a refusal. Counting it as one would turn a dead server into a
      # clean run, which is the most comfortable way for a security check to become worthless.
      verdict="NO-ANSWER"
    elif echo "$response" | grep -q -e '"error"' -e '"isError"'; then
      verdict="REFUSED"
    else
      verdict="ALLOWED"
    fi

    # Determine expected behaviour: deny and deny-under-redaction both expect REFUSED
    case "$expect" in
      deny|deny-under-redaction)
        if [ "$verdict" != "REFUSED" ]; then
          status="MISMATCH"
          MISMATCHES=$((MISMATCHES + 1))
        else
          status="OK"
        fi
        ;;
      allow)
        if [ "$verdict" != "ALLOWED" ]; then
          status="MISMATCH"
          MISMATCHES=$((MISMATCHES + 1))
        else
          status="OK"
        fi
        ;;
      *)
        # Unknown expectation – treat as mismatch to be safe
        status="MISMATCH"
        MISMATCHES=$((MISMATCHES + 1))
        ;;
    esac

    # Print one-line outcome: status, filename, expectation, first 60 chars of SQL
    printf "%-8s %s %-20s %s\n" "$status" "$fname" "$expect" "${sql:0:60}"
  done < "$file"
done

# Final summary
echo ""
echo "Total cases: $TOTAL"
echo "Mismatches:  $MISMATCHES"

if [ "$MISMATCHES" -gt 0 ]; then
  exit 1
fi
exit 0