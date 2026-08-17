#!/usr/bin/env bash
# Twelve minutes of mixed traffic against a server this script starts itself, to answer one question:
# does anything grow that should not? The number that matters is not throughput. It is the file
# descriptor count at the end, and the shape of the memory curve.
#
# Deliberately NOT a CI gate. It takes twelve minutes and measures a machine as much as a program.
# It is here so that the paragraph in the README about a soak can be checked instead of believed.
#
#   ./tests/soak.sh              # twelve minutes, the number the README quotes
#   SECONDS_TO_RUN=60 ./tests/soak.sh
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="${BIN:-$ROOT/target/release/postgres-mcp-hardened}"
DUR="${SECONDS_TO_RUN:-720}"
PGPORT_SOAK="${PGPORT_SOAK:-35994}"
PORT="${PORT:-38200}"
URL="http://127.0.0.1:$PORT/mcp"
TOK=soak-$$
PG_IMAGE="${PG_IMAGE:-postgres:18}"
CONTAINER=soak_pg_$$

if [ ! -x "$BIN" ]; then
    echo "no binary at $BIN — run: cargo build --release" >&2
    exit 2
fi

cleanup() {
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
    docker rm -f "$CONTAINER" >/dev/null 2>&1
}
trap cleanup EXIT

docker run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=pw \
    -p "127.0.0.1:$PGPORT_SOAK:5432" "$PG_IMAGE" >/dev/null || exit 2
for _ in $(seq 1 60); do
    docker exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && break
    sleep 1
done

docker exec -i "$CONTAINER" psql -U postgres -q -v ON_ERROR_STOP=1 <<'SQL' >/dev/null || { echo "fixture failed" >&2; exit 2; }
CREATE TABLE orders(id int, customer text);
INSERT INTO orders SELECT i, md5(i::text) FROM generate_series(1,5000) i;
CREATE ROLE ro LOGIN PASSWORD 'ro';
ALTER ROLE ro SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE postgres TO ro;
GRANT USAGE ON SCHEMA public TO ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ro;
SQL

# The rate limit is off on purpose. With it on, a soak looks exactly like the runaway loop the limit
# exists to stop, and you end up measuring the limiter.
DATABASE_URL="postgres://ro:ro@127.0.0.1:$PGPORT_SOAK/postgres" \
    MCP_BEARER_TOKEN="$TOK" MCP_ADDR="127.0.0.1:$PORT" MCP_RATE_RPM=0 \
    "$BIN" >/tmp/soak_srv_$$.log 2>&1 &
SRV=$!
for _ in $(seq 1 30); do
    curl -sf -m 2 -H "authorization: Bearer $TOK" "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
    sleep 1
done
if ! kill -0 "$SRV" 2>/dev/null; then
    echo "server did not stay up; log:" >&2
    tail -5 /tmp/soak_srv_$$.log >&2
    exit 2
fi

H=(-H "authorization: Bearer $TOK" -H 'content-type: application/json'
   -H 'accept: application/json, text/event-stream')
rss() { awk '/VmRSS/{print $2}' /proc/$SRV/status 2>/dev/null; }
fds() { ls /proc/$SRV/fd 2>/dev/null | wc -l; }
call() { curl -s -m 8 -o /dev/null -X POST "$URL" "${H[@]}" -d "$1"; }

RSS0=$(rss); FD0=$(fds)
printf 'start   RSS=%s kB  FD=%s\n' "$RSS0" "$FD0"

END=$(( $(date +%s) + DUR ))
n=0
while [ "$(date +%s)" -lt "$END" ]; do
    n=$((n + 1))
    case $((n % 6)) in
        # A read that returns rows, and one that returns many.
        0) call '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT * FROM orders LIMIT 50"}}}' ;;
        # A refusal: the validator rejects this before the database sees it.
        1) call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"sql":"DROP TABLE orders"}}}' ;;
        # An error from PostgreSQL itself, which travels a different path than a refusal.
        2) call '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT * FROM no_such_table"}}}' ;;
        # A request the client abandons mid-flight. This is the one that leaks connections if
        # anything does: the server is left holding a transaction nobody is waiting for.
        3) curl -s -m 0.05 -o /dev/null -X POST "$URL" "${H[@]}" \
             -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT pg_sleep(2)"}}}' 2>/dev/null ;;
        4) call '{"jsonrpc":"2.0","id":5,"method":"tools/list"}' ;;
        # No credentials. Rejected, but the rejection still allocates and still opens a socket.
        5) curl -s -m 8 -o /dev/null -X POST "$URL" -H 'content-type: application/json' \
             -H 'accept: application/json, text/event-stream' \
             -d '{"jsonrpc":"2.0","id":6,"method":"tools/list"}' ;;
    esac
    if [ $((n % 2000)) -eq 0 ]; then
        printf '  %6d requests  RSS=%s kB  FD=%s\n' "$n" "$(rss)" "$(fds)"
    fi
done

RSS1=$(rss); FD1=$(fds)
printf 'end     RSS=%s kB  FD=%s  requests=%d\n' "$RSS1" "$FD1" "$n"

# Descriptors are the assertion. Memory is reported because its SHAPE is informative, but a
# threshold on it would fire on allocator behaviour and get switched off, which costs more than it
# catches. A descriptor that is open at the end and was not open at the start is a leak, full stop.
if [ "$FD1" -gt "$FD0" ]; then
    printf 'FAIL: %d file descriptors at the end, %d at the start\n' "$FD1" "$FD0"
    exit 1
fi
printf 'PASS: file descriptors unchanged (%s), memory %s kB -> %s kB\n' "$FD1" "$RSS0" "$RSS1"
