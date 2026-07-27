#!/usr/bin/env bash
# Proof that the certificate claims are true.
#
# README says certificates are always verified and that the host name is checked. Until this existed,
# neither had an executor: CI ran PostgreSQL without TLS, and the acceptance suite never touched it.
# A cryptographic promise with no test is the one kind of claim that fails silently, because the
# failure looks exactly like success.
#
#   ./tests/tls.sh          # needs docker, openssl and a built release binary
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../target/release/postgres-mcp-hardened}"
PASS=0; FAIL=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n     %s\n' "$1" "${2:-}"; FAIL=$((FAIL+1)); }

command -v docker  >/dev/null || { echo 'docker required';  exit 1; }
command -v openssl >/dev/null || { echo 'openssl required'; exit 1; }
[ -x "$BIN" ] || { echo "binary not found: $BIN"; exit 1; }

DIR=$(mktemp -d); PGPW=tls_$RANDOM
# Asked for rather than assumed — see tests/free_port.sh for what a constant costs on a machine the
# suite does not own.
PGPORT_TLS=${PGPORT_TLS:-$("$(dirname "$0")/free_port.sh")}
cleanup(){ docker rm -f tls_pg >/dev/null 2>&1; rm -rf "$DIR"; }
trap cleanup EXIT

# A real certificate authority signing two server certificates, which is what a managed provider
# actually hands you — and it isolates the host-name check: both certs chain to the same CA, so the
# second one can fail for exactly one reason and nothing else.
openssl req -x509 -newkey rsa:2048 -days 1 -nodes -keyout "$DIR/ca.key" -out "$DIR/ca.crt" \
  -subj "/CN=postgres-mcp-hardened test CA" >/dev/null 2>&1
sign(){ # sign <basename> <dns-name>
  openssl req -newkey rsa:2048 -nodes -keyout "$DIR/$1.key" -out "$DIR/$1.csr" -subj "/CN=$2" >/dev/null 2>&1
  openssl x509 -req -in "$DIR/$1.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
    -days 1 -out "$DIR/$1.crt" -extfile <(printf 'subjectAltName=DNS:%s\n' "$2") >/dev/null 2>&1
}
sign server localhost
sign wrong  not-this-host.example

# The PostgreSQL process in the image runs as uid 999: it has to be able to traverse the directory
# and read the certificate, while the key must stay unreadable to anyone else or the server refuses
# to start. Both halves are load-bearing; getting either wrong looks like "TLS does not work".
chmod 755 "$DIR"
chmod 644 "$DIR"/*.crt
chmod 600 "$DIR"/*.key
# The ownership change needs root, which a CI runner is not — so borrow it from a container that is.
# Without this the key stays owned by the calling user, PostgreSQL cannot read it, and the whole
# suite reports "would not start with TLS", which looks like a TLS problem and is a permissions one.
docker run --rm -v "$DIR":/certs postgres:16 \
  sh -c 'chown 999:999 /certs/*.key && chmod 600 /certs/*.key' >/dev/null 2>&1 || true

start_pg(){ # start_pg <cert-basename>
  docker rm -f tls_pg >/dev/null 2>&1
  docker run -d --name tls_pg -e POSTGRES_PASSWORD=$PGPW \
    -p 127.0.0.1:$PGPORT_TLS:5432 -v "$DIR":/certs:ro postgres:16 \
    -c ssl=on -c ssl_cert_file=/certs/$1.crt -c ssl_key_file=/certs/$1.key >/dev/null || return 1
  for _ in $(seq 1 40); do docker exec tls_pg pg_isready -U postgres >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

# One query through the server, returning whatever it answered.
ask(){ # ask <DATABASE_URL> [extra env...]
  local url="$1"; shift
  local port=$((PGPORT_TLS + 300 + RANDOM % 200))
  env DATABASE_URL="$url" MCP_ADDR="127.0.0.1:$port" "$@" "$BIN" >/dev/null 2>&1 &
  local srv=$!
  sleep 2
  curl -s -m 20 -H content-type:application/json "http://127.0.0.1:$port/mcp" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT 1 AS ok"}}}'
  kill -9 "$srv" 2>/dev/null
}

printf '\n== A certificate we have no reason to trust ==\n'
start_pg server || { echo "fixture failed: PostgreSQL would not start with TLS"; exit 1; }
URL="postgres://postgres:$PGPW@localhost:$PGPORT_TLS/postgres?sslmode=require"
r=$(ask "$URL")
case "$r" in
  *"not signed by any CA we trust"*) ok "an unknown CA is refused, and the message names the fix";;
  *'"error"'*) no "refused for the wrong reason" "$r";;
  *) no "A CERTIFICATE FROM AN UNKNOWN CA WAS ACCEPTED" "$r";;
esac
case "$r" in *MCP_SSLROOTCERT*) ok "the refusal names the setting that resolves it";; *) no "no remediation in the message" "$r";; esac

printf '\n== The same certificate, once the operator supplies its CA ==\n'
r=$(ask "$URL" MCP_SSLROOTCERT="$DIR/ca.crt")
case "$r" in *'"error"'*) no "supplying the CA did not help" "$r";; *) ok "the connection succeeds with the CA bundle supplied";; esac

printf '\n== Encrypted in fact, not merely in configuration ==\n'
port=$((PGPORT_TLS + 700))
env DATABASE_URL="$URL" MCP_SSLROOTCERT="$DIR/ca.crt" MCP_ADDR="127.0.0.1:$port" "$BIN" >/dev/null 2>&1 &
SRV=$!; sleep 3
r=$(curl -s -m 25 -H content-type:application/json "http://127.0.0.1:$port/mcp" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"security_posture","arguments":{}}}')
kill -9 $SRV 2>/dev/null
case "$r" in
  *"is encrypted (measured, not assumed)"*) ok "pg_stat_ssl confirms the traffic was encrypted";;
  *) no "the posture cannot confirm encryption" "$r";;
esac

printf '\n== A certificate for somebody else’s host name ==\n'
start_pg wrong || { echo "fixture failed: PostgreSQL would not start with the second certificate"; exit 1; }
r=$(ask "$URL" MCP_SSLROOTCERT="$DIR/ca.crt")
case "$r" in
  *"does not cover this host name"*) ok "a certificate naming another host is refused, by name";;
  *'"error"'*) ok "a certificate naming another host is refused";;
  *) no "A CERTIFICATE FOR ANOTHER HOST WAS ACCEPTED" "$r";;
esac

printf '\n== %d passed, %d failed ==\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
