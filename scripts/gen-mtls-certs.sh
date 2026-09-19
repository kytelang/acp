#!/usr/bin/env bash
# Generate a CA plus server and client certs for ACP component mTLS (P1 #7).
#   ./scripts/gen-mtls-certs.sh <out-dir> [server-ip]
# Server SAN defaults to 127.0.0.1. Use the CA to sign one client cert per component.
set -euo pipefail
OUT="${1:-./mtls}"; IP="${2:-127.0.0.1}"; mkdir -p "$OUT"; cd "$OUT"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 3650 -subj "/CN=ACP CA" 2>/dev/null
gen() { # name  CN  [san]
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2" 2>/dev/null
  if [ -n "${3:-}" ]; then EXT=$(printf "subjectAltName=%s" "$3"); else EXT="subjectAltName=DNS:$2"; fi
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$1.crt" -days 825 \
    -extfile <(printf "%s" "$EXT") 2>/dev/null
  rm -f "$1.csr"
}
gen server acp-server "IP:$IP,DNS:localhost"
gen client acp-component ""
rm -f ca.srl
echo "wrote $OUT/{ca.crt,server.crt,server.key,client.crt,client.key}"
