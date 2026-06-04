#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/generate-certs.sh [address]
#   CERT_ADDRESS=157.22.231.153 ./scripts/generate-certs.sh
#   CERT_ADDRESS=panel.example.com FORCE=1 ./scripts/generate-certs.sh
#
# Generates files expected by configs/server.yaml:
#   certs/ca.crt
#   certs/ca.key
#   certs/server.crt
#   certs/server.key

CERT_DIR="${CERT_DIR:-certs}"
CERT_ADDRESS="${1:-${CERT_ADDRESS:-localhost}}"
DAYS="${CERT_DAYS:-365}"
FORCE="${FORCE:-0}"
CA_CN="${CA_CN:-shroud-dev-ca}"
SERVER_CN="${SERVER_CN:-$CERT_ADDRESS}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 1
  fi
}

is_ip() {
  local value="$1"
  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$value" =~ : ]]
}

need_cmd openssl
need_cmd od
need_cmd tr

mkdir -p "$CERT_DIR"

CA_KEY="$CERT_DIR/ca.key"
CA_CRT="$CERT_DIR/ca.crt"
CA_SRL="$CERT_DIR/ca.srl"
SERVER_KEY="$CERT_DIR/server.key"
SERVER_CSR="$CERT_DIR/server.csr"
SERVER_CRT="$CERT_DIR/server.crt"
SERVER_EXT="$CERT_DIR/server.ext"

if [[ "$FORCE" != "1" && -f "$SERVER_CRT" && -f "$SERVER_KEY" && -f "$CA_CRT" && -f "$CA_KEY" ]]; then
  echo "Certificates already exist in '$CERT_DIR'."
  echo "Use FORCE=1 to regenerate them."
  exit 0
fi

if [[ "$FORCE" == "1" ]]; then
  rm -f "$CA_KEY" "$CA_CRT" "$CA_SRL" "$SERVER_KEY" "$SERVER_CSR" "$SERVER_CRT" "$SERVER_EXT"
fi

if [[ ! -f "$CA_KEY" || ! -f "$CA_CRT" ]]; then
  echo "Generating local CA: $CA_CRT"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CA_KEY" \
    -out "$CA_CRT" \
    -days "$DAYS" \
    -subj "/CN=$CA_CN" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

SAN="DNS:localhost,IP:127.0.0.1"

if [[ "$CERT_ADDRESS" != "localhost" && "$CERT_ADDRESS" != "127.0.0.1" ]]; then
  if is_ip "$CERT_ADDRESS"; then
    SAN="$SAN,IP:$CERT_ADDRESS"
  else
    SAN="$SAN,DNS:$CERT_ADDRESS"
  fi
fi

cat > "$SERVER_EXT" <<EXT
subjectAltName=$SAN
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT

echo "Generating server key and CSR for: $CERT_ADDRESS"
openssl req -newkey rsa:2048 -nodes \
  -keyout "$SERVER_KEY" \
  -out "$SERVER_CSR" \
  -subj "/CN=$SERVER_CN"

echo "Signing server certificate: $SERVER_CRT"
openssl x509 -req \
  -in "$SERVER_CSR" \
  -CA "$CA_CRT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -out "$SERVER_CRT" \
  -days "$DAYS" \
  -extfile "$SERVER_EXT"

chmod 600 "$CA_KEY" "$SERVER_KEY"
chmod 644 "$CA_CRT" "$SERVER_CRT"
rm -f "$SERVER_CSR" "$SERVER_EXT"

echo
echo "Done. Generated:"
echo "  $CA_CRT"
echo "  $SERVER_CRT"
echo "  $SERVER_KEY"
echo
echo "SAN: $SAN"
echo
echo "Server certificate fingerprint for client pinning:"
openssl x509 -in "$SERVER_CRT" -outform DER \
  | openssl dgst -sha256 -binary \
  | od -An -tx1 -v \
  | tr -d ' \n'
echo