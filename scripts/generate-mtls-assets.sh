#!/usr/bin/env bash
set -euo pipefail

OUT_DIR=${1:-env/conf/mtls/issuer}
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

pushd "$WORK_DIR" > /dev/null

# 1. Create private CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -out ca.pem -days 3650   -subj "/C=VN/ST=Hanoi/L=Hanoi/O=VT Audit/CN=VT Audit Root CA"

# 2. Issue certificate for mTLS gateway
openssl genrsa -out server.key 2048
cat > server.cnf <<'EOF'
[req]
distinguished_name=req_distinguished_name
req_extensions=v3_req
prompt=no
[req_distinguished_name]
C=VN
ST=Hanoi
L=Hanoi
O=VT Audit
CN=agent-gateway.local
[v3_req]
subjectAltName=DNS:agent-gateway.local,DNS:dashboard.local,IP:127.0.0.1
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
openssl req -new -key server.key -out server.csr -config server.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial   -out server.pem -days 825 -extensions v3_req -extfile server.cnf

mkdir -p "$OUT_DIR"
cp ca.pem ca.key server.pem server.key "$OUT_DIR"/

popd > /dev/null

cd env
docker compose restart mtls-gateway api-agent
