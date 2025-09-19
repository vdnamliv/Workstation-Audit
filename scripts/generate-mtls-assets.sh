#!/bin/bash
set -e

# ==============================
# 1. Create a private CA
# ==============================
echo "[*] Creating private CA..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -out ca.pem -days 3650 \
  -subj "/C=VN/ST=Hanoi/L=Hanoi/O=VT Audit/CN=VT Audit Root CA"

# ==============================
# 2. Issue a certificate for the mTLS gateway
# ==============================
echo "[*] Creating server key and CSR..."
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

echo "[*] Signing server certificate with CA..."
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 825 -extensions v3_req -extfile server.cnf

# ==============================
# 3. Copy certs to env/conf/mtls/issuer
# ==============================
echo "[*] Copying certs to env/conf/mtls/issuer..."
mkdir -p env/conf/mtls/issuer
cp ca.pem ca.key server.pem server.key env/conf/mtls/issuer/

# ==============================
# 4. Restart services
# ==============================
echo "[*] Restarting Docker services..."
cd env
docker compose restart mtls-gateway api-agent

echo "[*] Done!"
