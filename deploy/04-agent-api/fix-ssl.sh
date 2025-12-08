#!/bin/bash
# Fix SSL certificates for Go build on Rocky Linux 9
# Run this on the server before building

echo "[*] Installing CA certificates..."
sudo dnf install -y ca-certificates

echo "[*] Updating CA trust..."
sudo update-ca-trust

echo "[*] Testing Go proxy connection..."
curl -I https://proxy.golang.org

echo "[SUCCESS] SSL certificates updated"
echo "Now you can run: docker compose up -d"