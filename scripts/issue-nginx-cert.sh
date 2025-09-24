#!/bin/bash
set -euo pipefail

# Issue or renew the gateway TLS certificate via Step-CA.
# Usage: scripts/issue-nginx-cert.sh [common_name] [crt_path] [key_path]

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ENV_FILE="$REPO_ROOT/env/.env"
COMMON_NAME=${1:-gateway.local}
CRT_PATH=${2:-/out/nginx/server.crt}
KEY_PATH=${3:-/out/nginx/server.key}

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a
  source "$ENV_FILE"
  set +a
fi

: "${STEPCA_PROVISIONER:?STEPCA_PROVISIONER missing (check env/.env)}"

compose_file="$REPO_ROOT/env/docker-compose.yml"

# Issue the certificate in the step-ca container so we can re-use the
# bootstrap password that encrypts the JWK inside ca.json.
docker compose -f "$compose_file" exec -T stepca \
  step ca certificate "$COMMON_NAME" "$CRT_PATH" "$KEY_PATH" \
  --provisioner "$STEPCA_PROVISIONER" \
  --password-file /home/step/secrets/password \
  --ca-url https://localhost:9000 \
  --root /home/step/certs/root_ca.crt

printf '\n[+] Certificate written to %s and %s\n' "$CRT_PATH" "$KEY_PATH"
