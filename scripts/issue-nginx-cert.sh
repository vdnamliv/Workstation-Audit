#!/bin/bash
set -euo pipefail

# Issue or renew the gateway TLS certificate via Step-CA.
# Usage: scripts/issue-nginx-cert.sh [common_name] [crt_path] [key_path]

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ENV_FILE="$REPO_ROOT/env/.env"
COMMON_NAME=${1:-gateway.local}
CRT_PATH=${2:-/out/nginx/server.crt}
KEY_PATH=${3:-/out/nginx/skerver.ey}

if [[ -f "$ENV_FILE" ]]; then
  if [[ -z "${STEPCA_PROVISIONER:-}" ]]; then
    STEPCA_PROVISIONER=$(grep -E '^STEPCA_PROVISIONER=' "$ENV_FILE" | tail -n1 | cut -d'=' -f2-)
  fi
  if [[ -z "${STEPCA_URL:-}" ]]; then
    STEPCA_URL=$(grep -E '^STEPCA_URL=' "$ENV_FILE" | tail -n1 | cut -d'=' -f2-)
  fi
fi

: "${STEPCA_PROVISIONER:?STEPCA_PROVISIONER missing (check env/.env)}"
CA_URL=${STEPCA_URL:-https://stepca:9000}

compose_file="$REPO_ROOT/env/docker-compose.yml"
container_id=$(docker compose -f "$compose_file" ps -q stepca)
if [[ -z "$container_id" ]]; then
  echo "Step-CA container not running" >&2
  exit 1
fi

set +e
output=$(docker exec -i "$container_id" \
  sh -c "umask 022 && step ca certificate '$COMMON_NAME' '$CRT_PATH' '$KEY_PATH' --provisioner '$STEPCA_PROVISIONER' --password-file /home/step/secrets/password --ca-url '$CA_URL' --root /home/step/certs/root_ca.crt" 2>&1)
status=$?
set -e

if [[ $status -ne 0 ]]; then
  echo "$output" >&2
  if [[ "$output" == *"open /dev/tty"* ]]; then
    echo "Hint: run this script from a terminal (or prepend 'winpty' on Git Bash for Windows)." >&2
  fi
  exit $status
fi

echo "$output"
printf '\n[+] Certificate written to %s and %s\n' "$CRT_PATH" "$KEY_PATH"