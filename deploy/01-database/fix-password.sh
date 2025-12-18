#!/bin/bash
# ============================================
# FIX DATABASE PASSWORD SCRIPT
# ============================================
# Script này dùng để fix password khi database đã tồn tại
# và init script không chạy (Skipping initialization)
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}===========================================${NC}"
echo -e "${YELLOW}  FIX DATABASE PASSWORD${NC}"
echo -e "${YELLOW}===========================================${NC}"
echo ""

# Load .env file
if [ ! -f .env ]; then
    echo -e "${RED}[ERROR]${NC} File .env not found!"
    echo "Please copy .env.example to .env first:"
    echo "  cp .env.example .env"
    exit 1
fi

source .env

# Check if container is running
CONTAINER_NAME="vt-postgres"
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${RED}[ERROR]${NC} Container ${CONTAINER_NAME} is not running!"
    echo "Please start it first:"
    echo "  docker compose up -d"
    exit 1
fi

echo -e "${GREEN}[INFO]${NC} Container ${CONTAINER_NAME} is running"
echo ""

# Password từ 01-init.sql (phải khớp!)
# Nếu production, cần đổi password mạnh hơn trong cả 2 files
VT_APP_PASSWORD="vtapp123"
KEYCLOAK_PASSWORD="keycloak123"
STEPCA_PASSWORD="stepca123"

echo -e "${YELLOW}[WARNING]${NC} This will update passwords for:"
echo "  - vt_app: ${VT_APP_PASSWORD}"
echo "  - keycloak: ${KEYCLOAK_PASSWORD}"
echo "  - stepca: ${STEPCA_PASSWORD}"
echo ""
read -p "Continue? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo -e "${GREEN}[INFO]${NC} Updating passwords..."

# Update vt_app password
echo -e "${GREEN}[INFO]${NC} Updating vt_app password..."
docker exec -i ${CONTAINER_NAME} psql -U ${POSTGRES_USER:-postgres} -d postgres <<EOF
-- Update vt_app password
ALTER USER vt_app WITH PASSWORD '${VT_APP_PASSWORD}';

-- Verify user exists, create if not
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = 'vt_app') THEN
        CREATE USER vt_app WITH PASSWORD '${VT_APP_PASSWORD}';
    END IF;
END
\$\$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE vt_db TO vt_app;
\c vt_db
GRANT ALL ON SCHEMA public TO vt_app;
GRANT ALL ON SCHEMA audit TO vt_app;
GRANT ALL ON SCHEMA policy TO vt_app;
EOF

# Update keycloak password
echo -e "${GREEN}[INFO]${NC} Updating keycloak password..."
docker exec -i ${CONTAINER_NAME} psql -U ${POSTGRES_USER:-postgres} -d postgres <<EOF
-- Update keycloak password
ALTER USER keycloak WITH PASSWORD '${KEYCLOAK_PASSWORD}';

-- Verify user exists, create if not
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = 'keycloak') THEN
        CREATE USER keycloak WITH PASSWORD '${KEYCLOAK_PASSWORD}';
    END IF;
END
\$\$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
\c keycloak
GRANT ALL ON SCHEMA public TO keycloak;
EOF

# Update stepca password
echo -e "${GREEN}[INFO]${NC} Updating stepca password..."
docker exec -i ${CONTAINER_NAME} psql -U ${POSTGRES_USER:-postgres} -d postgres <<EOF
-- Update stepca password
ALTER USER stepca WITH PASSWORD '${STEPCA_PASSWORD}';

-- Verify user exists, create if not
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = 'stepca') THEN
        CREATE USER stepca WITH PASSWORD '${STEPCA_PASSWORD}';
    END IF;
END
\$\$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE stepca TO stepca;
\c stepca
GRANT ALL ON SCHEMA public TO stepca;
EOF

echo ""
echo -e "${GREEN}[SUCCESS]${NC} Passwords updated successfully!"
echo ""
echo -e "${YELLOW}[INFO]${NC} Test connection:"
echo "  docker exec ${CONTAINER_NAME} psql -U vt_app -d vt_db -c 'SELECT 1;'"
echo ""

