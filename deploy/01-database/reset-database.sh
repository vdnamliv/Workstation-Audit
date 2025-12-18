#!/bin/bash
# ============================================
# RESET DATABASE SCRIPT
# ============================================
# Script này XÓA TOÀN BỘ data và tạo lại database từ đầu
# ⚠️ WARNING: Sẽ mất tất cả dữ liệu!
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}===========================================${NC}"
echo -e "${RED}  RESET DATABASE - WARNING!${NC}"
echo -e "${RED}===========================================${NC}"
echo ""
echo -e "${RED}[WARNING]${NC} This will DELETE ALL DATA in the database!"
echo -e "${RED}[WARNING]${NC} All tables, users, and data will be lost!"
echo ""
read -p "Are you SURE you want to continue? (type 'YES' to confirm): " -r
echo ""
if [[ ! $REPLY == "YES" ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo -e "${YELLOW}[INFO]${NC} Stopping container..."
docker compose down

echo -e "${YELLOW}[INFO]${NC} Removing database volume..."
docker volume rm 01-database_db_data 2>/dev/null || echo "Volume not found (OK)"

echo -e "${YELLOW}[INFO]${NC} Starting database with fresh data..."
docker compose up -d

echo ""
echo -e "${GREEN}[INFO]${NC} Waiting for database to initialize..."
sleep 5

# Wait for database to be ready
MAX_WAIT=60
WAIT_COUNT=0
while ! docker exec vt-postgres pg_isready -U ${POSTGRES_USER:-postgres} > /dev/null 2>&1; do
    if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
        echo -e "${RED}[ERROR]${NC} Database did not become ready in time!"
        exit 1
    fi
    echo -n "."
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

echo ""
echo -e "${GREEN}[SUCCESS]${NC} Database reset complete!"
echo ""
echo -e "${YELLOW}[INFO]${NC} Verify initialization:"
echo "  docker exec vt-postgres psql -U postgres -c '\l'"
echo "  docker exec vt-postgres psql -U postgres -c '\du'"
echo ""

