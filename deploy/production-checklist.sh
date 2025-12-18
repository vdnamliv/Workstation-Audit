#!/bin/bash
# ============================================
# PRODUCTION DEPLOYMENT CHECKLIST
# ============================================

echo "=========================================="
echo "VT-AUDIT PRODUCTION DEPLOYMENT CHECKLIST"
echo "=========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_port() {
    local host=$1
    local port=$2
    local service=$3
    
    if timeout 2 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} $service ($host:$port) - REACHABLE"
        return 0
    else
        echo -e "${RED}✗${NC} $service ($host:$port) - NOT REACHABLE"
        return 1
    fi
}

echo ""
echo "=========================================="
echo "1. DATABASE CONNECTIVITY (VIP: 10.211.130.51)"
echo "=========================================="
check_port 10.211.130.51 5432 "PostgreSQL VIP"

echo ""
echo "=========================================="
echo "2. GATEWAY CONNECTIVITY (VIP: 10.211.130.44)"
echo "=========================================="
check_port 10.211.130.44 9443 "HAProxy Agent Port"
check_port 10.211.130.44 9444 "HAProxy Admin Port (if configured)"

echo ""
echo "=========================================="
echo "3. KEYCLOAK CONNECTIVITY (Server .49)"
echo "=========================================="
check_port 10.211.130.49 8080 "Keycloak HTTP"

echo ""
echo "=========================================="
echo "4. AGENT API CONNECTIVITY (Server .47)"
echo "=========================================="
check_port 10.211.130.47 8080 "Agent API"
check_port 10.211.130.47 8082 "Enrollment Gateway"
check_port 10.211.130.47 9000 "Step-CA"

echo ""
echo "=========================================="
echo "5. ADMIN API CONNECTIVITY (Server .49)"
echo "=========================================="
check_port 10.211.130.49 8081 "Admin API Backend"

echo ""
echo "=========================================="
echo "6. DNS RESOLUTION TEST"
echo "=========================================="
ping -c 1 10.211.130.51 > /dev/null 2>&1 && echo -e "${GREEN}✓${NC} DB VIP pingable" || echo -e "${RED}✗${NC} DB VIP not pingable"
ping -c 1 10.211.130.44 > /dev/null 2>&1 && echo -e "${GREEN}✓${NC} Gateway VIP pingable" || echo -e "${RED}✗${NC} Gateway VIP not pingable"

echo ""
echo "=========================================="
echo "7. DOCKER CONTAINERS STATUS"
echo "=========================================="
echo -e "${YELLOW}Server .47 (Agent API):${NC}"
echo "Run on server .47: docker compose ps"
echo ""
echo -e "${YELLOW}Server .49 (Admin API):${NC}"
echo "Run on server .49: docker compose ps"

echo ""
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo "Next steps:"
echo "1. Copy updated .env files to respective servers"
echo "2. Run restart-production.sh on each server"
echo "3. Check logs for any connectivity errors"
echo "4. Deploy Nginx gateway (servers .45 & .46)"
echo ""
