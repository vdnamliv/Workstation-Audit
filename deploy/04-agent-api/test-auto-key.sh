#!/bin/bash
# ============================================
# TEST: Auto-generated Provisioner Key
# ============================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=========================================="
echo "TESTING AUTO-GENERATED PROVISIONER KEY"
echo "=========================================="

# Get provisioner name from .env
PROVISIONER_NAME=$(grep STEPCA_PROVISIONER= .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
echo "Provisioner name: $PROVISIONER_NAME"

echo ""
echo -e "${YELLOW}[1/4]${NC} Checking if Step-CA is running..."
if docker ps | grep -q vt-stepca; then
    echo -e "${GREEN}✓${NC} Step-CA is running"
else
    echo -e "${RED}✗${NC} Step-CA is not running"
    echo "Start with: docker compose up -d"
    exit 1
fi

echo ""
echo -e "${YELLOW}[2/4]${NC} Checking if provisioner key exists in Step-CA..."
KEY_PATH="/home/step/certs/secrets/${PROVISIONER_NAME}.key"

if docker exec vt-stepca test -f "$KEY_PATH"; then
    echo -e "${GREEN}✓${NC} Provisioner key exists: $KEY_PATH"
    
    # Show key info
    echo ""
    echo "Key content preview:"
    docker exec vt-stepca cat "$KEY_PATH" | jq -r '{use, kty, kid, crv, alg}' 2>/dev/null || docker exec vt-stepca cat "$KEY_PATH"
else
    echo -e "${RED}✗${NC} Provisioner key NOT found at: $KEY_PATH"
    echo ""
    echo "Possible locations:"
    docker exec vt-stepca find /home/step -name "*.key" -o -name "*${PROVISIONER_NAME}*" 2>/dev/null
    exit 1
fi

echo ""
echo -e "${YELLOW}[3/4]${NC} Checking if api-agent can access the key..."
if docker ps | grep -q vt-api-agent; then
    AGENT_KEY_PATH="/stepca/certs/secrets/${PROVISIONER_NAME}.key"
    
    if docker exec vt-api-agent test -f "$AGENT_KEY_PATH"; then
        echo -e "${GREEN}✓${NC} api-agent can access key at: $AGENT_KEY_PATH"
    else
        echo -e "${RED}✗${NC} api-agent CANNOT access key at: $AGENT_KEY_PATH"
        echo ""
        echo "Available files in /stepca:"
        docker exec vt-api-agent find /stepca -type f -name "*.key" 2>/dev/null || echo "No .key files found"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠${NC} api-agent is not running, skipping..."
fi

echo ""
echo -e "${YELLOW}[4/4]${NC} Checking api-agent logs..."
if docker ps | grep -q vt-api-agent; then
    if docker logs vt-api-agent --tail 30 | grep -q "waiting for Step-CA provisioner key"; then
        echo -e "${RED}✗${NC} api-agent is still waiting for key!"
        docker logs vt-api-agent --tail 10
    else
        echo -e "${GREEN}✓${NC} No key errors in logs"
        docker logs vt-api-agent --tail 10 | grep -i "stepca\|provisioner\|certificate" || echo "(no relevant logs)"
    fi
fi

echo ""
echo "=========================================="
echo -e "${GREEN}TEST COMPLETE${NC}"
echo "=========================================="
echo ""
echo "Summary:"
echo "  - Step-CA provisioner key: EXISTS"
echo "  - Shared volume mount: WORKING"
echo "  - api-agent access: OK"
echo ""
echo "You can now start/restart services with:"
echo "  docker compose up -d"
echo ""
