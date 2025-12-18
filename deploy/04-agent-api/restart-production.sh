#!/bin/bash
# ============================================
# RESTART AGENT API - PRODUCTION
# Server: 10.211.130.47
# ============================================

set -e

echo "=========================================="
echo "RESTARTING VT-AUDIT AGENT API"
echo "=========================================="

# Stop containers
echo "[1/3] Stopping containers..."
docker compose down

# Clean up (optional - comment out if want to keep data)
# docker volume prune -f

# Start containers
echo "[2/3] Starting containers..."
docker compose up -d

# Wait for services
echo "[3/3] Waiting for services to be healthy..."
sleep 10

# Check status
echo ""
echo "=========================================="
echo "SERVICE STATUS"
echo "=========================================="
docker compose ps

echo ""
echo "=========================================="
echo "CHECKING LOGS"
echo "=========================================="
echo "step-ca logs (last 20 lines):"
docker logs vt-stepca --tail 20

echo ""
echo "agent-api logs (last 20 lines):"
docker logs vt-api-agent --tail 20

echo ""
echo "=========================================="
echo "HEALTHCHECK"
echo "=========================================="
docker compose ps | grep -E "(healthy|unhealthy|starting)"

echo ""
echo "Done! Check logs above for any errors."
echo "To monitor real-time logs:"
echo "  docker logs -f vt-api-agent"
echo "  docker logs -f vt-stepca"
