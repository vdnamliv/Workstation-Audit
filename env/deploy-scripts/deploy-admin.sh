#!/bin/bash
# Deployment script for Admin API VMs (.49 and .50)
# Run this script on each admin VM after copying project files

set -euo pipefail

echo "=========================================="
echo "VT-Audit Admin API Deployment Script"
echo "=========================================="
echo ""

# Configuration
PROJECT_DIR="/opt/vt-audit"
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.admin.yml"
ENV_FILE="${PROJECT_DIR}/.env"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root" 
   exit 1
fi

echo "[1/7] Checking prerequisites..."

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed"
    exit 1
fi
echo "✓ Docker installed: $(docker --version)"

# Check Docker Compose plugin
if ! docker compose version &> /dev/null; then
    echo "ERROR: Docker Compose plugin is not installed"
    exit 1
fi
echo "✓ Docker Compose installed: $(docker compose version)"

echo ""
echo "[2/7] Checking database connectivity (VIP: 10.221.130.51)..."

# Check if we can reach the database VIP
if timeout 5 bash -c "cat < /dev/null > /dev/tcp/10.221.130.51/5432" 2>/dev/null; then
    echo "✓ Database VIP 10.221.130.51:5432 is reachable"
else
    echo "WARNING: Cannot reach database VIP 10.221.130.51:5432"
    echo "Make sure PostgreSQL HA is configured and running"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""
echo "[3/7] Checking project files..."

if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "ERROR: Compose file not found: $COMPOSE_FILE"
    exit 1
fi
echo "✓ Compose file found: $COMPOSE_FILE"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: .env file not found: $ENV_FILE"
    echo "Please copy .env.admin to $ENV_FILE and configure it"
    exit 1
fi
echo "✓ Environment file found: $ENV_FILE"

echo ""
echo "[4/7] Validating Docker Compose configuration..."
cd "$PROJECT_DIR"
if docker compose -f docker-compose.admin.yml config > /dev/null 2>&1; then
    echo "✓ Docker Compose configuration is valid"
else
    echo "ERROR: Docker Compose configuration is invalid"
    docker compose -f docker-compose.admin.yml config
    exit 1
fi

echo ""
echo "[5/7] Checking firewall rules..."
if systemctl is-active --quiet firewalld; then
    echo "Firewalld is active. Checking rules..."
    # Port 8080 (Keycloak) and 8081 (api-backend) should be open to proxy VMs
    if ! firewall-cmd --list-rich-rules | grep -q "port=\"8080\""; then
        echo "WARNING: Port 8080 may not be open to proxy VMs"
        echo "Run: firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"10.211.130.45/32\" port protocol=\"tcp\" port=\"8080\" accept'"
        echo "Run: firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"10.211.130.46/32\" port protocol=\"tcp\" port=\"8080\" accept'"
    fi
    if ! firewall-cmd --list-rich-rules | grep -q "port=\"8081\""; then
        echo "WARNING: Port 8081 may not be open to proxy VMs"
        echo "Run: firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"10.211.130.45/32\" port protocol=\"tcp\" port=\"8081\" accept'"
        echo "Run: firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"10.211.130.46/32\" port protocol=\"tcp\" port=\"8081\" accept'"
    fi
fi

echo ""
echo "[6/7] Pulling Docker images..."
docker compose -f docker-compose.admin.yml pull || true

echo ""
echo "[7/7] Starting services..."
docker compose -f docker-compose.admin.yml up -d

echo ""
echo "=========================================="
echo "Deployment Status"
echo "=========================================="
docker compose -f docker-compose.admin.yml ps

echo ""
echo "=========================================="
echo "Deployment completed!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Check logs: docker compose -f docker-compose.admin.yml logs -f"
echo "2. Verify Keycloak is accessible: curl http://localhost:8080/health"
echo "3. Verify API backend is running: docker compose -f docker-compose.admin.yml ps"
echo "4. Repeat this deployment on the other admin VM (.49 or .50)"
echo ""
