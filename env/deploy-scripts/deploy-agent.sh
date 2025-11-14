#!/bin/bash
# Deployment script for Agent API VMs (.47 and .48)
# Run this script on each agent VM after copying project files

set -euo pipefail

echo "=========================================="
echo "VT-Audit Agent API Deployment Script"
echo "=========================================="
echo ""

# Configuration
PROJECT_DIR="/opt/vt-audit"
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.agent.yml"
ENV_FILE="${PROJECT_DIR}/.env"
NFS_MOUNT="/mnt/stepca"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root" 
   exit 1
fi

echo "[1/9] Checking prerequisites..."

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
echo "[2/9] Checking database connectivity (VIP: 10.221.130.51)..."

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
echo "[3/9] Checking NFS mount for StepCA data..."

if [[ ! -d "$NFS_MOUNT" ]]; then
    echo "Creating NFS mount point: $NFS_MOUNT"
    mkdir -p "$NFS_MOUNT"
fi

if mountpoint -q "$NFS_MOUNT"; then
    echo "✓ NFS is mounted at $NFS_MOUNT"
else
    echo "ERROR: $NFS_MOUNT is not mounted"
    echo ""
    echo "NFS Setup Instructions:"
    echo "----------------------"
    echo "1. On NFS server (e.g., VM .47):"
    echo "   dnf install -y nfs-utils"
    echo "   systemctl enable --now nfs-server"
    echo "   mkdir -p /shared/stepca"
    echo "   echo '/shared/stepca 10.211.130.47(rw,sync,no_root_squash) 10.211.130.48(rw,sync,no_root_squash)' >> /etc/exports"
    echo "   exportfs -a"
    echo ""
    echo "2. On this client VM:"
    echo "   dnf install -y nfs-utils"
    echo "   mount <NFS_SERVER_IP>:/shared/stepca $NFS_MOUNT"
    echo "   echo '<NFS_SERVER_IP>:/shared/stepca $NFS_MOUNT nfs defaults 0 0' >> /etc/fstab"
    echo ""
    exit 1
fi

echo ""
echo "[4/9] Checking project files..."

if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "ERROR: Compose file not found: $COMPOSE_FILE"
    exit 1
fi
echo "✓ Compose file found: $COMPOSE_FILE"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: .env file not found: $ENV_FILE"
    echo "Please copy .env.agent to $ENV_FILE and configure it"
    exit 1
fi
echo "✓ Environment file found: $ENV_FILE"

echo ""
echo "[5/9] Validating Docker Compose configuration..."
cd "$PROJECT_DIR"
if docker compose -f docker-compose.agent.yml config > /dev/null 2>&1; then
    echo "✓ Docker Compose configuration is valid"
else
    echo "ERROR: Docker Compose configuration is invalid"
    docker compose -f docker-compose.agent.yml config
    exit 1
fi

echo ""
echo "[6/9] Checking firewall rules..."
if systemctl is-active --quiet firewalld; then
    echo "Firewalld is active. Checking rules..."
    # Port 9000 (StepCA), 8080 (api-agent), 8082 (enroll-gateway) should be open to proxy VMs
    if ! firewall-cmd --list-rich-rules | grep -q "port=\"9000\""; then
        echo "WARNING: Port 9000 may not be open to proxy VMs"
        echo "Run: firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"10.211.130.45/32\" port protocol=\"tcp\" port=\"9000\" accept'"
        echo "Run: firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"10.211.130.46/32\" port protocol=\"tcp\" port=\"9000\" accept'"
    fi
fi

echo ""
echo "[7/9] Checking NFS mount permissions..."
if [[ -w "$NFS_MOUNT" ]]; then
    echo "✓ NFS mount is writable"
else
    echo "WARNING: NFS mount may not be writable"
fi

echo ""
echo "[8/9] Pulling Docker images..."
docker compose -f docker-compose.agent.yml pull || true

echo ""
echo "[9/9] Starting services..."
docker compose -f docker-compose.agent.yml up -d

echo ""
echo "=========================================="
echo "Deployment Status"
echo "=========================================="
docker compose -f docker-compose.agent.yml ps

echo ""
echo "=========================================="
echo "Deployment completed!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Check logs: docker compose -f docker-compose.agent.yml logs -f"
echo "2. Verify StepCA is healthy: docker compose -f docker-compose.agent.yml ps"
echo "3. Check StepCA certificates in NFS: ls -la $NFS_MOUNT/certs/"
echo "4. Repeat this deployment on the other agent VM (.47 or .48)"
echo ""
echo "IMPORTANT: If this is the FIRST agent VM:"
echo "  - StepCA will initialize and create certificates in $NFS_MOUNT"
echo "  - Wait for StepCA to be healthy before deploying on the second VM"
echo "  - The second VM will use the same certificates from NFS"
echo ""
