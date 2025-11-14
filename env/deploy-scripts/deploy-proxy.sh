#!/bin/bash
# Deployment script for Reverse Proxy VMs (.45 and .46)
# Run this script on each proxy VM after copying project files

set -euo pipefail

echo "=========================================="
echo "VT-Audit Reverse Proxy Deployment Script"
echo "=========================================="
echo ""

# Configuration
PROJECT_DIR="/opt/vt-audit"
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.proxy.yml"
ENV_FILE="${PROJECT_DIR}/.env"
NFS_MOUNT="/mnt/nginx_certs"
IS_PRIMARY=false

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root" 
   exit 1
fi

# Detect if this is primary or secondary based on IP
CURRENT_IP=$(ip addr | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | grep '10.211.130' | head -1)
if [[ "$CURRENT_IP" == "10.211.130.45" ]]; then
    IS_PRIMARY=true
    echo "Detected as PRIMARY proxy VM (.45)"
elif [[ "$CURRENT_IP" == "10.211.130.46" ]]; then
    echo "Detected as SECONDARY proxy VM (.46)"
else
    echo "WARNING: Could not detect VM role. Assuming SECONDARY."
fi

echo ""
echo "[1/10] Checking prerequisites..."

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

# Check Keepalived
if ! command -v keepalived &> /dev/null; then
    echo "WARNING: Keepalived is not installed"
    echo "Install it: dnf install -y keepalived"
fi

echo ""
echo "[2/10] Checking backend connectivity..."

# Check if we can reach admin backends
if timeout 5 bash -c "cat < /dev/null > /dev/tcp/10.211.130.49/8080" 2>/dev/null; then
    echo "✓ Admin backend 10.211.130.49:8080 is reachable"
else
    echo "WARNING: Cannot reach admin backend 10.211.130.49:8080"
fi

# Check if we can reach agent backends
if timeout 5 bash -c "cat < /dev/null > /dev/tcp/10.211.130.47/9000" 2>/dev/null; then
    echo "✓ Agent backend 10.211.130.47:9000 is reachable"
else
    echo "WARNING: Cannot reach agent backend 10.211.130.47:9000"
fi

echo ""
echo "[3/10] Checking NFS mount for nginx certificates..."

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
    echo "1. On NFS server (can use same as stepca, e.g., VM .47):"
    echo "   mkdir -p /shared/nginx_certs"
    echo "   echo '/shared/nginx_certs 10.211.130.45(rw,sync,no_root_squash) 10.211.130.46(rw,sync,no_root_squash)' >> /etc/exports"
    echo "   exportfs -a"
    echo ""
    echo "2. On this proxy VM:"
    echo "   dnf install -y nfs-utils"
    echo "   mount <NFS_SERVER_IP>:/shared/nginx_certs $NFS_MOUNT"
    echo "   echo '<NFS_SERVER_IP>:/shared/nginx_certs $NFS_MOUNT nfs defaults 0 0' >> /etc/fstab"
    echo ""
    exit 1
fi

echo ""
echo "[4/10] Checking project files..."

if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "ERROR: Compose file not found: $COMPOSE_FILE"
    exit 1
fi
echo "✓ Compose file found: $COMPOSE_FILE"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: .env file not found: $ENV_FILE"
    echo "Please copy .env.proxy to $ENV_FILE and configure it"
    exit 1
fi
echo "✓ Environment file found: $ENV_FILE"

# Check nginx config files
if [[ ! -f "$PROJECT_DIR/conf/nginx/nginx.conf" ]]; then
    echo "ERROR: Nginx config not found: $PROJECT_DIR/conf/nginx/nginx.conf"
    exit 1
fi
echo "✓ Nginx configuration files found"

echo ""
echo "[5/10] Validating Docker Compose configuration..."
cd "$PROJECT_DIR"
if docker compose -f docker-compose.proxy.yml config > /dev/null 2>&1; then
    echo "✓ Docker Compose configuration is valid"
else
    echo "ERROR: Docker Compose configuration is invalid"
    docker compose -f docker-compose.proxy.yml config
    exit 1
fi

echo ""
echo "[6/10] Checking firewall rules..."
if systemctl is-active --quiet firewalld; then
    echo "Firewalld is active. Checking rules..."
    # Port 443, 8443, 80 should be open
    if ! firewall-cmd --list-ports | grep -q "443/tcp"; then
        echo "WARNING: Port 443/tcp may not be open"
        echo "Run: firewall-cmd --permanent --add-port=443/tcp"
    fi
    if ! firewall-cmd --list-ports | grep -q "8443/tcp"; then
        echo "WARNING: Port 8443/tcp may not be open"
        echo "Run: firewall-cmd --permanent --add-port=8443/tcp"
    fi
    # Check VRRP protocol for Keepalived
    if ! firewall-cmd --list-rich-rules | grep -q "protocol value=\"vrrp\""; then
        echo "WARNING: VRRP protocol not allowed (needed for Keepalived)"
        echo "Run: firewall-cmd --permanent --add-rich-rule='rule protocol value=\"vrrp\" accept'"
        echo "Run: firewall-cmd --reload"
    fi
fi

echo ""
echo "[7/10] Checking Keepalived configuration..."
if [[ -f "/etc/keepalived/keepalived.conf" ]]; then
    echo "✓ Keepalived configuration exists"
    # Check if VIP is configured
    if grep -q "10.221.130.44" /etc/keepalived/keepalived.conf; then
        echo "✓ VIP 10.221.130.44 is configured"
    else
        echo "WARNING: VIP 10.221.130.44 not found in keepalived.conf"
    fi
else
    echo "WARNING: Keepalived not configured at /etc/keepalived/keepalived.conf"
    echo "Please configure Keepalived according to RUNBOOK before proceeding"
fi

echo ""
echo "[8/10] Generating/checking nginx certificates..."

# Only generate certs on primary VM if they don't exist
if [[ "$IS_PRIMARY" == true ]]; then
    if [[ ! -f "$NFS_MOUNT/server.crt" ]]; then
        echo "Primary VM: Generating nginx certificates..."
        docker compose -f docker-compose.proxy.yml run --rm nginx-certs
        echo "✓ Certificates generated in $NFS_MOUNT"
    else
        echo "✓ Certificates already exist in $NFS_MOUNT"
    fi
else
    if [[ ! -f "$NFS_MOUNT/server.crt" ]]; then
        echo "WARNING: Certificates do not exist in $NFS_MOUNT"
        echo "Please run deployment on PRIMARY VM (.45) first to generate certificates"
        exit 1
    else
        echo "✓ Certificates exist in $NFS_MOUNT (shared from primary)"
    fi
fi

echo ""
echo "[9/10] Pulling Docker images..."
docker compose -f docker-compose.proxy.yml pull || true

echo ""
echo "[10/10] Starting services..."
docker compose -f docker-compose.proxy.yml up -d

echo ""
echo "=========================================="
echo "Deployment Status"
echo "=========================================="
docker compose -f docker-compose.proxy.yml ps

echo ""
echo "=========================================="
echo "Deployment completed!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Check logs: docker compose -f docker-compose.proxy.yml logs -f"
echo "2. Verify nginx config: docker exec vt-nginx nginx -t"
echo "3. Check Keepalived status: systemctl status keepalived"
echo "4. Check VIP assignment: ip a | grep 10.221.130.44"
echo "5. Repeat this deployment on the other proxy VM (.45 or .46)"
echo ""
if [[ "$IS_PRIMARY" == true ]]; then
    echo "IMPORTANT: This is the PRIMARY proxy VM"
    echo "  - VIP 10.221.130.44 should be assigned to this VM"
    echo "  - Check: ip a | grep 10.221.130.44"
else
    echo "IMPORTANT: This is the SECONDARY proxy VM"
    echo "  - VIP should NOT be on this VM (unless primary failed)"
    echo "  - Check: ip a | grep 10.221.130.44 (should be empty)"
fi
echo ""
echo "Test the system:"
echo "  curl -k https://10.221.130.44/health"
echo "  curl -k https://10.221.130.44/auth/"
echo ""
