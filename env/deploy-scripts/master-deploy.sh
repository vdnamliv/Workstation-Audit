#!/bin/bash
# VT-Audit Deployment Master Script
# This script helps coordinate deployment across all VMs
# Run from your local machine or jump host

set -euo pipefail

# VM IP Configuration
DB_PRIMARY="10.221.130.52"
DB_SECONDARY="10.221.130.53"
ADMIN_VM1="10.211.130.49"
ADMIN_VM2="10.211.130.50"
AGENT_VM1="10.211.130.47"
AGENT_VM2="10.211.130.48"
PROXY_VM1="10.211.130.45"
PROXY_VM2="10.211.130.46"

PROXY_VIP="10.221.130.44"
DB_VIP="10.221.130.51"

SSH_USER="root"
PROJECT_DIR="/opt/vt-audit"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "VT-Audit HA Deployment Master Control"
echo "=========================================="
echo ""

# Function to check VM connectivity
check_vm() {
    local vm_ip=$1
    local vm_name=$2
    if timeout 3 bash -c "cat < /dev/null > /dev/tcp/${vm_ip}/22" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} ${vm_name} (${vm_ip}) is reachable"
        return 0
    else
        echo -e "${RED}✗${NC} ${vm_name} (${vm_ip}) is NOT reachable"
        return 1
    fi
}

# Function to check VIP assignment
check_vip() {
    local vm_ip=$1
    local vip=$2
    local vm_name=$3
    if ssh ${SSH_USER}@${vm_ip} "ip a | grep -q ${vip}" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} VIP ${vip} is on ${vm_name}"
        return 0
    else
        echo -e "${YELLOW}○${NC} VIP ${vip} is NOT on ${vm_name}"
        return 1
    fi
}

# Main menu
show_menu() {
    echo ""
    echo "=========================================="
    echo "Deployment Menu"
    echo "=========================================="
    echo "1. Check VM connectivity (all 8 VMs)"
    echo "2. Check VIP assignments"
    echo "3. Check Docker status (all VMs)"
    echo "4. Deploy Admin VMs (.49, .50)"
    echo "5. Deploy Agent VMs (.47, .48)"
    echo "6. Deploy Proxy VMs (.45, .46)"
    echo "7. Check deployment status (all VMs)"
    echo "8. Verify system (end-to-end test)"
    echo "9. Show logs (select VM)"
    echo "10. Restart services (select VM)"
    echo "0. Exit"
    echo "=========================================="
    read -p "Select option: " choice
    echo ""
    return $choice
}

# Option 1: Check connectivity
check_connectivity() {
    echo "Checking VM connectivity..."
    echo ""
    check_vm $DB_PRIMARY "Database Primary"
    check_vm $DB_SECONDARY "Database Secondary"
    check_vm $ADMIN_VM1 "Admin VM1"
    check_vm $ADMIN_VM2 "Admin VM2"
    check_vm $AGENT_VM1 "Agent VM1"
    check_vm $AGENT_VM2 "Agent VM2"
    check_vm $PROXY_VM1 "Proxy VM1"
    check_vm $PROXY_VM2 "Proxy VM2"
}

# Option 2: Check VIPs
check_vips() {
    echo "Checking VIP assignments..."
    echo ""
    echo "Proxy VIP (${PROXY_VIP}):"
    check_vip $PROXY_VM1 $PROXY_VIP "Proxy VM1 (.45)" || check_vip $PROXY_VM2 $PROXY_VIP "Proxy VM2 (.46)"
    echo ""
    echo "Database VIP (${DB_VIP}):"
    check_vip $DB_PRIMARY $DB_VIP "DB Primary (.52)" || check_vip $DB_SECONDARY $DB_VIP "DB Secondary (.53)"
}

# Option 3: Check Docker
check_docker() {
    echo "Checking Docker status on all VMs..."
    echo ""
    for vm in $ADMIN_VM1 $ADMIN_VM2 $AGENT_VM1 $AGENT_VM2 $PROXY_VM1 $PROXY_VM2; do
        if ssh ${SSH_USER}@${vm} "docker --version && docker compose version" &>/dev/null; then
            echo -e "${GREEN}✓${NC} Docker is installed on ${vm}"
        else
            echo -e "${RED}✗${NC} Docker is NOT properly installed on ${vm}"
        fi
    done
}

# Option 7: Check deployment status
check_status() {
    echo "Checking deployment status..."
    echo ""
    
    echo "Admin VMs:"
    for vm in $ADMIN_VM1 $ADMIN_VM2; do
        echo "  ${vm}:"
        ssh ${SSH_USER}@${vm} "cd ${PROJECT_DIR} && docker compose -f docker-compose.admin.yml ps" 2>/dev/null || echo "    Not deployed"
    done
    
    echo ""
    echo "Agent VMs:"
    for vm in $AGENT_VM1 $AGENT_VM2; do
        echo "  ${vm}:"
        ssh ${SSH_USER}@${vm} "cd ${PROJECT_DIR} && docker compose -f docker-compose.agent.yml ps" 2>/dev/null || echo "    Not deployed"
    done
    
    echo ""
    echo "Proxy VMs:"
    for vm in $PROXY_VM1 $PROXY_VM2; do
        echo "  ${vm}:"
        ssh ${SSH_USER}@${vm} "cd ${PROJECT_DIR} && docker compose -f docker-compose.proxy.yml ps" 2>/dev/null || echo "    Not deployed"
    done
}

# Option 8: Verify system
verify_system() {
    echo "Running end-to-end verification..."
    echo ""
    
    echo "Testing Proxy VIP (${PROXY_VIP})..."
    if curl -k -s -o /dev/null -w "%{http_code}" https://${PROXY_VIP}/ | grep -q "200\|301\|302"; then
        echo -e "${GREEN}✓${NC} Proxy VIP is responding"
    else
        echo -e "${RED}✗${NC} Proxy VIP is not responding"
    fi
    
    echo ""
    echo "Testing Keycloak..."
    if curl -k -s https://${PROXY_VIP}/auth/realms/vt-audit | grep -q "vt-audit"; then
        echo -e "${GREEN}✓${NC} Keycloak is accessible"
    else
        echo -e "${RED}✗${NC} Keycloak is not accessible"
    fi
    
    echo ""
    echo "Testing Database VIP (${DB_VIP})..."
    if timeout 3 bash -c "cat < /dev/null > /dev/tcp/${DB_VIP}/5432" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Database VIP is reachable"
    else
        echo -e "${RED}✗${NC} Database VIP is not reachable"
    fi
}

# Main loop
while true; do
    show_menu
    choice=$?
    
    case $choice in
        1)
            check_connectivity
            ;;
        2)
            check_vips
            ;;
        3)
            check_docker
            ;;
        4)
            echo "Deploy Admin VMs - Not implemented in this script"
            echo "Please run deploy-admin.sh on each VM manually"
            ;;
        5)
            echo "Deploy Agent VMs - Not implemented in this script"
            echo "Please run deploy-agent.sh on each VM manually"
            ;;
        6)
            echo "Deploy Proxy VMs - Not implemented in this script"
            echo "Please run deploy-proxy.sh on each VM manually"
            ;;
        7)
            check_status
            ;;
        8)
            verify_system
            ;;
        9)
            echo "Show logs - Not implemented"
            echo "Use: ssh root@<VM_IP> 'cd ${PROJECT_DIR} && docker compose logs -f'"
            ;;
        10)
            echo "Restart services - Not implemented"
            echo "Use: ssh root@<VM_IP> 'cd ${PROJECT_DIR} && docker compose restart'"
            ;;
        0)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option"
            ;;
    esac
    
    read -p "Press Enter to continue..."
done
