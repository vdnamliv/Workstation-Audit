#!/bin/bash
# Nginx Gateway Server Validation Script
# Servers: 10.211.130.45, 10.211.130.46
# Usage: bash validate.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

ERROR_COUNT=0
WARNING_COUNT=0

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}VT-AUDIT Nginx Gateway Validator${NC}"
echo -e "${CYAN}Servers: 10.211.130.45, 10.211.130.46${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Function to check command exists
check_command() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}[OK]${NC} $2 is installed"
        return 0
    else
        echo -e "${RED}[FAIL]${NC} $2 is not installed"
        ((ERROR_COUNT++))
        return 1
    fi
}

# Function to check file exists
check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}[OK]${NC} File exists: $1"
        return 0
    else
        echo -e "${RED}[FAIL]${NC} File missing: $1"
        ((ERROR_COUNT++))
        return 1
    fi
}

echo -e "\n${CYAN}--- System Requirements ---${NC}"

# Check OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo -e "${GREEN}[OK]${NC} OS: $NAME $VERSION"
else
    echo -e "${YELLOW}[WARN]${NC} Cannot detect OS version"
    ((WARNING_COUNT++))
fi

# Check Docker
echo -e "\n${CYAN}--- Docker Environment ---${NC}"
check_command docker "Docker"
check_command "docker compose" "Docker Compose"

# Check Docker daemon
if docker ps &> /dev/null; then
    echo -e "${GREEN}[OK]${NC} Docker daemon is running"
else
    echo -e "${RED}[FAIL]${NC} Docker daemon is not running"
    echo "  Start with: sudo systemctl start docker"
    ((ERROR_COUNT++))
fi

# Check Docker network
echo -e "\n${CYAN}--- Docker Network ---${NC}"
if docker network ls | grep -q "vt-system-net"; then
    echo -e "${GREEN}[OK]${NC} Docker network 'vt-system-net' exists"
else
    echo -e "${RED}[FAIL]${NC} Docker network 'vt-system-net' not found"
    echo "  Create with: docker network create --driver bridge --subnet 172.18.0.0/16 vt-system-net"
    ((ERROR_COUNT++))
fi

# Check configuration files
echo -e "\n${CYAN}--- Nginx Configuration Files ---${NC}"
check_file "docker-compose.yml"
check_file "conf/nginx.conf"
check_file "conf/conf.d/00-upstream.conf"
check_file "conf/conf.d/10-admin-8443.conf"
check_file "conf/conf.d/20-agent-mtls-443.conf"

# Check upstream configuration for production IPs
echo -e "\n${CYAN}--- Upstream Configuration ---${NC}"
if grep -q "10.211.130" conf/conf.d/00-upstream.conf; then
    echo -e "${GREEN}[OK]${NC} Using production IPs in upstream config"
else
    echo -e "${YELLOW}[WARN]${NC} Upstream config might be using local container names"
    echo "  Switch to production: use 00-upstream.conf.production"
    ((WARNING_COUNT++))
fi

# Check SSL certificates
echo -e "\n${CYAN}--- SSL Certificates ---${NC}"
if check_file "certs/server.crt"; then
    # Check if self-signed
    if openssl x509 -in certs/server.crt -noout -subject 2>/dev/null | grep -qi "CN=localhost\|CN=vt-audit"; then
        echo -e "${YELLOW}[WARN]${NC} Using self-signed certificate (NOT for production)"
        ((WARNING_COUNT++))
    else
        echo -e "${GREEN}[OK]${NC} SSL certificate appears properly signed"
    fi
fi

check_file "certs/server.key"

# Check StepCA chain certificate for mTLS
if check_file "certs/stepca_chain.crt"; then
    echo -e "${GREEN}[OK]${NC} StepCA chain certificate exists (mTLS enabled)"
else
    echo -e "${YELLOW}[WARN]${NC} StepCA chain certificate missing"
    echo "  Generate with: docker exec vt-stepca step ca roots > certs/stepca_chain.crt"
    ((WARNING_COUNT++))
fi

# Check certificate permissions
echo -e "\n${CYAN}--- Certificate Permissions ---${NC}"
if [ -f "certs/server.key" ]; then
    perms=$(stat -c "%a" certs/server.key 2>/dev/null || stat -f "%Lp" certs/server.key 2>/dev/null)
    if [ "$perms" == "600" ] || [ "$perms" == "400" ]; then
        echo -e "${GREEN}[OK]${NC} Private key has secure permissions ($perms)"
    else
        echo -e "${YELLOW}[WARN]${NC} Private key permissions not secure ($perms)"
        echo "  Secure with: chmod 600 certs/server.key"
        ((WARNING_COUNT++))
    fi
fi

# Check mTLS configuration
echo -e "\n${CYAN}--- mTLS Configuration ---${NC}"
if grep -q "^[^#]*ssl_client_certificate" conf/conf.d/20-agent-mtls-443.conf; then
    echo -e "${GREEN}[OK]${NC} mTLS client verification enabled"
else
    echo -e "${YELLOW}[WARN]${NC} mTLS client verification commented out"
    echo "  Enable for production: uncomment ssl_client_certificate directives"
    ((WARNING_COUNT++))
fi

# Check rate limiting configuration
echo -e "\n${CYAN}--- Rate Limiting ---${NC}"
if grep -q "limit_req_zone" conf/nginx.conf; then
    echo -e "${GREEN}[OK]${NC} Rate limiting zones configured"
else
    echo -e "${YELLOW}[WARN]${NC} Rate limiting not configured"
    ((WARNING_COUNT++))
fi

# Check firewall
echo -e "\n${CYAN}--- Firewall Configuration ---${NC}"
if command -v firewall-cmd &> /dev/null; then
    local missing_ports=()
    
    if ! sudo firewall-cmd --list-ports | grep -q "443/tcp"; then
        missing_ports+=("443/tcp (Agent API)")
    fi
    
    if ! sudo firewall-cmd --list-ports | grep -q "8443/tcp"; then
        missing_ports+=("8443/tcp (Admin Dashboard)")
    fi
    
    if [ ${#missing_ports[@]} -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC} Required ports are open"
    else
        echo -e "${YELLOW}[WARN]${NC} Missing firewall rules:"
        for port in "${missing_ports[@]}"; do
            echo "  - $port"
        done
        echo "  Open with: sudo firewall-cmd --permanent --add-port=443/tcp --add-port=8443/tcp && sudo firewall-cmd --reload"
        ((WARNING_COUNT++))
    fi
else
    echo -e "${YELLOW}[WARN]${NC} firewalld not installed, skipping firewall check"
    ((WARNING_COUNT++))
fi

# Check backend connectivity
echo -e "\n${CYAN}--- Backend Connectivity ---${NC}"
backends=("10.211.130.47:8080" "10.211.130.49:8081")
for backend in "${backends[@]}"; do
    if timeout 2 bash -c "echo > /dev/tcp/${backend%:*}/${backend#*:}" 2>/dev/null; then
        echo -e "${GREEN}[OK]${NC} Backend reachable: $backend"
    else
        echo -e "${YELLOW}[WARN]${NC} Cannot reach backend: $backend (may not be deployed yet)"
        ((WARNING_COUNT++))
    fi
done

# Check if container is running
echo -e "\n${CYAN}--- Container Status ---${NC}"
if docker ps --format '{{.Names}}' | grep -q "vt-nginx"; then
    echo -e "${GREEN}[OK]${NC} Nginx container is running"
    
    # Test nginx configuration
    if docker exec vt-nginx-gateway nginx -t &>/dev/null 2>&1 || docker exec vt-nginx nginx -t &>/dev/null 2>&1; then
        echo -e "${GREEN}[OK]${NC} Nginx configuration is valid"
    fi
else
    echo -e "${YELLOW}[INFO]${NC} Container not running (will be started during deployment)"
fi

# Summary
echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN}Validation Summary${NC}"
echo -e "${CYAN}========================================${NC}"

if [ $ERROR_COUNT -eq 0 ] && [ $WARNING_COUNT -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS]${NC} All checks passed! Ready for deployment."
    exit 0
else
    if [ $ERROR_COUNT -gt 0 ]; then
        echo -e "Errors: ${RED}$ERROR_COUNT${NC}"
    else
        echo -e "Errors: ${GREEN}0${NC}"
    fi
    
    if [ $WARNING_COUNT -gt 0 ]; then
        echo -e "Warnings: ${YELLOW}$WARNING_COUNT${NC}"
    else
        echo -e "Warnings: ${GREEN}0${NC}"
    fi
    
    if [ $ERROR_COUNT -gt 0 ]; then
        echo -e "\n${RED}[FAIL]${NC} Fix errors before deployment"
        exit 1
    else
        echo -e "\n${YELLOW}[WARN]${NC} Review warnings - deployment may proceed with caution"
        exit 0
    fi
fi
