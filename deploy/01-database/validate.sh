#!/bin/bash
# Database Server Validation Script
# Server: 10.211.130.51
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
echo -e "${CYAN}VT-AUDIT Database Server Validator${NC}"
echo -e "${CYAN}Server: 10.211.130.51${NC}"
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

# Function to check weak passwords
check_weak_passwords() {
    local file=$1
    local weak_patterns=("password" "admin" "123456" "CHANGE_ME" "ChangeMe")
    local found_weak=false
    
    for pattern in "${weak_patterns[@]}"; do
        if grep -qi "$pattern" "$file" 2>/dev/null; then
            echo -e "${YELLOW}[WARN]${NC} Weak password pattern found in $file: $pattern"
            ((WARNING_COUNT++))
            found_weak=true
        fi
    done
    
    if [ "$found_weak" = false ]; then
        echo -e "${GREEN}[OK]${NC} Password security check passed: $file"
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
echo -e "\n${CYAN}--- Configuration Files ---${NC}"
check_file "docker-compose.yml"
check_file "conf/init/01-init.sql"

if [ -f ".env" ]; then
    check_file ".env"
    check_weak_passwords ".env"
else
    echo -e "${YELLOW}[WARN]${NC} .env file not found"
    echo "  Create from: cp .env.example .env"
    ((WARNING_COUNT++))
fi

# Check firewall
echo -e "\n${CYAN}--- Firewall Configuration ---${NC}"
if command -v firewall-cmd &> /dev/null; then
    if sudo firewall-cmd --list-ports | grep -q "5432/tcp"; then
        echo -e "${GREEN}[OK]${NC} PostgreSQL port 5432 is open"
    else
        echo -e "${YELLOW}[WARN]${NC} PostgreSQL port 5432 not open in firewall"
        echo "  Open with: sudo firewall-cmd --permanent --add-port=5432/tcp && sudo firewall-cmd --reload"
        ((WARNING_COUNT++))
    fi
else
    echo -e "${YELLOW}[WARN]${NC} firewalld not installed, skipping firewall check"
    ((WARNING_COUNT++))
fi

# Check if container is already running
echo -e "\n${CYAN}--- Container Status ---${NC}"
if docker ps --format '{{.Names}}' | grep -q "postgres-vt-audit"; then
    echo -e "${GREEN}[OK]${NC} Container 'postgres-vt-audit' is running"
    
    # Check container health
    if docker inspect postgres-vt-audit --format='{{.State.Health.Status}}' 2>/dev/null | grep -q "healthy"; then
        echo -e "${GREEN}[OK]${NC} Container is healthy"
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
