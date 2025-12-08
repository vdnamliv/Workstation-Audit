#!/bin/bash
# Admin API Server Validation Script
# Servers: 10.211.130.49, 10.211.130.50
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
echo -e "${CYAN}VT-AUDIT Admin API Server Validator${NC}"
echo -e "${CYAN}Servers: 10.211.130.49, 10.211.130.50${NC}"
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

if [ -f ".env" ]; then
    check_file ".env"
    check_weak_passwords ".env"
    
    # Check important variables
    source .env
    
    if [ "$DB_HOST" == "10.211.130.51" ]; then
        echo -e "${GREEN}[OK]${NC} Database host configured for production"
    else
        echo -e "${YELLOW}[WARN]${NC} Database host might not be configured for production"
        ((WARNING_COUNT++))
    fi
    
    if echo "$OIDC_ISSUER_URL" | grep -q "10.211.130.44"; then
        echo -e "${GREEN}[OK]${NC} OIDC issuer URL configured for production"
    else
        echo -e "${YELLOW}[WARN]${NC} OIDC issuer URL might not be configured for production"
        ((WARNING_COUNT++))
    fi
else
    echo -e "${RED}[FAIL]${NC} .env file not found"
    echo "  Create from: cp .env.example .env"
    ((ERROR_COUNT++))
fi

# Check docker-compose.yml for production settings
echo -e "\n${CYAN}--- Keycloak Configuration ---${NC}"
if grep -q "command: start --optimized" docker-compose.yml; then
    echo -e "${GREEN}[OK]${NC} Keycloak in production mode (start --optimized)"
else
    echo -e "${YELLOW}[WARN]${NC} Keycloak might be in dev mode"
    echo "  Change to: command: start --optimized"
    ((WARNING_COUNT++))
fi

if grep -q '"8080:8080"' docker-compose.yml; then
    echo -e "${GREEN}[OK]${NC} Keycloak using production port (8080)"
else
    echo -e "${YELLOW}[WARN]${NC} Keycloak port configuration might not be for production"
    ((WARNING_COUNT++))
fi

# Check Keycloak realm file
if [ -f "conf/keycloak/vt-audit-realm.json" ]; then
    echo -e "${GREEN}[OK]${NC} Keycloak realm configuration exists"
else
    echo -e "${YELLOW}[WARN]${NC} Keycloak realm file not found"
    echo "  You'll need to import realm manually or create conf/keycloak/vt-audit-realm.json"
    ((WARNING_COUNT++))
fi

# Check firewall
echo -e "\n${CYAN}--- Firewall Configuration ---${NC}"
if command -v firewall-cmd &> /dev/null; then
    local missing_ports=()
    
    if ! sudo firewall-cmd --list-ports | grep -q "8080/tcp"; then
        missing_ports+=("8080/tcp (Keycloak)")
    fi
    
    if ! sudo firewall-cmd --list-ports | grep -q "8081/tcp"; then
        missing_ports+=("8081/tcp (Backend)")
    fi
    
    if [ ${#missing_ports[@]} -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC} Required ports are open"
    else
        echo -e "${YELLOW}[WARN]${NC} Missing firewall rules:"
        for port in "${missing_ports[@]}"; do
            echo "  - $port"
        done
        echo "  Open with: sudo firewall-cmd --permanent --add-port=8080/tcp --add-port=8081/tcp && sudo firewall-cmd --reload"
        ((WARNING_COUNT++))
    fi
else
    echo -e "${YELLOW}[WARN]${NC} firewalld not installed, skipping firewall check"
    ((WARNING_COUNT++))
fi

# Check database connectivity
echo -e "\n${CYAN}--- Database Connectivity ---${NC}"
if [ -f ".env" ]; then
    source .env
    if command -v psql &> /dev/null; then
        if PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1" &>/dev/null; then
            echo -e "${GREEN}[OK]${NC} Database connection successful"
        else
            echo -e "${YELLOW}[WARN]${NC} Cannot connect to database (may not be deployed yet)"
            ((WARNING_COUNT++))
        fi
    else
        echo -e "${YELLOW}[INFO]${NC} psql not installed, skipping database connection test"
    fi
fi

# Check if containers are running
echo -e "\n${CYAN}--- Container Status ---${NC}"
if docker ps --format '{{.Names}}' | grep -q "vt-keycloak"; then
    echo -e "${GREEN}[OK]${NC} Container 'vt-keycloak' is running"
else
    echo -e "${YELLOW}[INFO]${NC} Container not running (will be started during deployment)"
fi

if docker ps --format '{{.Names}}' | grep -q "vt-api-backend"; then
    echo -e "${GREEN}[OK]${NC} Container 'vt-api-backend' is running"
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
