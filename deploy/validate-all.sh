#!/bin/bash
# Master Validation Script - Run on all servers
# This script validates all components across the deployment
# Usage: bash validate-all.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}VT-AUDIT Multi-Server Validator${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

TOTAL_ERRORS=0
TOTAL_WARNINGS=0

# Function to run validation on a component
validate_component() {
    local component=$1
    local name=$2
    
    echo -e "\n${CYAN}=== Validating: $name ===${NC}"
    
    if [ -f "$component/validate.sh" ]; then
        cd "$component"
        if bash validate.sh; then
            echo -e "${GREEN}[OK]${NC} $name validation passed"
            cd - > /dev/null
            return 0
        else
            exit_code=$?
            echo -e "${RED}[FAIL]${NC} $name validation failed (exit code: $exit_code)"
            cd - > /dev/null
            ((TOTAL_ERRORS++))
            return 1
        fi
    else
        echo -e "${YELLOW}[WARN]${NC} No validation script for $name"
        ((TOTAL_WARNINGS++))
        return 0
    fi
}

# Detect which server this is based on IP or hostname
detect_server_role() {
    local ip=$(hostname -I | awk '{print $1}')
    
    case "$ip" in
        10.211.130.51)
            echo "database"
            ;;
        10.211.130.47|10.211.130.48)
            echo "agent-api"
            ;;
        10.211.130.49|10.211.130.50)
            echo "admin-api"
            ;;
        10.211.130.45|10.211.130.46)
            echo "nginx-gateway"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Main validation logic
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SERVER_ROLE=$(detect_server_role)

if [ "$SERVER_ROLE" != "unknown" ]; then
    echo -e "${CYAN}Detected server role: $SERVER_ROLE${NC}"
    echo ""
    
    case "$SERVER_ROLE" in
        database)
            validate_component "01-database" "Database Server"
            ;;
        agent-api)
            validate_component "04-agent-api" "Agent API Server"
            ;;
        admin-api)
            validate_component "03-admin-api" "Admin API Server"
            ;;
        nginx-gateway)
            validate_component "02-nginx-gateway" "Nginx Gateway"
            ;;
    esac
else
    echo -e "${YELLOW}[WARN]${NC} Cannot detect server role, running all validations"
    echo ""
    
    # Run all validations
    validate_component "01-database" "Database Server"
    validate_component "04-agent-api" "Agent API Server"
    validate_component "03-admin-api" "Admin API Server"
    validate_component "02-nginx-gateway" "Nginx Gateway"
fi

# Summary
echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN}Overall Validation Summary${NC}"
echo -e "${CYAN}========================================${NC}"

if [ $TOTAL_ERRORS -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS]${NC} All validations passed!"
    if [ $TOTAL_WARNINGS -gt 0 ]; then
        echo -e "Warnings: ${YELLOW}$TOTAL_WARNINGS${NC}"
    fi
    exit 0
else
    echo -e "${RED}[FAIL]${NC} $TOTAL_ERRORS component(s) failed validation"
    if [ $TOTAL_WARNINGS -gt 0 ]; then
        echo -e "Warnings: ${YELLOW}$TOTAL_WARNINGS${NC}"
    fi
    exit 1
fi
