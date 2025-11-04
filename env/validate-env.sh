#!/bin/bash

# =============================================================================
# VT-Audit Environment Validation Script
# =============================================================================
# This script validates your .env configuration before deployment
#
# Usage:
#   chmod +x validate-env.sh
#   ./validate-env.sh
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

ERRORS=0
WARNINGS=0

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       VT-Audit Environment Validation                  ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if .env exists
if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}✗ ERROR: .env file not found!${NC}"
    echo -e "  Run: ${BLUE}./setup-env.sh${NC} or copy from template"
    exit 1
fi

echo -e "${GREEN}✓ .env file found${NC}"
echo ""

# Load .env
source "$ENV_FILE"

echo -e "${BLUE}Validating configuration...${NC}"
echo ""

# Function to check variable
check_var() {
    local var_name=$1
    local var_value="${!var_name}"
    local description=$2
    
    if [ -z "$var_value" ]; then
        echo -e "${RED}✗ $var_name is not set${NC}"
        echo -e "  Description: $description"
        ((ERRORS++))
        return 1
    fi
    return 0
}

# Function to check if contains placeholder
check_placeholder() {
    local var_name=$1
    local var_value="${!var_name}"
    
    if [[ "$var_value" == *"CHANGE_ME"* ]] || [[ "$var_value" == *"replace-with"* ]]; then
        echo -e "${YELLOW}⚠ $var_name contains placeholder value${NC}"
        echo -e "  Current: $var_value"
        ((WARNINGS++))
        return 1
    fi
    return 0
}

# Database checks
echo -e "${BLUE}[1/6] Database Configuration${NC}"

if check_var "POSTGRES_DB" "PostgreSQL database name"; then
    if [ "$POSTGRES_DB" != "audit" ]; then
        echo -e "${RED}✗ POSTGRES_DB must be 'audit' (found: '$POSTGRES_DB')${NC}"
        echo -e "  Reason: Hardcoded in init scripts"
        ((ERRORS++))
    else
        echo -e "${GREEN}✓ POSTGRES_DB is correct${NC}"
    fi
fi

check_var "POSTGRES_USER" "PostgreSQL username"
if check_var "POSTGRES_PASSWORD" "PostgreSQL password"; then
    check_placeholder "POSTGRES_PASSWORD"
fi

if check_var "POSTGRES_DSN" "PostgreSQL connection string"; then
    if [[ ! "$POSTGRES_DSN" =~ $POSTGRES_PASSWORD ]]; then
        echo -e "${YELLOW}⚠ POSTGRES_DSN password doesn't match POSTGRES_PASSWORD${NC}"
        ((WARNINGS++))
    fi
fi
echo ""

# Keycloak checks
echo -e "${BLUE}[2/6] Keycloak Configuration${NC}"

if check_var "KEYCLOAK_DB" "Keycloak database name"; then
    if [ "$KEYCLOAK_DB" != "audit" ]; then
        echo -e "${RED}✗ KEYCLOAK_DB must be 'audit' (found: '$KEYCLOAK_DB')${NC}"
        echo -e "  Reason: Must use same database as application"
        ((ERRORS++))
    else
        echo -e "${GREEN}✓ KEYCLOAK_DB is correct${NC}"
    fi
fi

if check_var "KEYCLOAK_DB_USER" "Keycloak database user"; then
    if [ "$KEYCLOAK_DB_USER" != "keycloak" ]; then
        echo -e "${RED}✗ KEYCLOAK_DB_USER must be 'keycloak' (found: '$KEYCLOAK_DB_USER')${NC}"
        echo -e "  Reason: Hardcoded in 20_grants.sql"
        ((ERRORS++))
    else
        echo -e "${GREEN}✓ KEYCLOAK_DB_USER is correct${NC}"
    fi
fi

if check_var "KEYCLOAK_DB_PASSWORD" "Keycloak database password"; then
    if [ "$KEYCLOAK_DB_PASSWORD" != "ChangeMe123!" ]; then
        echo -e "${RED}✗ KEYCLOAK_DB_PASSWORD must be 'ChangeMe123!' (found: '$KEYCLOAK_DB_PASSWORD')${NC}"
        echo -e "  Reason: Hardcoded in conf/postgres/init/20_grants.sql"
        echo -e "  To change: Edit 20_grants.sql first, then update .env"
        ((ERRORS++))
    else
        echo -e "${GREEN}✓ KEYCLOAK_DB_PASSWORD is correct${NC}"
    fi
fi

check_var "KEYCLOAK_ADMIN" "Keycloak admin username"
if check_var "KEYCLOAK_ADMIN_PASSWORD" "Keycloak admin password"; then
    check_placeholder "KEYCLOAK_ADMIN_PASSWORD"
    if [ ${#KEYCLOAK_ADMIN_PASSWORD} -lt 12 ]; then
        echo -e "${YELLOW}⚠ KEYCLOAK_ADMIN_PASSWORD should be at least 12 characters${NC}"
        ((WARNINGS++))
    fi
fi
echo ""

# Step-CA checks
echo -e "${BLUE}[3/6] Certificate Authority Configuration${NC}"

check_var "STEPCA_NAME" "Certificate Authority name"

if check_var "STEPCA_DNS_NAMES" "DNS names for certificates"; then
    if [[ "$STEPCA_DNS_NAMES" =~ [[:space:]] ]]; then
        echo -e "${RED}✗ STEPCA_DNS_NAMES contains spaces!${NC}"
        echo -e "  Current: '$STEPCA_DNS_NAMES'"
        echo -e "  Spaces after commas will break certificate generation"
        echo -e "  Example: gateway.local,stepca,localhost (no spaces)"
        ((ERRORS++))
    else
        echo -e "${GREEN}✓ STEPCA_DNS_NAMES format is correct${NC}"
    fi
    
    # Check for common names
    if [[ ! "$STEPCA_DNS_NAMES" =~ "localhost" ]]; then
        echo -e "${YELLOW}⚠ STEPCA_DNS_NAMES should include 'localhost'${NC}"
        ((WARNINGS++))
    fi
fi

check_var "STEPCA_PROVISIONER" "Provisioner name"
if check_var "STEPCA_PASSWORD" "Step-CA password"; then
    check_placeholder "STEPCA_PASSWORD"
fi
if check_var "STEPCA_PROVISIONER_PASSWORD" "Provisioner password"; then
    check_placeholder "STEPCA_PROVISIONER_PASSWORD"
fi
echo ""

# OIDC checks
echo -e "${BLUE}[4/6] OIDC/OAuth2 Configuration${NC}"

check_var "OIDC_CLIENT_ID" "OAuth2 client ID"

if check_var "OIDC_CLIENT_SECRET" "OAuth2 client secret"; then
    check_placeholder "OIDC_CLIENT_SECRET"
    if [ ${#OIDC_CLIENT_SECRET} -lt 32 ]; then
        echo -e "${YELLOW}⚠ OIDC_CLIENT_SECRET should be at least 32 characters${NC}"
        ((WARNINGS++))
    fi
fi

if check_var "OIDC_COOKIE_SECRET" "OAuth2 cookie secret"; then
    check_placeholder "OIDC_COOKIE_SECRET"
    
    local length=${#OIDC_COOKIE_SECRET}
    if [ $length -ne 32 ] && [ $length -ne 48 ] && [ $length -ne 64 ]; then
        echo -e "${RED}✗ OIDC_COOKIE_SECRET must be exactly 32, 48, or 64 hex characters${NC}"
        echo -e "  Current length: $length characters"
        echo -e "  Generate with: ${BLUE}openssl rand -hex 16${NC} (for 32 chars)"
        echo -e "              or: ${BLUE}openssl rand -hex 24${NC} (for 48 chars)"
        echo -e "              or: ${BLUE}openssl rand -hex 32${NC} (for 64 chars)"
        ((ERRORS++))
    else
        # Check if it's hex
        if [[ ! "$OIDC_COOKIE_SECRET" =~ ^[0-9a-fA-F]+$ ]]; then
            echo -e "${RED}✗ OIDC_COOKIE_SECRET must contain only hex characters (0-9, a-f)${NC}"
            echo -e "  Do not use base64 strings with +, /, = characters"
            ((ERRORS++))
        else
            echo -e "${GREEN}✓ OIDC_COOKIE_SECRET length and format are correct${NC}"
        fi
    fi
fi

check_var "OIDC_ISSUER" "OIDC issuer URL"
echo ""

# Agent checks
echo -e "${BLUE}[5/6] Agent Configuration${NC}"

if check_var "AGENT_BOOTSTRAP_TOKEN" "Agent bootstrap token"; then
    check_placeholder "AGENT_BOOTSTRAP_TOKEN"
    if [ ${#AGENT_BOOTSTRAP_TOKEN} -lt 20 ]; then
        echo -e "${YELLOW}⚠ AGENT_BOOTSTRAP_TOKEN should be at least 20 characters${NC}"
        ((WARNINGS++))
    fi
fi
echo ""

# File permissions check
echo -e "${BLUE}[6/6] Security Checks${NC}"

file_perms=$(stat -c "%a" "$ENV_FILE")
if [ "$file_perms" != "600" ] && [ "$file_perms" != "400" ]; then
    echo -e "${YELLOW}⚠ .env file permissions are too open: $file_perms${NC}"
    echo -e "  Recommended: ${BLUE}chmod 600 .env${NC}"
    ((WARNINGS++))
else
    echo -e "${GREEN}✓ .env file permissions are secure ($file_perms)${NC}"
fi

# Check for common passwords
weak_passwords=("password" "admin123" "123456" "changeme")
for weak in "${weak_passwords[@]}"; do
    if grep -qi "$weak" "$ENV_FILE"; then
        echo -e "${YELLOW}⚠ Potentially weak password detected: '$weak'${NC}"
        ((WARNINGS++))
    fi
done
echo ""

# Summary
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  Validation Summary                    ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo -e "${GREEN}✓ Configuration is ready for deployment${NC}"
    echo ""
    echo -e "Next steps:"
    echo -e "  1. ${BLUE}sudo docker compose down -v${NC} (clean old deployment)"
    echo -e "  2. ${BLUE}sudo rm -f certs/nginx/*.crt certs/nginx/*.key${NC} (clean certs)"
    echo -e "  3. ${BLUE}sudo docker compose up -d${NC} (deploy)"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ Found $WARNINGS warning(s)${NC}"
    echo -e "${YELLOW}⚠ You can deploy, but review warnings above${NC}"
    echo ""
    read -p "Continue with deployment? (y/n): " continue_deploy
    if [ "$continue_deploy" = "y" ] || [ "$continue_deploy" = "Y" ]; then
        echo -e "${GREEN}Proceeding...${NC}"
        exit 0
    else
        echo -e "${YELLOW}Deployment cancelled${NC}"
        exit 1
    fi
else
    echo -e "${RED}✗ Found $ERRORS error(s) and $WARNINGS warning(s)${NC}"
    echo -e "${RED}✗ Please fix errors before deployment${NC}"
    echo ""
    echo -e "To fix:"
    echo -e "  1. Review error messages above"
    echo -e "  2. Edit .env: ${BLUE}nano .env${NC}"
    echo -e "  3. Run validation again: ${BLUE}./validate-env.sh${NC}"
    echo ""
    echo -e "For help, see: ${BLUE}../DEPLOYMENT.md${NC}"
    exit 1
fi
