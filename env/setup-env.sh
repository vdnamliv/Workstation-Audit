#!/bin/bash

# =============================================================================
# VT-Audit Environment Setup Script
# =============================================================================
# This script helps generate a secure .env file for production deployment
#
# Usage:
#   chmod +x setup-env.sh
#   ./setup-env.sh
#
# The script will:
# 1. Backup existing .env file (if any)
# 2. Generate secure random passwords and secrets
# 3. Create a new .env file with proper configuration
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
ENV_BACKUP="${SCRIPT_DIR}/.env.backup.$(date +%Y%m%d_%H%M%S)"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       VT-Audit Environment Configuration Setup        ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to generate secure passwords
generate_password() {
    openssl rand -base64 24 | tr -d '\n='
}

generate_hex_secret() {
    local bytes=$1
    openssl rand -hex "$bytes" | tr -d '\n'
}

# Function to prompt user
prompt_user() {
    local prompt_text=$1
    local default_value=$2
    local user_input
    
    if [ -n "$default_value" ]; then
        read -p "$prompt_text [$default_value]: " user_input
        echo "${user_input:-$default_value}"
    else
        read -p "$prompt_text: " user_input
        echo "$user_input"
    fi
}

# Check if .env exists and backup
if [ -f "$ENV_FILE" ]; then
    echo -e "${YELLOW}⚠ Existing .env file found!${NC}"
    echo -e "Backing up to: ${ENV_BACKUP}"
    cp "$ENV_FILE" "$ENV_BACKUP"
    echo -e "${GREEN}✓ Backup created${NC}"
    echo ""
fi

echo -e "${BLUE}Generating secure random values...${NC}"
echo ""

# Generate all secrets
POSTGRES_PASSWORD=$(generate_password)
KEYCLOAK_ADMIN_PASSWORD=$(generate_password)
STEPCA_PASSWORD=$(generate_password)
STEPCA_PROVISIONER_PASSWORD=$(generate_password)
OIDC_CLIENT_SECRET=$(generate_password)
OIDC_COOKIE_SECRET=$(generate_hex_secret 16)
AGENT_BOOTSTRAP_TOKEN=$(generate_password)

echo -e "${GREEN}✓ Generated PostgreSQL password${NC}"
echo -e "${GREEN}✓ Generated Keycloak admin password${NC}"
echo -e "${GREEN}✓ Generated Step-CA passwords${NC}"
echo -e "${GREEN}✓ Generated OIDC secrets${NC}"
echo -e "${GREEN}✓ Generated Agent bootstrap token${NC}"
echo ""

# Ask for optional customizations
echo -e "${BLUE}Optional Customizations (press Enter to use defaults):${NC}"
echo ""

POSTGRES_USER=$(prompt_user "PostgreSQL username" "audit")
KEYCLOAK_ADMIN=$(prompt_user "Keycloak admin username" "admin")
STEPCA_NAME=$(prompt_user "Certificate Authority name" "VT-Audit Certificate Authority")
STEPCA_DNS_NAMES=$(prompt_user "Step-CA DNS names (comma-separated, NO spaces)" "gateway.local,stepca,api-agent,localhost")

echo ""
echo -e "${BLUE}Creating .env file...${NC}"

# Create .env file
cat > "$ENV_FILE" << EOF
# =============================================================================
# VT-AUDIT PRODUCTION ENVIRONMENT CONFIGURATION
# =============================================================================
# Generated on: $(date)
# NEVER commit this file to version control - it contains sensitive data

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

# PostgreSQL database settings
POSTGRES_DB=audit
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DSN=postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/audit?sslmode=disable

# Database connection settings
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_SSLMODE=disable

# =============================================================================
# KEYCLOAK AUTHENTICATION
# =============================================================================

# Keycloak database settings
# IMPORTANT: Password must be "ChangeMe123!" to match init scripts
KEYCLOAK_DB=audit
KEYCLOAK_DB_USER=keycloak
KEYCLOAK_DB_PASSWORD=ChangeMe123!

# Keycloak admin credentials
KEYCLOAK_ADMIN=${KEYCLOAK_ADMIN}
KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD}

# Keycloak realm
KEYCLOAK_REALM=vt-audit

# =============================================================================
# CERTIFICATE AUTHORITY CONFIGURATION
# =============================================================================

# Step-CA configuration
STEPCA_NAME=${STEPCA_NAME}
STEPCA_DNS_NAMES=${STEPCA_DNS_NAMES}
STEPCA_PROVISIONER=bootstrap@vt-audit
STEPCA_URL=https://stepca:9000
STEPCA_EXTERNAL_URL=https://gateway.local/step-ca

# Step-CA passwords
STEPCA_PASSWORD=${STEPCA_PASSWORD}
STEPCA_PROVISIONER_PASSWORD=${STEPCA_PROVISIONER_PASSWORD}

# Step-CA key path
STEPCA_KEY_PATH=/stepca/secrets/provisioner.key

# Certificate validity settings
MTLS_CERT_TTL=24h
CERTIFICATE_VALIDITY_HOURS=24

# =============================================================================
# OAUTH2 / OIDC CONFIGURATION
# =============================================================================

# OAuth2 proxy settings
OIDC_CLIENT_ID=dashboard-proxy
OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}
OIDC_COOKIE_SECRET=${OIDC_COOKIE_SECRET}

# OIDC issuer and roles
OIDC_ISSUER=https://gateway.local/auth/realms/vt-audit
OIDC_ADMIN_ROLE=admin

# =============================================================================
# AGENT CONFIGURATION
# =============================================================================

# Agent bootstrap token
AGENT_BOOTSTRAP_TOKEN=${AGENT_BOOTSTRAP_TOKEN}
EOF

# Set proper permissions
chmod 600 "$ENV_FILE"

echo ""
echo -e "${GREEN}✓ .env file created successfully!${NC}"
echo ""

# Display credentials summary
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              IMPORTANT CREDENTIALS SUMMARY             ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Save these credentials in a secure location:${NC}"
echo ""
echo -e "PostgreSQL:"
echo -e "  Username: ${GREEN}${POSTGRES_USER}${NC}"
echo -e "  Password: ${GREEN}${POSTGRES_PASSWORD}${NC}"
echo ""
echo -e "Keycloak Admin:"
echo -e "  Username: ${GREEN}${KEYCLOAK_ADMIN}${NC}"
echo -e "  Password: ${GREEN}${KEYCLOAK_ADMIN_PASSWORD}${NC}"
echo -e "  Console:  ${BLUE}https://gateway.local/auth/${NC}"
echo ""
echo -e "Keycloak Database:"
echo -e "  Username: ${GREEN}keycloak${NC}"
echo -e "  Password: ${GREEN}ChangeMe123!${NC} ${YELLOW}(hardcoded in init script)${NC}"
echo ""
echo -e "Step-CA:"
echo -e "  Password: ${GREEN}${STEPCA_PASSWORD}${NC}"
echo -e "  Provisioner Password: ${GREEN}${STEPCA_PROVISIONER_PASSWORD}${NC}"
echo ""
echo -e "OAuth2:"
echo -e "  Client Secret: ${GREEN}${OIDC_CLIENT_SECRET}${NC}"
echo -e "  Cookie Secret: ${GREEN}${OIDC_COOKIE_SECRET}${NC}"
echo ""
echo -e "Agent:"
echo -e "  Bootstrap Token: ${GREEN}${AGENT_BOOTSTRAP_TOKEN}${NC}"
echo ""

# Final instructions
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    NEXT STEPS                          ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "1. Review the generated .env file:"
echo -e "   ${BLUE}cat .env${NC}"
echo ""
echo -e "2. Clean up existing deployment (if any):"
echo -e "   ${BLUE}sudo docker compose down -v${NC}"
echo -e "   ${BLUE}sudo rm -f certs/nginx/*.crt certs/nginx/*.key${NC}"
echo ""
echo -e "3. Deploy the stack:"
echo -e "   ${BLUE}sudo docker compose up -d${NC}"
echo ""
echo -e "4. Monitor the deployment:"
echo -e "   ${BLUE}sudo docker compose logs -f${NC}"
echo ""
echo -e "5. Check status (after 2-3 minutes):"
echo -e "   ${BLUE}sudo docker compose ps${NC}"
echo ""
echo -e "${GREEN}For detailed deployment guide, see: DEPLOYMENT.md${NC}"
echo ""

# Ask if user wants to deploy now
read -p "Would you like to deploy now? (y/n): " deploy_now

if [ "$deploy_now" = "y" ] || [ "$deploy_now" = "Y" ]; then
    echo ""
    echo -e "${BLUE}Starting deployment...${NC}"
    echo ""
    
    # Clean up
    echo -e "${YELLOW}Cleaning up existing deployment...${NC}"
    sudo docker compose down -v 2>/dev/null || true
    sudo rm -f certs/nginx/*.crt certs/nginx/*.key 2>/dev/null || true
    
    # Deploy
    echo ""
    echo -e "${BLUE}Deploying stack...${NC}"
    sudo docker compose up -d
    
    echo ""
    echo -e "${GREEN}✓ Deployment started!${NC}"
    echo ""
    echo -e "Waiting for services to start (this may take 2-3 minutes)..."
    echo -e "You can monitor progress with: ${BLUE}sudo docker compose logs -f${NC}"
else
    echo ""
    echo -e "${YELLOW}Deployment skipped. Run 'sudo docker compose up -d' when ready.${NC}"
fi

echo ""
echo -e "${GREEN}Setup completed successfully!${NC}"
