#!/bin/bash
# Extract StepCA Provisioner Key
# Run this AFTER StepCA container is initialized
# Usage: bash extract-provisioner-key.sh

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================="
echo "StepCA Provisioner Key Extractor"
echo "========================================="
echo ""

CONTAINER_NAME="vt-stepca"
OUTPUT_FILE="admin.jwk"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${RED}[ERROR]${NC} Container '${CONTAINER_NAME}' is not running"
    echo "Start it with: docker compose up -d"
    exit 1
fi

echo -e "${GREEN}[OK]${NC} Container '${CONTAINER_NAME}' is running"

# Wait for StepCA to be fully initialized
echo "Waiting for StepCA to initialize..."
sleep 5

# Check if StepCA is healthy
if ! docker exec $CONTAINER_NAME step ca health &>/dev/null; then
    echo -e "${YELLOW}[WARN]${NC} StepCA is not ready yet, waiting..."
    sleep 10
fi

echo -e "${GREEN}[OK]${NC} StepCA is healthy"

# Get provisioner name from environment
source .env
PROVISIONER_NAME="${STEPCA_PROVISIONER:-admin}"

echo "Looking for provisioner: $PROVISIONER_NAME"

# List available provisioners
echo ""
echo "Available provisioners:"
docker exec $CONTAINER_NAME step ca provisioner list

# Check if secrets directory exists and find the JWK key
echo ""
echo "Searching for provisioner key..."

# Try to find the JWK key in StepCA config
if docker exec $CONTAINER_NAME test -f /home/step/config/ca.json; then
    echo -e "${GREEN}[OK]${NC} Found StepCA config"
    
    # Extract provisioner key from config
    docker exec $CONTAINER_NAME cat /home/step/config/ca.json | \
        jq -r ".authority.provisioners[] | select(.name==\"$PROVISIONER_NAME\") | .encryptedKey" > /tmp/check_key.txt
    
    if [ -s /tmp/check_key.txt ] && [ "$(cat /tmp/check_key.txt)" != "null" ]; then
        echo -e "${GREEN}[OK]${NC} Found provisioner in config, extracting full JWK..."
        
        # Extract complete JWK
        docker exec $CONTAINER_NAME cat /home/step/config/ca.json | \
            jq ".authority.provisioners[] | select(.name==\"$PROVISIONER_NAME\") | .key" > "$OUTPUT_FILE"
        
        if [ -s "$OUTPUT_FILE" ]; then
            echo -e "${GREEN}[SUCCESS]${NC} Provisioner key extracted to: $OUTPUT_FILE"
            echo ""
            echo "Key details:"
            jq -r '{use, kty, kid, crv, alg}' "$OUTPUT_FILE"
            
            # Set secure permissions
            chmod 600 "$OUTPUT_FILE"
            echo ""
            echo -e "${YELLOW}[SECURITY]${NC} File permissions set to 600 (read/write for owner only)"
            echo -e "${YELLOW}[SECURITY]${NC} This file is ignored by git (.gitignore)"
            echo -e "${RED}[WARNING]${NC} Keep this file secure! Never commit to git!"
            
            exit 0
        fi
    fi
fi

# Alternative: Check secrets directory
echo ""
echo "Checking secrets directory..."
if docker exec $CONTAINER_NAME test -d /home/step/secrets; then
    SECRET_FILES=$(docker exec $CONTAINER_NAME ls -la /home/step/secrets/ 2>/dev/null || echo "")
    
    if [ -n "$SECRET_FILES" ]; then
        echo "Files in secrets directory:"
        echo "$SECRET_FILES"
        
        # Try to find JWK files
        JWK_FILE=$(docker exec $CONTAINER_NAME find /home/step/secrets -name "*.jwk" -o -name "*provisioner*" 2>/dev/null | head -1)
        
        if [ -n "$JWK_FILE" ]; then
            echo -e "${GREEN}[OK]${NC} Found JWK file: $JWK_FILE"
            docker exec $CONTAINER_NAME cat "$JWK_FILE" > "$OUTPUT_FILE"
            chmod 600 "$OUTPUT_FILE"
            
            echo -e "${GREEN}[SUCCESS]${NC} Provisioner key extracted to: $OUTPUT_FILE"
            exit 0
        fi
    fi
fi

# If we reach here, automatic extraction failed
echo ""
echo -e "${YELLOW}[WARN]${NC} Could not automatically extract provisioner key"
echo ""
echo "Manual extraction steps:"
echo "1. Access StepCA container:"
echo "   docker exec -it $CONTAINER_NAME sh"
echo ""
echo "2. Find the provisioner key in config:"
echo "   cat /home/step/config/ca.json | jq '.authority.provisioners'"
echo ""
echo "3. Copy the provisioner key object to admin.jwk"
echo ""
echo "OR generate a new JWK provisioner:"
echo "   step ca provisioner add vt-audit-provisioner --type JWK --create"
echo ""

exit 1
