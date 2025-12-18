#!/bin/bash
# ============================================
# EXTRACT STEP-CA PROVISIONER KEY
# ============================================
# Script này extract provisioner key từ Step-CA container
# sau khi Step-CA đã khởi động và tạo provisioner

set -e

echo "=========================================="
echo "EXTRACTING STEP-CA PROVISIONER KEY"
echo "=========================================="

# Màu sắc
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Step-CA container is running
if ! docker ps | grep -q vt-stepca; then
    echo -e "${RED}[ERROR]${NC} Step-CA container is not running!"
    echo "Start it with: docker compose up -d stepca"
    exit 1
fi

echo -e "${YELLOW}[1/5]${NC} Checking Step-CA health..."
# Wait for Step-CA to be healthy
RETRY=0
MAX_RETRIES=30
while [ $RETRY -lt $MAX_RETRIES ]; do
    if docker exec vt-stepca step ca health 2>/dev/null | grep -q "ok"; then
        echo -e "${GREEN}✓${NC} Step-CA is healthy"
        break
    fi
    echo "Waiting for Step-CA to be ready... ($RETRY/$MAX_RETRIES)"
    sleep 2
    RETRY=$((RETRY + 1))
done

if [ $RETRY -eq $MAX_RETRIES ]; then
    echo -e "${RED}[ERROR]${NC} Step-CA did not become healthy in time"
    exit 1
fi

echo ""
echo -e "${YELLOW}[2/5]${NC} Listing available provisioners..."
docker exec vt-stepca step ca provisioner list

echo ""
echo -e "${YELLOW}[3/5]${NC} Extracting provisioner key from Step-CA..."

# Get provisioner name from .env
PROVISIONER_NAME=$(grep STEPCA_PROVISIONER= .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
if [ -z "$PROVISIONER_NAME" ]; then
    echo -e "${RED}[ERROR]${NC} Cannot find STEPCA_PROVISIONER in .env file"
    exit 1
fi

echo "Provisioner name: $PROVISIONER_NAME"

# Step-CA stores provisioners at different locations:
# - /home/step/certs/secrets/<name>.key (encrypted private key)
# - /home/step/secrets/<name>.key (alternative)
# List all possible locations
echo "Searching for provisioner key..."
docker exec vt-stepca find /home/step -type f \( -name "*.jwk" -o -name "${PROVISIONER_NAME}*" \) 2>/dev/null

# The provisioner key is stored in the stepca volume at:
# /home/step/certs/secrets/<provisioner-name>.key (this is a JWK file)
PROVISIONER_KEY_PATH="/home/step/certs/secrets/${PROVISIONER_NAME}.key"

# Check if provisioner key exists
if docker exec vt-stepca test -f "$PROVISIONER_KEY_PATH"; then
    echo -e "${GREEN}✓${NC} Found provisioner key at: $PROVISIONER_KEY_PATH"
else
    # Try alternative path (JWK provisioner)
    PROVISIONER_KEY_PATH="/home/step/secrets/${PROVISIONER_NAME}.key"
    if docker exec vt-stepca test -f "$PROVISIONER_KEY_PATH"; then
        echo -e "${GREEN}✓${NC} Found provisioner key at: $PROVISIONER_KEY_PATH"
    else
        # Try to find it using ca.json config
        echo "Looking up provisioner in ca.json..."
        KEY_FILE=$(docker exec vt-stepca jq -r ".authority.provisioners[] | select(.name==\"${PROVISIONER_NAME}\") | .encryptedKey // .key" /home/step/config/ca.json 2>/dev/null)
        
        if [ -n "$KEY_FILE" ] && [ "$KEY_FILE" != "null" ]; then
            echo -e "${YELLOW}[INFO]${NC} Provisioner key is embedded in ca.json"
            # Extract from ca.json
            docker exec vt-stepca jq -r ".authority.provisioners[] | select(.name==\"${PROVISIONER_NAME}\")" /home/step/config/ca.json > admin.jwk.tmp
            
            if [ -s admin.jwk.tmp ] && jq empty admin.jwk.tmp 2>/dev/null; then
                mv admin.jwk.tmp admin.jwk
                echo -e "${GREEN}✓${NC} Extracted provisioner from ca.json"
            else
                rm -f admin.jwk.tmp
                echo -e "${RED}[ERROR]${NC} Failed to extract from ca.json"
                exit 1
            fi
        else
            echo -e "${RED}[ERROR]${NC} Provisioner key not found!"
            echo ""
            echo "Debugging info:"
            echo "1. List files in /home/step:"
            docker exec vt-stepca ls -la /home/step/
            echo ""
            echo "2. List secrets directory:"
            docker exec vt-stepca ls -la /home/step/secrets/ 2>/dev/null || echo "   No /home/step/secrets/ directory"
            echo ""
            echo "3. List certs/secrets directory:"
            docker exec vt-stepca ls -la /home/step/certs/secrets/ 2>/dev/null || echo "   No /home/step/certs/secrets/ directory"
            echo ""
            echo "4. Check ca.json provisioners:"
            docker exec vt-stepca jq '.authority.provisioners[] | {name, type, key: (.key // .encryptedKey // "N/A")}' /home/step/config/ca.json
            exit 1
        fi
    fi
fi

echo ""
echo -e "${YELLOW}[4/5]${NC} Copying provisioner key to host..."

# Extract the key if not already extracted from ca.json
if [ ! -f admin.jwk ]; then
    docker exec vt-stepca cat "$PROVISIONER_KEY_PATH" > admin.jwk
fi

# Verify the key is valid JSON
if ! jq empty admin.jwk 2>/dev/null; then
    echo -e "${RED}[ERROR]${NC} Extracted key is not valid JSON!"
    cat admin.jwk
    exit 1
fi

# Verify it has required JWK fields
if ! jq -e '.kty and .crv' admin.jwk &>/dev/null; then
    echo -e "${RED}[ERROR]${NC} Extracted key is not a valid JWK!"
    jq . admin.jwk
    exit 1
fi

echo -e "${GREEN}✓${NC} Provisioner key extracted successfully"

echo ""
echo -e "${YELLOW}[5/5]${NC} Verifying extracted key..."
echo "Key info:"
jq -r '{use, kty, kid, crv, alg, x, y} | to_entries[] | "\(.key): \(.value)"' admin.jwk 2>/dev/null || jq . admin.jwk

# Set proper permissions
chmod 600 admin.jwk

echo ""
echo "=========================================="
echo -e "${GREEN}SUCCESS!${NC}"
echo "=========================================="
echo "Provisioner key saved to: ./admin.jwk"
echo "File permissions: 600 (read/write owner only)"
echo ""
echo -e "${YELLOW}NEXT STEPS:${NC}"
echo "1. Restart agent-api to use the new key:"
echo "   docker compose restart api-agent"
echo ""
echo "2. Verify agent-api can read the key:"
echo "   docker logs vt-api-agent --tail 20"
echo ""
echo "3. IMPORTANT: Keep this file secure!"
echo "   - DO NOT commit to git"
echo "   - DO NOT share publicly"
echo "   - Backup securely"
echo ""
