#!/bin/bash
# ============================================
# VERIFY OFFLINE ASSETS DEPLOYMENT
# ============================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=========================================="
echo "VERIFYING OFFLINE ASSETS"
echo "=========================================="

echo ""
echo -e "${YELLOW}[1/5]${NC} Checking local asset files..."

# Check CSS files
if [ -f "conf/html/assets/css/flowbite.min.css" ]; then
    SIZE=$(stat -f%z "conf/html/assets/css/flowbite.min.css" 2>/dev/null || stat -c%s "conf/html/assets/css/flowbite.min.css" 2>/dev/null)
    echo -e "${GREEN}✓${NC} flowbite.min.css (${SIZE} bytes)"
else
    echo -e "${RED}✗${NC} flowbite.min.css NOT FOUND"
fi

# Check JS files
JS_FILES=("alpine.min.js" "flowbite.min.js" "tailwindcss.js")
for file in "${JS_FILES[@]}"; do
    if [ -f "conf/html/assets/js/${file}" ]; then
        SIZE=$(stat -f%z "conf/html/assets/js/${file}" 2>/dev/null || stat -c%s "conf/html/assets/js/${file}" 2>/dev/null)
        echo -e "${GREEN}✓${NC} ${file} (${SIZE} bytes)"
    else
        echo -e "${RED}✗${NC} ${file} NOT FOUND"
    fi
done

echo ""
echo -e "${YELLOW}[2/5]${NC} Checking HTML references..."

CDN_COUNT=$(grep -c "cdn\.\|jsdelivr\|cdnjs" conf/html/index.html || echo "0")
if [ "$CDN_COUNT" -eq "0" ]; then
    echo -e "${GREEN}✓${NC} No CDN references found"
else
    echo -e "${RED}✗${NC} Found ${CDN_COUNT} CDN references:"
    grep -n "cdn\.\|jsdelivr\|cdnjs" conf/html/index.html || true
fi

LOCAL_COUNT=$(grep -c "./assets/" conf/html/index.html || echo "0")
if [ "$LOCAL_COUNT" -ge "4" ]; then
    echo -e "${GREEN}✓${NC} Found ${LOCAL_COUNT} local asset references"
else
    echo -e "${YELLOW}⚠${NC} Only found ${LOCAL_COUNT} local asset references (expected 4+)"
fi

echo ""
echo -e "${YELLOW}[3/5]${NC} Checking docker-compose volume mount..."

if grep -q "./conf/html:/usr/share/nginx/html" docker-compose.yml; then
    echo -e "${GREEN}✓${NC} HTML directory mount configured"
else
    echo -e "${RED}✗${NC} HTML directory mount NOT configured"
fi

echo ""
echo -e "${YELLOW}[4/5]${NC} Checking nginx configuration..."

if grep -q "location /assets/" conf/conf.d/10-admin-9444.conf; then
    echo -e "${GREEN}✓${NC} Assets location configured in nginx"
else
    echo -e "${RED}✗${NC} Assets location NOT configured in nginx"
fi

echo ""
echo -e "${YELLOW}[5/5]${NC} Testing nginx container (if running)..."

if docker ps | grep -q vt-nginx-gateway; then
    echo "Container is running, checking mounts..."
    
    # Check if assets are accessible in container
    if docker exec vt-nginx-gateway test -d /usr/share/nginx/html/assets; then
        echo -e "${GREEN}✓${NC} Assets directory exists in container"
        
        echo "Files in container:"
        docker exec vt-nginx-gateway find /usr/share/nginx/html/assets -type f
    else
        echo -e "${RED}✗${NC} Assets directory NOT found in container"
    fi
else
    echo -e "${YELLOW}⚠${NC} Container not running (run: docker compose up -d)"
fi

echo ""
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo "Next steps:"
echo "1. If container is not running:"
echo "   cd deploy/02-nginx-gateway"
echo "   docker compose up -d"
echo ""
echo "2. Restart nginx to reload config:"
echo "   docker compose restart"
echo ""
echo "3. Test static files from outside (when deployed):"
echo "   curl -I https://10.211.130.44:9444/assets/js/alpine.min.js"
echo "   curl -I https://10.211.130.44:9444/assets/css/flowbite.min.css"
echo ""
echo "4. Open browser and check Network tab:"
echo "   https://10.211.130.44:9444/"
echo "   All assets should load from /assets/ (not CDN)"
echo ""
