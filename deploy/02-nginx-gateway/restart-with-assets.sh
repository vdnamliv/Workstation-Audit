#!/bin/bash
# ============================================
# RESTART NGINX WITH OFFLINE ASSETS
# ============================================

cd "$(dirname "$0")"

echo "=========================================="
echo "RESTARTING NGINX GATEWAY"
echo "=========================================="

echo ""
echo "[1/3] Stopping nginx..."
docker compose down

echo ""
echo "[2/3] Starting nginx with new config..."
docker compose up -d

echo ""
echo "[3/3] Checking status..."
sleep 2
docker compose ps

echo ""
echo "=========================================="
echo "VERIFICATION"
echo "=========================================="

# Check if assets are mounted
echo "Assets in container:"
docker exec vt-nginx-gateway ls -lh /usr/share/nginx/html/assets/js/ 2>/dev/null || echo "ERROR: Cannot access assets"
docker exec vt-nginx-gateway ls -lh /usr/share/nginx/html/assets/css/ 2>/dev/null || echo "ERROR: Cannot access assets"

echo ""
echo "=========================================="
echo "TEST URLs (after full deployment):"
echo "=========================================="
echo "Main page:"
echo "  https://10.211.130.44:9444/"
echo ""
echo "Static assets:"
echo "  https://10.211.130.44:9444/assets/js/alpine.min.js"
echo "  https://10.211.130.44:9444/assets/js/flowbite.min.js"
echo "  https://10.211.130.44:9444/assets/js/tailwindcss.js"
echo "  https://10.211.130.44:9444/assets/css/flowbite.min.css"
echo ""
echo "Monitor logs:"
echo "  docker logs -f vt-nginx-gateway"
echo ""
