# ============================================
# SCRIPT: Switch back to PRODUCTION environment
# ============================================

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  VT-AUDIT: Switch to PRODUCTION" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Restore Admin API .env
Write-Host "[1/3] Restoring Admin API config..." -ForegroundColor Yellow
$adminPath = "03-admin-api"
if (Test-Path "$adminPath\.env.production") {
    Copy-Item "$adminPath\.env.production" "$adminPath\.env" -Force
    Write-Host "  ✓ Restored .env.production" -ForegroundColor Green
} else {
    Write-Host "  ✗ .env.production not found (nothing to restore)" -ForegroundColor Gray
}

# Restore Agent API .env
Write-Host ""
Write-Host "[2/3] Restoring Agent API config..." -ForegroundColor Yellow
$agentPath = "04-agent-api"
if (Test-Path "$agentPath\.env.production") {
    Copy-Item "$agentPath\.env.production" "$agentPath\.env" -Force
    Write-Host "  ✓ Restored .env.production" -ForegroundColor Green
} else {
    Write-Host "  ✗ .env.production not found (nothing to restore)" -ForegroundColor Gray
}

# Restore Nginx config
Write-Host ""
Write-Host "[3/3] Restoring Nginx config..." -ForegroundColor Yellow
$nginxPath = "02-nginx-gateway/conf/conf.d"
if (Test-Path "$nginxPath\00-upstream.conf.production") {
    Copy-Item "$nginxPath\00-upstream.conf.production" "$nginxPath\00-upstream.conf" -Force
    Write-Host "  ✓ Restored 00-upstream.conf.production" -ForegroundColor Green
} else {
    Write-Host "  ✗ 00-upstream.conf.production not found (nothing to restore)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  ✓ Switched to PRODUCTION mode" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  Remember to update IP addresses for production!" -ForegroundColor Yellow
Write-Host ""
