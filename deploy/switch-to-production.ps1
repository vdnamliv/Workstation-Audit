#!/usr/bin/env pwsh
# VT-AUDIT Production Configuration Switch Script
# This script prepares the deployment for production environment

Write-Host "[*] VT-AUDIT - Switching to PRODUCTION Configuration..." -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Stop"
$deployPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Function to backup file
function Backup-ConfigFile {
    param([string]$FilePath)
    if (Test-Path $FilePath) {
        $backup = "$FilePath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Copy-Item $FilePath $backup -Force
        Write-Host "  [OK] Backed up: $(Split-Path -Leaf $FilePath)" -ForegroundColor Gray
    }
}

Write-Host "[>] Pre-flight Checks..." -ForegroundColor Yellow
Write-Host "  [OK] Deploy path: $deployPath" -ForegroundColor Green
Write-Host ""

# 1. Nginx Gateway Configuration
Write-Host "[1] Configuring Nginx Gateway..." -ForegroundColor Cyan

# Swap local -> production upstream
$upstreamLocal = "$deployPath/02-nginx-gateway/conf/conf.d/00-upstream.conf"
$upstreamProd = "$deployPath/02-nginx-gateway/conf/conf.d/00-upstream.conf.production"

if (Test-Path $upstreamLocal) {
    Backup-ConfigFile $upstreamLocal
    Move-Item $upstreamLocal "$upstreamLocal.local" -Force
    Write-Host "  [OK] Saved local config as .local" -ForegroundColor Green
}

if (Test-Path $upstreamProd) {
    Copy-Item $upstreamProd $upstreamLocal -Force
    Write-Host "  [OK] Activated production upstream config" -ForegroundColor Green
} else {
    Write-Host "  [!] WARNING: $upstreamProd not found" -ForegroundColor Yellow
}

Write-Host ""

# 2. Update docker-compose files
Write-Host "[2] Updating Docker Compose configurations..." -ForegroundColor Cyan

# Admin API - Change Keycloak to production mode
$adminCompose = "$deployPath/03-admin-api/docker-compose.yml"
if (Test-Path $adminCompose) {
    Backup-ConfigFile $adminCompose
    $content = Get-Content $adminCompose -Raw
    
    if ($content -match "start-dev") {
        $content = $content -replace "start-dev", "start --optimized"
        Write-Host "  [OK] Keycloak: start-dev -> start --optimized" -ForegroundColor Green
    }
    
    if ($content -match '"8090:8080"') {
        $content = $content -replace '"8090:8080"', '"8080:8080"'
        Write-Host "  [OK] Keycloak: port 8090 -> 8080" -ForegroundColor Green
    }
    
    Set-Content $adminCompose -Value $content -NoNewline
}

Write-Host ""

# 3. Enable production security features
Write-Host "[3] Enabling production security features..." -ForegroundColor Cyan

# Uncomment mTLS in 20-agent-mtls-443.conf
$mtlsConfig = "$deployPath/02-nginx-gateway/conf/conf.d/20-agent-mtls-443.conf"
if (Test-Path $mtlsConfig) {
    Backup-ConfigFile $mtlsConfig
    $content = Get-Content $mtlsConfig -Raw
    $content = $content -replace "#ssl_client_certificate /etc/nginx/certs/stepca_chain.crt;", "ssl_client_certificate /etc/nginx/certs/stepca_chain.crt;"
    $content = $content -replace "#ssl_verify_client optional;", "ssl_verify_client optional;"
    $content = $content -replace "#ssl_verify_depth 2;", "ssl_verify_depth 2;"
    Set-Content $mtlsConfig -Value $content -NoNewline
    Write-Host "  [OK] Enabled mTLS verification" -ForegroundColor Green
}

Write-Host ""

# 4. Summary
Write-Host "[SUCCESS] Configuration switched to PRODUCTION mode!" -ForegroundColor Green
Write-Host ""
Write-Host "[NEXT STEPS]" -ForegroundColor Yellow
Write-Host "  1. Update all .env files with production IPs and passwords" -ForegroundColor White
Write-Host "  2. Generate StepCA chain certificate:" -ForegroundColor White
Write-Host "     docker exec vt-stepca step ca roots > 02-nginx-gateway/certs/stepca_chain.crt" -ForegroundColor Gray
Write-Host "  3. Verify SSL certificates in 02-nginx-gateway/certs/" -ForegroundColor White
Write-Host "  4. Review and commit changes to Git" -ForegroundColor White
Write-Host "  5. Deploy to production servers following PRODUCTION_DEPLOYMENT.md" -ForegroundColor White
Write-Host ""
Write-Host "[WARNING]" -ForegroundColor Red
Write-Host "  * NEVER commit .env files with production passwords" -ForegroundColor Red
Write-Host "  * NEVER commit private keys (.key files)" -ForegroundColor Red
Write-Host "  * Review .gitignore before pushing to GitHub" -ForegroundColor Red
Write-Host ""
Write-Host "[GUIDE] Full deployment guide: deploy/PRODUCTION_DEPLOYMENT.md" -ForegroundColor Cyan
