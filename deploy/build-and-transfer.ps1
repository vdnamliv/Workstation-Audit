# Build and Transfer Docker Images to Production Servers
# Run this on your local machine (Windows) to build images and transfer to servers
# Usage: .\build-and-transfer.ps1

param(
    [string]$TargetServer = "10.211.130.47",
    [string]$Username = "root"
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "VT-AUDIT Build & Transfer Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ImageName = "vt-server"
$ImageTag = "latest"
$FullImageName = "${ImageName}:${ImageTag}"
$TarFile = "vt-server-${ImageTag}.tar"

# Step 1: Build image locally
Write-Host "[1/5] Building Docker image locally..." -ForegroundColor Yellow
Set-Location ..
docker build -f env/docker/Dockerfile.vt-server -t $FullImageName .
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Docker build failed" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Image built successfully" -ForegroundColor Green

# Step 2: Save image to tar
Write-Host ""
Write-Host "[2/5] Saving image to tar file..." -ForegroundColor Yellow
docker save -o $TarFile $FullImageName
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Failed to save image" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Image saved to: $TarFile" -ForegroundColor Green

# Step 3: Compress (optional for faster transfer)
Write-Host ""
Write-Host "[3/5] Compressing image..." -ForegroundColor Yellow
if (Get-Command gzip -ErrorAction SilentlyContinue) {
    gzip -f $TarFile
    $TarFile = "$TarFile.gz"
    Write-Host "[OK] Image compressed" -ForegroundColor Green
} else {
    Write-Host "[WARN] gzip not found, skipping compression" -ForegroundColor Yellow
}

# Step 4: Transfer to server
Write-Host ""
Write-Host "[4/5] Transferring to server $TargetServer..." -ForegroundColor Yellow
scp $TarFile ${Username}@${TargetServer}:/tmp/
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Transfer failed" -ForegroundColor Red
    Write-Host "Make sure SSH access is configured: ssh ${Username}@${TargetServer}" -ForegroundColor Yellow
    exit 1
}
Write-Host "[OK] File transferred to /tmp/$TarFile" -ForegroundColor Green

# Step 5: Load image on server
Write-Host ""
Write-Host "[5/5] Loading image on server..." -ForegroundColor Yellow

if ($TarFile -like "*.gz") {
    $RemoteCommand = "gunzip -c /tmp/$TarFile | docker load && rm /tmp/$TarFile"
} else {
    $RemoteCommand = "docker load -i /tmp/$TarFile && rm /tmp/$TarFile"
}

ssh ${Username}@${TargetServer} $RemoteCommand
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Failed to load image on server" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Image loaded on server" -ForegroundColor Green

# Cleanup local tar
Write-Host ""
Write-Host "Cleaning up local files..." -ForegroundColor Yellow
Remove-Item $TarFile -ErrorAction SilentlyContinue
Remove-Item "vt-server-${ImageTag}.tar" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[SUCCESS] Image ready on server!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps on server:" -ForegroundColor Yellow
Write-Host "  ssh ${Username}@${TargetServer}" -ForegroundColor White
Write-Host "  cd /opt/vt-audit/deploy/04-agent-api" -ForegroundColor White
Write-Host "  docker compose up -d" -ForegroundColor White
