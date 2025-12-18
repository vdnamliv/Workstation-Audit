# ============================================
# COPY ASSETS TO CORRECT LOCATION
# ============================================
# Script này copy assets từ nginx về server/ui (nơi đúng)

Write-Host "=========================================="
Write-Host "MOVING ASSETS TO CORRECT LOCATION"
Write-Host "=========================================="

$sourceDir = "deploy\02-nginx-gateway\conf\html\assets"
$targetDir = "server\ui\assets"

Write-Host ""
Write-Host "[1/3] Copying CSS files..."
Copy-Item "$sourceDir\css\*" -Destination "$targetDir\css\" -Force
Write-Host "  - flowbite.min.css"

Write-Host ""
Write-Host "[2/3] Copying JS files..."
Copy-Item "$sourceDir\js\*" -Destination "$targetDir\js\" -Force
Write-Host "  - alpine.min.js"
Write-Host "  - flowbite.min.js"
Write-Host "  - tailwindcss.js"

Write-Host ""
Write-Host "[3/3] Verifying..."
Get-ChildItem -Path "$targetDir" -Recurse -File | ForEach-Object {
    $size = [math]::Round($_.Length / 1KB, 2)
    $relativePath = $_.FullName.Replace((Get-Location).Path + '\', '')
    Write-Host "  OK $relativePath ($size KB)"
}

Write-Host ""
Write-Host "=========================================="
Write-Host "SUCCESS!"
Write-Host "=========================================="
Write-Host "Assets are now in the correct location:"
Write-Host "  server/ui/assets/"
Write-Host ""
Write-Host "Admin API will serve:"
Write-Host "  https://10.211.130.44:9444/app/ -> HTML + Assets"
Write-Host "  https://10.211.130.44:9444/api/ -> API endpoints"
Write-Host ""
Write-Host "Nginx only does reverse proxy:"
Write-Host "  / -> admin-api:8081"
Write-Host ""
