# VT-Agent Production Deployment Script
# This script deploys VT-Agent with mTLS authentication in production mode

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerURL,
    
    [Parameter(Mandatory=$true)]
    [string]$BootstrapToken,
    
    [string]$InstallPath = "C:\Program Files\VT-Agent",
    
    [string]$ServiceName = "VT-Agent",
    
    [switch]$TestMode = $false
)

# Security checks
if ($TestMode) {
    Write-Warning "⚠️  TEST MODE ENABLED - This will use insecure bypass authentication"
    Write-Warning "⚠️  DO NOT use -TestMode in production environments"
    $env:VT_AGENT_BYPASS_TOKEN = "test:test"
}

# Create installation directory
Write-Host "📁 Creating installation directory: $InstallPath"
New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null

# Copy files
Write-Host "📋 Copying VT-Agent files..."
Copy-Item "agent.exe" "$InstallPath\agent.exe" -Force
Copy-Item "agent.conf" "$InstallPath\agent.conf" -Force
Copy-Item "windows.yml" "$InstallPath\windows.yml" -Force

# Update configuration
Write-Host "⚙️  Updating agent configuration..."
$configPath = "$InstallPath\agent.conf"
$config = Get-Content $configPath -Raw

# Update server URL
$config = $config -replace "SERVER_URL=.*", "SERVER_URL=$ServerURL"

# Update bootstrap token  
$config = $config -replace "BOOTSTRAP_TOKEN=.*", "BOOTSTRAP_TOKEN=$BootstrapToken"

# Set production logging
$config = $config -replace "LOG_LEVEL=.*", "LOG_LEVEL=warn"

Set-Content $configPath $config -Encoding UTF8

# Create certificate directory
$certDir = "$InstallPath\data\certs"
Write-Host "🔐 Creating certificate directory: $certDir"
New-Item -ItemType Directory -Path $certDir -Force | Out-Null

# Set proper permissions (restrict access to SYSTEM and Administrators)
Write-Host "🔒 Setting secure file permissions..."
icacls $InstallPath /inheritance:d
icacls $InstallPath /grant:r "SYSTEM:(OI)(CI)F"
icacls $InstallPath /grant:r "Administrators:(OI)(CI)F"
icacls $InstallPath /remove "Users"
icacls $InstallPath /remove "Everyone"

# Stop existing service if running
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "🛑 Stopping existing service..."
    Stop-Service $ServiceName -Force
    sc.exe delete $ServiceName
    Start-Sleep 2
}

# Install as Windows service
Write-Host "🚀 Installing Windows service..."
$binPath = if ($TestMode) {
    # Test mode with bypass authentication
    "`"$InstallPath\agent.exe`" --service --skip-mtls"
} else {
    # Production mode with mTLS
    "`"$InstallPath\agent.exe`" --service"
}

$result = sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= "VT Compliance Agent"
if ($LASTEXITCODE -ne 0) {
    Write-Error "❌ Failed to create service"
    exit 1
}

# Set service description
sc.exe description $ServiceName "VT-Audit Compliance Agent - Automated Windows baseline security scanning"

# Set service recovery options
sc.exe failure $ServiceName reset= 60 actions= restart/30000/restart/30000/restart/30000

# Configure service to run as Local System (for system access)
sc.exe config $ServiceName obj= LocalSystem

Write-Host "✅ Service installed successfully"

# Test agent connectivity
Write-Host "🔍 Testing agent connectivity..."
$testCommand = if ($TestMode) {
    "& `"$InstallPath\agent.exe`" --once --skip-mtls"
} else {
    "& `"$InstallPath\agent.exe`" --once"
}

try {
    $output = Invoke-Expression $testCommand 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Agent connectivity test successful"
    } else {
        Write-Warning "⚠️  Agent connectivity test failed - check server configuration"
        Write-Host "Error output: $output"
    }
} catch {
    Write-Warning "⚠️  Could not test agent connectivity: $($_.Exception.Message)"
}

# Start the service
Write-Host "▶️  Starting VT-Agent service..."
Start-Service $ServiceName

# Verify service status
Start-Sleep 5
$service = Get-Service $ServiceName
if ($service.Status -eq "Running") {
    Write-Host "✅ VT-Agent service is running successfully"
} else {
    Write-Warning "⚠️  Service status: $($service.Status)"
}

# Display final information
Write-Host ""
Write-Host "🎉 VT-Agent Deployment Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Installation Summary:"
Write-Host "   • Installation Path: $InstallPath"
Write-Host "   • Service Name: $ServiceName"
Write-Host "   • Server URL: $ServerURL"
if ($TestMode) {
    Write-Host "   • Mode: TEST (Bypass Authentication)" -ForegroundColor Yellow
} else {
    Write-Host "   • Mode: PRODUCTION (mTLS Authentication)" -ForegroundColor Green
}
Write-Host ""
Write-Host "🔧 Management Commands:"
Write-Host "   • Start:   sc.exe start $ServiceName"
Write-Host "   • Stop:    sc.exe stop $ServiceName"
Write-Host "   • Status:  sc.exe query $ServiceName"
Write-Host "   • Logs:    Get-Content `"$InstallPath\agent.log`" -Tail 20"
Write-Host ""
Write-Host "🔐 Security Notes:"
if (-not $TestMode) {
    Write-Host "   • Agent uses mTLS certificates for authentication"
    Write-Host "   • Certificates auto-enroll on first connection"  
    Write-Host "   • Check certificate status: ls `"$InstallPath\data\certs`""
}
Write-Host "   • Agent runs as Local System account"
Write-Host "   • Installation directory secured to Administrators only"
Write-Host ""