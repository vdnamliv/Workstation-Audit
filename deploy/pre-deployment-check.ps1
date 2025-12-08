# Pre-Deployment Validation Script
# Checks configuration files and environment before deployment
# Usage: .\pre-deployment-check.ps1

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "VT-AUDIT Pre-Deployment Validator" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

$ErrorCount = 0
$WarningCount = 0

function Test-FileExists {
    param([string]$Path, [string]$Description)
    
    if (Test-Path $Path) {
        Write-Host "[OK] $Description exists" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[FAIL] $Description missing: $Path" -ForegroundColor Red
        $script:ErrorCount++
        return $false
    }
}

function Test-PasswordSecurity {
    param([string]$FilePath)
    
    if (Test-Path $FilePath) {
        $Content = Get-Content $FilePath -Raw
        
        # Check for default passwords
        $WeakPasswords = @("CHANGE_ME", "password", "admin", "123456", "ChangeMe")
        $FoundWeak = $false
        
        foreach ($Weak in $WeakPasswords) {
            if ($Content -match $Weak) {
                Write-Host "[WARN] Weak password found in $FilePath : $Weak" -ForegroundColor Yellow
                $script:WarningCount++
                $FoundWeak = $true
            }
        }
        
        if (-not $FoundWeak) {
            Write-Host "[OK] Password security check passed: $FilePath" -ForegroundColor Green
        }
    }
}

function Test-NetworkConfiguration {
    Write-Host "`n--- Network Configuration ---" -ForegroundColor Cyan
    
    # Check if production IPs are configured
    $UpstreamFile = "02-nginx-gateway\conf\conf.d\00-upstream.conf"
    
    if (Test-Path $UpstreamFile) {
        $Content = Get-Content $UpstreamFile -Raw
        
        if ($Content -match "vt-api-agent:8080|vt-api-backend:8081") {
            Write-Host "[WARN] Nginx still using local test configuration (container names)" -ForegroundColor Yellow
            Write-Host "    Run .\switch-to-production.ps1 to switch to production IPs" -ForegroundColor Yellow
            $script:WarningCount++
        } elseif ($Content -match "10\.211\.130\.\d+") {
            Write-Host "[OK] Nginx using production IPs" -ForegroundColor Green
        }
    }
}

function Test-CertificateFiles {
    Write-Host "`n--- SSL Certificate Check ---" -ForegroundColor Cyan
    
    $CertDir = "02-nginx-gateway\certs"
    
    if (Test-FileExists "$CertDir\server.crt" "SSL Certificate") {
        # Check if self-signed
        $CertContent = Get-Content "$CertDir\server.crt" -Raw
        if ($CertContent -match "CN=localhost" -or $CertContent -match "CN=vt-audit") {
            Write-Host "[WARN] Using self-signed certificate (OK for test, NOT for production)" -ForegroundColor Yellow
            $script:WarningCount++
        } else {
            Write-Host "[OK] SSL certificate appears to be properly signed" -ForegroundColor Green
        }
    }
    
    Test-FileExists "$CertDir\server.key" "SSL Private Key"
    
    # StepCA chain certificate
    if (Test-FileExists "$CertDir\stepca_chain.crt" "StepCA Chain Certificate") {
        Write-Host "[OK] mTLS certificate configured" -ForegroundColor Green
    } else {
        Write-Host "[WARN] StepCA chain missing - mTLS will not work" -ForegroundColor Yellow
        Write-Host "    Generate with: docker exec vt-stepca step ca roots > $CertDir\stepca_chain.crt" -ForegroundColor Yellow
        $script:WarningCount++
    }
}

function Test-DockerEnvironment {
    Write-Host "`n--- Docker Environment ---" -ForegroundColor Cyan
    
    # Check Docker is installed
    try {
        $DockerVersion = docker --version
        Write-Host "[OK] Docker installed: $DockerVersion" -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Docker not installed or not in PATH" -ForegroundColor Red
        $script:ErrorCount++
    }
    
    # Check Docker Compose
    try {
        $ComposeVersion = docker compose version
        Write-Host "[OK] Docker Compose installed: $ComposeVersion" -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Docker Compose not installed or not in PATH" -ForegroundColor Red
        $script:ErrorCount++
    }
    
    # Check if Docker daemon is running
    try {
        docker ps | Out-Null
        Write-Host "[OK] Docker daemon is running" -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Docker daemon is not running" -ForegroundColor Red
        $script:ErrorCount++
    }
}

function Test-EnvironmentFiles {
    Write-Host "`n--- Environment Files ---" -ForegroundColor Cyan
    
    $Components = @(
        @{Path="01-database\.env"; Name="Database"},
        @{Path="03-admin-api\.env"; Name="Admin API"},
        @{Path="04-agent-api\.env"; Name="Agent API"}
    )
    
    foreach ($Component in $Components) {
        if (Test-FileExists $Component.Path "$($Component.Name) .env file") {
            Test-PasswordSecurity $Component.Path
        }
    }
}

function Test-ProvisionerKey {
    Write-Host "`n--- StepCA Configuration ---" -ForegroundColor Cyan
    
    # Note: admin.jwk is no longer required as a separate file
    # The provisioner key is auto-generated inside StepCA's ca.json
    # and read directly from the StepCA volume
    
    Write-Host "[INFO] StepCA provisioner key will be auto-generated on first start" -ForegroundColor Cyan
    Write-Host "[INFO] Key is stored in /home/step/config/ca.json inside StepCA volume" -ForegroundColor Cyan
    
    # Check if StepCA container exists and verify ca.json
    try {
        $ContainerRunning = docker ps --format "{{.Names}}" | Select-String "vt-stepca"
        if ($ContainerRunning) {
            $CaJsonExists = docker exec vt-stepca test -f /home/step/config/ca.json 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[OK] StepCA ca.json exists (provisioner key inside)" -ForegroundColor Green
            } else {
                Write-Host "[WARN] StepCA ca.json not found - may need initialization" -ForegroundColor Yellow
                $script:WarningCount++
            }
        } else {
            Write-Host "[INFO] StepCA container not running (will be created during deployment)" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "[INFO] Cannot check StepCA container (deployment not started yet)" -ForegroundColor Cyan
    }
}

function Test-DatabaseInitScript {
    Write-Host "`n--- Database Configuration ---" -ForegroundColor Cyan
    
    $InitScript = "01-database\conf\init\01-init.sql"
    
    if (Test-FileExists $InitScript "Database initialization script") {
        $Content = Get-Content $InitScript -Raw
        
        # Check for proper GRANT ordering
        if ($Content -match "CREATE SCHEMA.*\n.*GRANT.*ON SCHEMA.*\n.*CREATE TABLE") {
            Write-Host "[OK] Database GRANT statements properly ordered" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Verify GRANT statement ordering in init script" -ForegroundColor Yellow
            $script:WarningCount++
        }
    }
}

# Run all checks
Write-Host "Starting validation checks...`n" -ForegroundColor White

Test-DockerEnvironment
Test-EnvironmentFiles
Test-NetworkConfiguration
Test-CertificateFiles
Test-ProvisionerKey
Test-DatabaseInitScript

# Summary
Write-Host "`n==================================" -ForegroundColor Cyan
Write-Host "Validation Summary" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

if ($ErrorCount -eq 0 -and $WarningCount -eq 0) {
    Write-Host "[SUCCESS] All checks passed! Ready for deployment." -ForegroundColor Green
} else {
    Write-Host "Errors: $ErrorCount" -ForegroundColor $(if ($ErrorCount -gt 0) {"Red"} else {"Green"})
    Write-Host "Warnings: $WarningCount" -ForegroundColor $(if ($WarningCount -gt 0) {"Yellow"} else {"Green"})
    
    if ($ErrorCount -gt 0) {
        Write-Host "`n[FAIL] Fix errors before deployment" -ForegroundColor Red
    } else {
        Write-Host "`n[WARN] Review warnings - deployment may proceed with caution" -ForegroundColor Yellow
    }
}

Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "1. Fix any errors listed above" -ForegroundColor White
Write-Host "2. Review warnings and update configurations" -ForegroundColor White
Write-Host "3. For production: Run .\switch-to-production.ps1" -ForegroundColor White
Write-Host "4. Follow deployment guide: PRODUCTION_DEPLOYMENT.md" -ForegroundColor White
