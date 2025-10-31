# Agent Management

Comprehensive guide for managing VT-Audit Windows agents.

## 🏗️ Agent Architecture

VT-Audit agent là Windows service chạy compliance audits và communicate với central server thông qua mTLS authentication.

### Agent Components

```
┌─────────────────────────────────────────────────────────┐
│                    VT-Agent Service                     │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐  │
│  │   Policy    │ │  Audit      │ │   Report        │  │
│  │  Fetcher    │ │  Engine     │ │  Submission     │  │
│  └─────────────┘ └─────────────┘ └─────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────┐ ┌───────────────────────────────┐  │
│  │  Certificate    │ │      Configuration           │  │
│  │  Manager        │ │      Manager                 │  │
│  └─────────────────┘ └───────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Agent Deployment

### Prerequisites

```powershell
# Check system requirements
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion
$PSVersionTable.PSVersion  # Requires 5.1+
Test-NetConnection -ComputerName "your-server" -Port 8443
```

### Installation Methods

#### Method 1: Automatic Installation (Recommended)

```powershell
# Download agent
Invoke-WebRequest -Uri "https://your-server/agent.exe" -OutFile "agent.exe"

# Run as Administrator
# Install với automatic mTLS enrollment
.\agent.exe --server https://your-server:8443 --install

# Start service
Start-Service VT-Agent
```

#### Method 2: Manual Installation

```powershell
# Create program directory
$agentPath = "C:\Program Files\VT-Agent"
New-Item -Path $agentPath -ItemType Directory -Force

# Copy agent executable
Copy-Item "agent.exe" "$agentPath\agent.exe"

# Create configuration
@"
[server]
url = https://your-server:8443/agent
polling_interval = 600

[security]
mtls_enabled = true
verify_server_cert = true

[logging]
level = info
file_path = C:\ProgramData\VT-Agent\logs\agent.log
"@ | Out-File "$agentPath\agent.conf" -Encoding UTF8

# Install service
sc.exe create VT-Agent binPath="$agentPath\agent.exe --service" start=auto DisplayName="VT Compliance Agent"
```

#### Method 3: Group Policy Deployment

```powershell
# GPO startup script (distribute\Deploy-VTAgent.ps1)
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,
    
    [string]$InstallPath = "C:\Program Files\VT-Agent",
    
    [switch]$Force
)

# Download latest agent
$agentUrl = "$ServerUrl/downloads/agent.exe"
$tempPath = "$env:TEMP\vt-agent.exe"

try {
    Invoke-WebRequest -Uri $agentUrl -OutFile $tempPath -UseBasicParsing
    
    # Install agent
    New-Item -Path $InstallPath -ItemType Directory -Force
    Copy-Item $tempPath $InstallPath\agent.exe -Force
    
    # Configure và install service
    & "$InstallPath\agent.exe" --server $ServerUrl --install --force:$Force
    
    # Start service
    Start-Service VT-Agent -ErrorAction SilentlyContinue
    
    Write-EventLog -LogName Application -Source "VT-Agent-Deployment" -EventId 1000 -Message "VT-Agent deployed successfully to $env:COMPUTERNAME"
}
catch {
    Write-EventLog -LogName Application -Source "VT-Agent-Deployment" -EventId 1001 -EntryType Error -Message "Failed to deploy VT-Agent: $_"
}
```

## ⚙️ Agent Configuration

### Configuration File (agent.conf)

```ini
# VT-Agent Configuration File

[server]
# Server endpoint URL
url = https://gateway.company.com:8443/agent

# Polling interval in seconds (server can override)
polling_interval = 600

# Connection timeout
timeout = 30

[security]
# Enable mTLS authentication
mtls_enabled = true

# Certificate paths (auto-managed)
certificate_path = %PROGRAMDATA%\VT-Agent\certs\client.crt
private_key_path = %PROGRAMDATA%\VT-Agent\certs\client.key
ca_certificate_path = %PROGRAMDATA%\VT-Agent\certs\ca.crt

# Server certificate verification
verify_server_cert = true

# Skip certificate verification (development only)
skip_tls_verify = false

[enrollment]
# Enrollment gateway URL
enroll_gateway_url = https://gateway.company.com:8443/api/enroll

# Step-CA URL
step_ca_url = https://gateway.company.com:8443/step-ca

# Certificate lifetime
certificate_ttl = 24h

# Renewal threshold (renew when < 1 hour remaining)
renewal_threshold = 1h

[logging]
# Log level: debug, info, warn, error
level = info

# Log file path
file_path = C:\ProgramData\VT-Agent\logs\agent.log

# Maximum log file size (MB)
max_size = 10

# Number of log files to keep
max_backups = 5

# Days to keep log files
max_age = 30

[audit]
# Enable HTML report generation
enable_html_reports = true

# Enable JSON report generation  
enable_json_reports = false

# Enable Excel report generation
enable_excel_reports = false

# Local report directory
report_directory = C:\ProgramData\VT-Agent\reports

[cache]
# Policy cache file
policy_cache_path = C:\ProgramData\VT-Agent\data\policy_cache.json

# Cache validity (minutes)
cache_validity = 60

[service]
# Service health check interval (seconds)
health_check_interval = 300

# Maximum consecutive failures before restart
max_failures = 5
```

### Environment Variables

```powershell
# Set environment variables for agent
[System.Environment]::SetEnvironmentVariable("VT_AGENT_SERVER", "https://gateway.company.com:8443", "Machine")
[System.Environment]::SetEnvironmentVariable("VT_AGENT_LOG_LEVEL", "info", "Machine")
[System.Environment]::SetEnvironmentVariable("VT_AGENT_SKIP_MTLS", "false", "Machine")

# For development/testing
[System.Environment]::SetEnvironmentVariable("VT_AGENT_FORCE_BYPASS", "true", "User")
```

## 🎯 Agent Operation Modes

### 1. Local Mode

Fetch policy và run audit locally, không submit results:

```powershell
# Basic local audit
.\agent.exe --local

# Local audit với HTML report
.\agent.exe --local --html

# Local audit với custom server
.\agent.exe --local --html --server https://test-server:8443
```

**Use Cases:**
- Testing compliance rules
- Offline auditing
- Policy validation
- Development và debugging

### 2. Once Mode

Fetch policy, run audit once, submit results:

```powershell
# Single audit với mTLS
.\agent.exe --once

# Single audit với bypass authentication
.\agent.exe --once --skip-mtls

# Single audit với custom server
.\agent.exe --once --server https://production-server:8443
```

**Use Cases:**
- Manual compliance checks
- Scheduled task execution
- Testing server connectivity
- One-time audits

### 3. Service Mode

Continuous operation như Windows service:

```powershell
# Install và run as service
.\agent.exe --install
Start-Service VT-Agent

# Check service status
Get-Service VT-Agent

# View service logs
Get-EventLog -LogName Application -Source "VT-Agent" -Newest 10
```

**Use Cases:**
- Production deployment
- Automated compliance monitoring
- Centralized management
- Continuous auditing

## 🔧 Agent Management

### Service Management

```powershell
# Service control commands
Start-Service VT-Agent
Stop-Service VT-Agent
Restart-Service VT-Agent

# Service status
Get-Service VT-Agent | Format-Table Name, Status, StartType

# Service configuration
Get-WmiObject -Class Win32_Service -Filter "Name='VT-Agent'" | 
  Format-List Name, DisplayName, StartMode, State, ProcessId
```

### Certificate Management

```powershell
# Check certificate status
.\agent.exe --check-cert

# Force certificate renewal
.\agent.exe --renew-cert

# Reset certificates (will auto re-enroll)
.\agent.exe --reset-cert

# Manual certificate cleanup
Remove-Item "$env:PROGRAMDATA\VT-Agent\certs\*" -Force -Recurse
```

### Health Monitoring

```powershell
# Agent health check
.\agent.exe --health-check

# Service health monitoring script
function Test-VTAgentHealth {
    $service = Get-Service -Name "VT-Agent" -ErrorAction SilentlyContinue
    
    if ($service -eq $null) {
        Write-Warning "VT-Agent service not found"
        return $false
    }
    
    if ($service.Status -ne "Running") {
        Write-Warning "VT-Agent service not running: $($service.Status)"
        return $false
    }
    
    # Check certificate expiration
    $certInfo = & "C:\Program Files\VT-Agent\agent.exe" --check-cert --json | ConvertFrom-Json
    if ($certInfo.expires_in_hours -lt 2) {
        Write-Warning "Certificate expires in $($certInfo.expires_in_hours) hours"
        return $false
    }
    
    Write-Host "VT-Agent service healthy"
    return $true
}
```

### Log Management

```powershell
# View recent logs
Get-Content "C:\ProgramData\VT-Agent\logs\agent.log" -Tail 50

# Search for errors
Select-String -Path "C:\ProgramData\VT-Agent\logs\agent.log" -Pattern "ERROR|WARN"

# Log rotation (if not automatic)
function Rotate-VTAgentLogs {
    $logPath = "C:\ProgramData\VT-Agent\logs\agent.log"
    $backupPath = "C:\ProgramData\VT-Agent\logs\agent-$(Get-Date -Format 'yyyyMMdd').log"
    
    if (Test-Path $logPath) {
        if ((Get-Item $logPath).Length -gt 10MB) {
            Move-Item $logPath $backupPath
            New-Item $logPath -ItemType File
        }
    }
}
```

## 📊 Fleet Management

### Bulk Deployment Script

```powershell
# deploy-to-fleet.ps1
param(
    [Parameter(Mandatory=$true)]
    [string[]]$ComputerNames,
    
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,
    
    [PSCredential]$Credential
)

foreach ($computer in $ComputerNames) {
    try {
        Write-Host "Deploying to $computer..."
        
        $session = New-PSSession -ComputerName $computer -Credential $Credential
        
        # Copy agent to remote machine
        Copy-Item -Path "agent.exe" -Destination "C:\temp\agent.exe" -ToSession $session
        
        # Install agent remotely
        Invoke-Command -Session $session -ScriptBlock {
            param($serverUrl)
            
            & "C:\temp\agent.exe" --server $serverUrl --install
            Start-Service VT-Agent
            
        } -ArgumentList $ServerUrl
        
        Remove-PSSession $session
        Write-Host "✅ Successfully deployed to $computer"
        
    } catch {
        Write-Error "❌ Failed to deploy to $computer`: $_"
    }
}
```

### Fleet Status Monitoring

```powershell
# check-fleet-status.ps1
param(
    [string[]]$ComputerNames = @(),
    [PSCredential]$Credential
)

$results = foreach ($computer in $ComputerNames) {
    try {
        $session = New-PSSession -ComputerName $computer -Credential $Credential -ErrorAction Stop
        
        $status = Invoke-Command -Session $session -ScriptBlock {
            $service = Get-Service -Name "VT-Agent" -ErrorAction SilentlyContinue
            $lastSeen = (Get-EventLog -LogName Application -Source "VT-Agent" -Newest 1 -ErrorAction SilentlyContinue).TimeGenerated
            
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                ServiceStatus = if ($service) { $service.Status } else { "Not Installed" }
                LastSeen = $lastSeen
                CertificateExpiry = $null  # Could add certificate check here
            }
        }
        
        Remove-PSSession $session
        $status
        
    } catch {
        [PSCustomObject]@{
            ComputerName = $computer
            ServiceStatus = "Connection Failed"
            LastSeen = $null
            Error = $_.Exception.Message
        }
    }
}

# Display results
$results | Format-Table -AutoSize

# Export to CSV
$results | Export-Csv -Path "fleet-status-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```

## 🔍 Troubleshooting Agent Issues

### Common Issues

#### Agent Service Won't Start

```powershell
# Check service configuration
sc.exe qc VT-Agent

# Check service dependencies
Get-Service VT-Agent | Select-Object -ExpandProperty RequiredServices

# Check event logs
Get-EventLog -LogName System -Source "Service Control Manager" | 
    Where-Object {$_.Message -like "*VT-Agent*"} | 
    Select-Object TimeGenerated, EntryType, Message
```

#### Certificate Issues

```powershell
# Diagnostic script
function Test-VTAgentCertificate {
    $certPath = "$env:PROGRAMDATA\VT-Agent\certs\client.crt"
    
    if (-not (Test-Path $certPath)) {
        Write-Warning "Certificate not found at $certPath"
        return $false
    }
    
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certPath
        $timeUntilExpiry = $cert.NotAfter - (Get-Date)
        
        Write-Host "Certificate Subject: $($cert.Subject)"
        Write-Host "Certificate Issuer: $($cert.Issuer)"
        Write-Host "Valid From: $($cert.NotBefore)"
        Write-Host "Valid Until: $($cert.NotAfter)"
        Write-Host "Time Until Expiry: $($timeUntilExpiry.Days) days, $($timeUntilExpiry.Hours) hours"
        
        if ($timeUntilExpiry.TotalHours -lt 1) {
            Write-Warning "Certificate expires soon!"
            return $false
        }
        
        return $true
        
    } catch {
        Write-Error "Failed to read certificate: $_"
        return $false
    }
}
```

### Performance Optimization

```powershell
# Agent performance monitoring
function Monitor-VTAgentPerformance {
    $processName = "agent"
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    
    if ($process) {
        [PSCustomObject]@{
            ProcessId = $process.Id
            CPUPercent = (Get-Counter "\Process($processName)\% Processor Time").CounterSamples[0].CookedValue
            MemoryMB = [Math]::Round($process.WorkingSet64 / 1MB, 2)
            HandleCount = $process.HandleCount
            ThreadCount = $process.Threads.Count
        }
    } else {
        Write-Warning "VT-Agent process not found"
    }
}
```

## 📋 Maintenance Tasks

### Scheduled Maintenance

```powershell
# Create scheduled task for agent maintenance
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\VT-Agent-Maintenance.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1)

Register-ScheduledTask -TaskName "VT-Agent Maintenance" -Action $action -Trigger $trigger -Principal $principal -Settings $settings
```

### Maintenance Script

```powershell
# VT-Agent-Maintenance.ps1
try {
    # Check service health
    $service = Get-Service -Name "VT-Agent"
    if ($service.Status -ne "Running") {
        Start-Service VT-Agent
        Start-Sleep 30
    }
    
    # Check certificate expiration
    $certCheck = & "C:\Program Files\VT-Agent\agent.exe" --check-cert --json | ConvertFrom-Json
    if ($certCheck.expires_in_hours -lt 4) {
        & "C:\Program Files\VT-Agent\agent.exe" --renew-cert
    }
    
    # Rotate logs if needed
    $logFile = "C:\ProgramData\VT-Agent\logs\agent.log"
    if ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -gt 50MB) {
        Rotate-VTAgentLogs
    }
    
    # Clean old reports
    Get-ChildItem "C:\ProgramData\VT-Agent\reports" -File | 
        Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-30)} |
        Remove-Item -Force
    
    Write-EventLog -LogName Application -Source "VT-Agent" -EventId 2000 -Message "Maintenance completed successfully"
    
} catch {
    Write-EventLog -LogName Application -Source "VT-Agent" -EventId 2001 -EntryType Error -Message "Maintenance failed: $_"
}
```

## 📞 Support

For agent-specific issues:
- Check [Troubleshooting Guide](Troubleshooting.md)  
- Review agent logs: `C:\ProgramData\VT-Agent\logs\agent.log`
- Use debug mode: `.\agent.exe --once --debug`
- Create GitHub Issue with agent logs và system information