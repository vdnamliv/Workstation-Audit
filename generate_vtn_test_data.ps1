param(
    [string]$Container = "vt-postgres",
    [string]$Database = "audit",
    [string]$Username = "audit",
    [int]$TotalHosts = 100
)

Write-Host "Starting VT-Audit realistic test data generation..." -ForegroundColor Green

# Read hostnames from file and generate more based on pattern
$baseHostnames = @(
    "VTN-NAMVD10", "VTN-NAMNB7", "VTN-KHANHCG", "VTN-HUYDVN", "VTN-HAUVV8", 
    "VTN-DUNGBV18", "VTN-TRUONGLV11", "VTN-VIETNT41", "VTN-TUANTA67", "VTN-NAMVD1", "VTN-NamVD2"
)

$hostnames = @()
$agents = @()

# Generate hostnames based on pattern
for ($i = 0; $i -lt $TotalHosts; $i++) {
    if ($i -lt $baseHostnames.Length) {
        $hostname = $baseHostnames[$i]
    } else {
        # Generate more hostnames by incrementing numbers in base patterns
        $baseIndex = $i % $baseHostnames.Length
        $baseHost = $baseHostnames[$baseIndex]
        
        # Extract pattern and increment number
        if ($baseHost -match '^(VTN-\w+?)(\d+)$') {
            $prefix = $matches[1]
            $number = [int]$matches[2] + ($i - $baseIndex)
            $hostname = "$prefix$number"
        } else {
            $hostname = "$baseHost$i"
        }
    }
    
    $agentId = [System.Guid]::NewGuid().ToString()
    $hostnames += $hostname
    $agents += @{
        agent_id = $agentId
        hostname = $hostname
    }
}

Write-Host "Generated $($hostnames.Count) VTN hostnames"

# Clear existing data
Write-Host "Clearing existing audit data..." -ForegroundColor Yellow
$clearSQL = @"
DELETE FROM audit.check_results;
DELETE FROM audit.runs;
DELETE FROM audit.agents;
"@

$clearSQL | docker exec -i $Container psql -U $Username -d $Database -q

# Create temporary SQL file
$tempFile = [System.IO.Path]::GetTempFileName() + ".sql"

# Generate SQL for agents
$sqlContent = @"
-- Insert agents
"@

foreach ($agent in $agents) {
    $sqlContent += @"

INSERT INTO audit.agents (agent_id, hostname, os, cert_cn, cert_serial, enrolled_at, last_seen)
VALUES ('$($agent.agent_id)', '$($agent.hostname)', 'windows', '$($agent.hostname).vtn.local', 'serial-$($agent.agent_id.Substring(0,8))', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '5 minutes');
"@
}

# Policy rules (24 rules total like real VT policy)
$policyRules = @(
    @{ id = "WN.00.01.01"; title = "Windows Firewall Domain Profile"; category = "Network Security" },
    @{ id = "WN.00.01.02"; title = "Windows Firewall Private Profile"; category = "Network Security" },
    @{ id = "WN.00.01.03"; title = "Windows Firewall Public Profile"; category = "Network Security" },
    @{ id = "WN.00.02.01"; title = "Account Lockout Duration"; category = "Account Policy" },
    @{ id = "WN.00.02.02"; title = "Account Lockout Threshold"; category = "Account Policy" },
    @{ id = "WN.00.02.03"; title = "Reset Account Lockout Counter"; category = "Account Policy" },
    @{ id = "WN.00.03.01"; title = "Password History"; category = "Password Policy" },
    @{ id = "WN.00.03.02"; title = "Maximum Password Age"; category = "Password Policy" },
    @{ id = "WN.00.03.03"; title = "Minimum Password Age"; category = "Password Policy" },
    @{ id = "WN.00.03.04"; title = "Minimum Password Length"; category = "Password Policy" },
    @{ id = "WN.00.03.05"; title = "Password Complexity"; category = "Password Policy" },
    @{ id = "WN.00.04.01"; title = "Interactive Logon Message Title"; category = "Security Options" },
    @{ id = "WN.00.04.02"; title = "Interactive Logon Message Text"; category = "Security Options" },
    @{ id = "WN.00.05.01"; title = "Windows Update Automatic Updates"; category = "System Services" },
    @{ id = "WN.00.05.02"; title = "Windows Defender Antivirus"; category = "System Services" },
    @{ id = "WN.00.06.01"; title = "User Rights - Log on as Service"; category = "User Rights" },
    @{ id = "WN.00.06.02"; title = "User Rights - Log on Locally"; category = "User Rights" },
    @{ id = "WN.00.07.01"; title = "Audit Account Logon Events"; category = "Audit Policy" },
    @{ id = "WN.00.07.02"; title = "Audit Account Management"; category = "Audit Policy" },
    @{ id = "WN.00.07.03"; title = "Audit Logon Events"; category = "Audit Policy" },
    @{ id = "WN.00.08.01"; title = "Registry Security Permissions"; category = "Registry Settings" },
    @{ id = "WN.00.08.02"; title = "File System Security"; category = "File System" },
    @{ id = "WN.00.09.01"; title = "Windows Defender Real-time Protection"; category = "Antivirus" },
    @{ id = "WN.00.09.02"; title = "Windows Defender Scan Schedule"; category = "Antivirus" }
)

# Generate runs and check results with realistic distribution
$sqlContent += @"

-- Insert runs and check results
"@

$processedCount = 0
foreach ($agent in $agents) {
    $processedCount++
    
    # Create a run for this agent
    $runId = [System.Guid]::NewGuid().ToString()
    $policyId = "win_baseline"
    
    # Determine performance tier and rule distribution
    if ($processedCount -le 60) {
        # 60 hosts first: 100% pass (all 24 rules pass)
        $passedRules = 24
        $failedRules = 0
    }
    elseif ($processedCount -le 90) {
        # Next 30 hosts: ~70% pass (17-18 pass, 6-7 fail)
        $passedRules = Get-Random -Minimum 16 -Maximum 19
        $failedRules = 24 - $passedRules
    }
    else {
        # Last 10 hosts: ~50% pass (11-13 pass, 11-13 fail)
        $passedRules = Get-Random -Minimum 11 -Maximum 14
        $failedRules = 24 - $passedRules
    }
    
    $timestamp = (Get-Date).AddMinutes(-$(Get-Random -Minimum 1 -Maximum 2880)).ToString("yyyy-MM-dd HH:mm:ss")
    
    # Insert run
    $sqlContent += @"

INSERT INTO audit.runs (run_id, agent_id, policy_id, policy_ver, received_at)
VALUES ('$runId', '$($agent.agent_id)', '$policyId', 2, '$timestamp');
"@
    
    # Shuffle rules for realistic pass/fail distribution
    $shuffledRules = $policyRules | Sort-Object { Get-Random }
    
    # Insert passed checks (first N rules)
    for ($j = 0; $j -lt $passedRules; $j++) {
        $rule = $shuffledRules[$j]
        $sqlContent += @"

INSERT INTO audit.check_results (run_id, agent_id, hostname, os, rule_id, rule_title, status, expected, reason)
VALUES ('$runId', '$($agent.agent_id)', '$($agent.hostname)', 'windows', '$($rule.id)', '$($rule.title)', 'PASS', 'compliant', 'Policy requirement met successfully');
"@
    }
    
    # Insert failed checks (remaining rules)
    for ($j = $passedRules; $j -lt 24; $j++) {
        $rule = $shuffledRules[$j]
        $reasons = @(
            "Configuration does not meet security requirements",
            "Policy setting is not configured",
            "Service is not running as required",
            "Registry value does not match expected setting",
            "Security permission is not properly configured",
            "Feature is disabled when it should be enabled"
        )
        $reason = $reasons | Get-Random
        
        $sqlContent += @"

INSERT INTO audit.check_results (run_id, agent_id, hostname, os, rule_id, rule_title, status, expected, reason, fix)
VALUES ('$runId', '$($agent.agent_id)', '$($agent.hostname)', 'windows', '$($rule.id)', '$($rule.title)', 'FAIL', 'compliant', '$reason', 'Review and update system configuration per security baseline');
"@
    }
    
    if ($processedCount % 10 -eq 0) {
        Write-Host "Processed $processedCount/$TotalHosts hosts"
    }
}

# Write SQL to file
$sqlContent | Out-File -FilePath $tempFile -Encoding UTF8

Write-Host "Inserting data into database..." -ForegroundColor Yellow
Get-Content $tempFile | docker exec -i $Container psql -U $Username -d $Database -q

# Clean up temp file
Remove-Item $tempFile -Force

Write-Host "Successfully inserted realistic test data!" -ForegroundColor Green

# Show statistics
Write-Host "`nDatabase Statistics:" -ForegroundColor Cyan
$statsSQL = @"
SELECT 
    COUNT(DISTINCT a.hostname) as total_hosts,
    AVG(CASE WHEN stats.failed_count = 0 THEN 100.0 ELSE (stats.passed_count::float / stats.total_count::float) * 100 END) as avg_pass_rate,
    COUNT(CASE WHEN stats.failed_count = 0 THEN 1 END) as perfect_hosts,
    COUNT(CASE WHEN (stats.passed_count::float / stats.total_count::float) >= 0.7 AND stats.failed_count > 0 THEN 1 END) as good_hosts,
    COUNT(CASE WHEN (stats.passed_count::float / stats.total_count::float) < 0.7 THEN 1 END) as poor_hosts
FROM audit.agents a
LEFT JOIN (
    SELECT 
        cr.agent_id,
        COUNT(*) as total_count,
        COUNT(CASE WHEN cr.status = 'PASS' THEN 1 END) as passed_count,
        COUNT(CASE WHEN cr.status = 'FAIL' THEN 1 END) as failed_count
    FROM audit.check_results cr
    GROUP BY cr.agent_id
) stats ON a.agent_id = stats.agent_id;
"@

$statsSQL | docker exec -i $Container psql -U $Username -d $Database -t

Write-Host "`nSample Data Check:" -ForegroundColor Cyan
$sampleSQL = @"
SELECT hostname, COUNT(*) as total_rules, 
       COUNT(CASE WHEN status = 'PASS' THEN 1 END) as passed,
       COUNT(CASE WHEN status = 'FAIL' THEN 1 END) as failed
FROM audit.check_results cr 
JOIN audit.agents a ON cr.agent_id = a.agent_id 
GROUP BY hostname 
ORDER BY hostname 
LIMIT 5;
"@

$sampleSQL | docker exec -i $Container psql -U $Username -d $Database

Write-Host "`nRealistic VTN test data generation completed!" -ForegroundColor Green
Write-Host "- All hosts have exactly 24 policy rules (matching real VT baseline)" -ForegroundColor White
Write-Host "- Hostnames follow VTN-* pattern from your file" -ForegroundColor White  
Write-Host "- Performance distribution: 60 perfect, 30 good, 10 poor hosts" -ForegroundColor White
Write-Host "You can now test the dashboard at: https://gateway.local/app/" -ForegroundColor Cyan