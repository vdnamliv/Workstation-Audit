# Script to clear test agent data from database for demo purposes
# Usage: .\clear-test-agent.ps1

Write-Host "Clearing test agent data from database..." -ForegroundColor Yellow

# Clear from results_flat table (where test agent data is stored)
Write-Host "Deleting from audit.results_flat..."
docker exec -it vt-postgres psql -U audit -d audit -c "DELETE FROM audit.results_flat WHERE agent_id = 'test-agent';"

# Check remaining count
Write-Host "`nChecking remaining data..."
$remaining = docker exec -it vt-postgres psql -U audit -d audit -c "SELECT COUNT(*) FROM audit.results_flat WHERE agent_id = 'test-agent';" | Select-String -Pattern "[0-9]+"
if ($remaining) {
    Write-Host "Test agent records remaining: $($remaining.Matches[0].Value)" -ForegroundColor Green
} else {
    Write-Host "Test agent records remaining: 0" -ForegroundColor Green
}

# Check total hosts now
Write-Host "`nTotal unique hosts in database:"
docker exec -it vt-postgres psql -U audit -d audit -c "WITH combined_results AS (SELECT hostname FROM audit.results_flat UNION ALL SELECT cr.hostname FROM audit.runs r JOIN audit.check_results cr ON r.run_id = cr.run_id) SELECT COUNT(DISTINCT hostname) as total_hosts FROM combined_results;"

Write-Host "`nTest agent data cleared! You can now run agent demo fresh." -ForegroundColor Green
Write-Host "Run: .\agent.exe --once --skip-mtls" -ForegroundColor Cyan