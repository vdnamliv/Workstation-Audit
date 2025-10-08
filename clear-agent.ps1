# Quick command to clear test agent data
# Usage: .\clear-agent.ps1

docker exec -it vt-postgres psql -U audit -d audit -c "DELETE FROM audit.results_flat WHERE agent_id = 'test-agent';"
Write-Host "Test agent data cleared!" -ForegroundColor Green