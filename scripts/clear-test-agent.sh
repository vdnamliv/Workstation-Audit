#!/bin/bash
# WSL/Linux script to clear test agent data from database for demo purposes  
# Usage: ./clear-test-agent.sh

echo "🗑️ Clearing test agent data from database..."

# Clear from results_flat table (where test agent data is stored)
echo "Deleting from audit.results_flat..."
docker exec -it vt-postgres psql -U audit -d audit -c "DELETE FROM audit.results_flat WHERE agent_id = 'test-agent';"

# Check remaining count  
echo -e "\n📊 Checking remaining data..."
remaining=$(docker exec -it vt-postgres psql -U audit -d audit -c "SELECT COUNT(*) FROM audit.results_flat WHERE agent_id = 'test-agent';" | grep -o '[0-9]\+')
echo "Test agent records remaining: $remaining"

# Check total hosts now
echo -e "\n🏠 Total unique hosts in database:"
docker exec -it vt-postgres psql -U audit -d audit -c "WITH combined_results AS (SELECT hostname FROM audit.results_flat UNION ALL SELECT cr.hostname FROM audit.runs r JOIN audit.check_results cr ON r.run_id = cr.run_id) SELECT COUNT(DISTINCT hostname) as total_hosts FROM combined_results;"

echo -e "\n✅ Test agent data cleared! You can now run agent demo fresh."
echo -e "💡 Run: ./agent.exe --once --skip-mtls"