# Troubleshooting Guide

Comprehensive troubleshooting guide cho VT-Audit system issues.

## 🚨 Quick Diagnostic Commands

```bash
# Server health check
docker compose ps
curl -k https://localhost:443/health
curl -k https://localhost:8443/health  
curl -k https://localhost:8742/health

# Agent diagnostic
.\agent.exe --check-cert
.\agent.exe --skip-mtls --once --debug

# Service logs
docker logs vt-api-agent
docker logs vt-api-backend
docker logs vt-nginx
docker logs postgres
```

## 🔧 Agent Issues

### Agent Cannot Connect to Server

#### Symptoms
- Connection timeout errors
- "Server unreachable" messages
- Network connectivity failures

#### Diagnostic Steps

```bash
# Test network connectivity
ping your-server-domain.com
nslookup your-server-domain.com

# Test HTTPS connectivity
curl -k https://your-server:8443/health
Invoke-WebRequest -Uri "https://your-server:8443/health" -SkipCertificateCheck

# Test with bypass mode
.\agent.exe --skip-mtls --once --debug --server https://your-server:8443
```

#### Solutions

1. **Check Firewall Rules**
```powershell
# Windows Firewall
Get-NetFirewallRule -DisplayName "*VT-Agent*"
New-NetFirewallRule -DisplayName "VT-Agent HTTPS Out" -Direction Outbound -Protocol TCP -RemotePort 8443 -Action Allow

# Corporate Firewall
# Contact network team to allow outbound HTTPS to server ports 443, 8443, 8742
```

2. **Verify Server Configuration**
```bash
# Check server services
docker compose ps | grep -E "(nginx|api-agent|api-backend)"

# Test server endpoints
curl -k https://your-server:443/health    # Dashboard
curl -k https://your-server:8443/health   # Agent API  
curl -k https://your-server:8742/health   # Enrollment
```

3. **DNS Resolution Issues**
```powershell
# Add to hosts file if DNS issues
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "192.168.1.100 gateway.company.com"
```

### Certificate Authentication Failed  

#### Symptoms
- "mTLS handshake failed" errors
- "Certificate verification failed" 
- HTTP 401 authentication errors

#### Diagnostic Steps

```bash
# Check certificate status
.\agent.exe --check-cert

# Test certificate files exist
dir "%PROGRAMDATA%\VT-Agent\certs\"

# Test with bypass authentication
.\agent.exe --skip-mtls --once --debug
```

#### Solutions

1. **Certificate Enrollment Issues**
```bash
# Reset certificates và auto re-enroll
.\agent.exe --reset-cert

# Manual enrollment with debug
.\agent.exe --once --debug --server https://your-server:8443

# Check enrollment endpoint
curl -k https://your-server:8443/api/enroll -d '{"subject":"test"}'
```

2. **Certificate Expired**
```bash
# Force renewal
.\agent.exe --renew-cert

# If renewal fails, reset
.\agent.exe --reset-cert
```

3. **Certificate Permissions**
```powershell
# Fix certificate file permissions
$certDir = "$env:PROGRAMDATA\VT-Agent\certs"
icacls $certDir /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T
icacls $certDir /grant:r "BUILTIN\Administrators:(OI)(CI)F" /T
```

### Policy Fetch Failed

#### Symptoms
- "Policy download failed" errors
- Empty or outdated policy cache
- Agent runs với old policies

#### Diagnostic Steps

```bash
# Test policy endpoint
curl -k -H "X-Test-Mode: true" https://your-server:8443/agent/policies

# Check policy cache
type "%PROGRAMDATA%\VT-Agent\data\policy_cache.json"

# Test với debug logging
.\agent.exe --once --debug --log-level debug
```

#### Solutions

1. **Server API Issues**
```bash
# Check API server logs
docker logs vt-api-agent

# Test database connectivity
docker exec postgres psql -U vtaudit -d vtaudit -c "SELECT COUNT(*) FROM audit.agents;"
```

2. **Authentication Fallback**
```bash
# Test với X-Test-Mode header
curl -k -H "X-Test-Mode: true" -H "X-Agent-ID: $(hostname)" \
  https://your-server:8443/agent/policies
```

### Service Installation Failed

#### Symptoms
- "Service creation failed" errors
- Service won't start
- Permission denied errors

#### Solutions

1. **Run as Administrator**
```powershell
# Ensure PowerShell runs as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Run PowerShell as Administrator"
    exit 1
}
```

2. **Manual Service Installation**
```cmd
# Install service manually
sc.exe create VT-Agent binPath="C:\Program Files\VT-Agent\agent.exe --service" start=auto DisplayName="VT Compliance Agent"
sc.exe start VT-Agent

# Check service status
sc.exe query VT-Agent
```

3. **Service Permissions**
```powershell
# Grant service permissions
$servicePath = "C:\Program Files\VT-Agent"
New-Item -Path $servicePath -ItemType Directory -Force
icacls $servicePath /grant "NT AUTHORITY\LocalService:(OI)(CI)F" /T
```

## 🖥️ Server Issues

### Database Connection Failed

#### Symptoms
- "Database connection error"
- API returns 500 errors
- Cannot store audit results

#### Diagnostic Steps

```bash
# Check PostgreSQL container
docker logs postgres

# Test database connection
docker exec -it postgres psql -U vtaudit -d vtaudit

# Check database schema
docker exec postgres psql -U vtaudit -d vtaudit -c "\dt audit.*"
```

#### Solutions

1. **Database Container Issues**
```bash
# Restart database
docker restart postgres

# Check disk space
df -h

# Recreate database volume if corrupted
docker compose down -v
docker volume rm vt-audit_postgres_data
docker compose up -d
```

2. **Database Configuration**
```bash
# Check environment variables
docker exec postgres env | grep POSTGRES

# Verify database exists
docker exec postgres psql -U postgres -c "\l" | grep vtaudit
```

### Nginx Routing Issues

#### Symptoms
- HTTP 502/503 errors
- Incorrect request routing
- SSL/TLS errors

#### Diagnostic Steps

```bash
# Check nginx configuration
docker exec vt-nginx nginx -t

# Check nginx logs
docker logs vt-nginx

# Test upstream services
curl -k http://localhost:8080/health   # Backend API
curl -k http://localhost:8081/health   # Agent API
```

#### Solutions

1. **Nginx Configuration Fix**
```bash
# Reload nginx config
docker exec vt-nginx nginx -s reload

# Restart nginx if needed
docker restart vt-nginx
```

2. **Certificate Issues**
```bash
# Regenerate nginx certificates
cd env
./scripts/generate-mtls-assets.sh
./scripts/issue-nginx-cert.sh gateway.your-domain.com
docker restart vt-nginx
```

### Step-CA Issues

#### Symptoms
- Certificate enrollment failures
- "Step-CA unreachable" errors
- Certificate validation failures

#### Diagnostic Steps

```bash
# Check Step-CA container
docker logs stepca

# Test Step-CA health
curl -k https://localhost:8742/step-ca/health

# Check certificate authority
docker exec stepca step ca health
```

#### Solutions

1. **Step-CA Restart**
```bash
# Restart Step-CA container
docker restart stepca

# Recreate if persistent issues
docker compose down stepca
docker compose up -d stepca
```

2. **Certificate Authority Repair**
```bash
# Regenerate CA certificates
cd env/certs/stepca
rm -f *.crt *.key
../scripts/generate-step-ca-certs.sh
docker compose restart
```

## 🔐 Authentication & Authorization Issues

### Keycloak Authentication Failed

#### Symptoms
- Cannot login to dashboard
- "Invalid credentials" errors
- OIDC authentication failures

#### Solutions

1. **Check Keycloak Service**
```bash
# Check Keycloak container
docker logs keycloak

# Access Keycloak admin console
curl -k https://localhost:8443/auth/admin/
```

2. **Reset Admin Password**
```bash
# Reset Keycloak admin password
docker exec keycloak /opt/keycloak/bin/kcadm.sh config credentials \
  --server https://localhost:8443/auth --realm master --user admin

docker exec keycloak /opt/keycloak/bin/kcadm.sh update users/admin-user-id \
  -s enabled=true -s 'credentials=[{"type":"password","value":"newpassword","temporary":false}]'
```

### mTLS Authentication Issues

#### Symptoms
- Client certificate rejected
- "Certificate verification failed"
- Nginx mTLS errors

#### Solutions

See detailed [Certificate Management Guide](Certificate-Management.md) for mTLS troubleshooting.

## 📊 Performance Issues

### High CPU Usage

#### Investigation
```bash
# Check container resource usage
docker stats

# Check individual processes
docker exec vt-api-backend top
```

#### Solutions
```yaml
# Add resource limits to docker-compose.yml
services:
  api-backend:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
```

### High Memory Usage

#### Investigation
```bash
# Check memory usage
free -h
docker system df

# Check container memory
docker exec vt-api-backend cat /proc/meminfo
```

#### Solutions
```bash
# Clean up Docker resources
docker system prune -f
docker volume prune -f
docker image prune -a -f
```

### Database Performance

#### Investigation
```sql
-- Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC LIMIT 10;

-- Check database size
SELECT pg_size_pretty(pg_database_size('vtaudit'));
```

#### Solutions
```sql
-- Optimize database
VACUUM ANALYZE;
REINDEX DATABASE vtaudit;

-- Archive old data
DELETE FROM audit.check_results 
WHERE created_at < NOW() - INTERVAL '90 days';
```

## 🔍 Diagnostic Tools

### Log Analysis

```bash
# Centralized log collection
mkdir logs
docker logs vt-api-agent > logs/agent-api.log 2>&1
docker logs vt-api-backend > logs/backend-api.log 2>&1
docker logs vt-nginx > logs/nginx.log 2>&1
docker logs postgres > logs/postgres.log 2>&1

# Search for errors
grep -i error logs/*.log
grep -i "certificate" logs/*.log
grep -i "authentication" logs/*.log
```

### Network Debugging

```bash
# Port scanning
nmap -p 443,8443,8742 localhost

# Traffic monitoring
tcpdump -i any port 8443

# DNS resolution
dig gateway.company.com
nslookup gateway.company.com
```

### System Resource Monitoring

```bash
# System resources
htop
iotop
netstat -tulpn

# Docker resources
docker system df
docker stats --no-stream
```

## 📋 Support Information Collection

### Create Support Bundle

```bash
#!/bin/bash
# collect-support-info.sh

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BUNDLE_DIR="support_bundle_$TIMESTAMP"
mkdir -p $BUNDLE_DIR

# System information
uname -a > $BUNDLE_DIR/system_info.txt
docker --version >> $BUNDLE_DIR/system_info.txt
docker compose version >> $BUNDLE_DIR/system_info.txt

# Service status
docker compose ps > $BUNDLE_DIR/service_status.txt

# Configuration (sanitized)
cp env/.env $BUNDLE_DIR/env_config.txt
sed -i 's/PASSWORD=.*/PASSWORD=***REDACTED***/g' $BUNDLE_DIR/env_config.txt

# Logs (last 1000 lines)
docker logs --tail=1000 vt-api-agent > $BUNDLE_DIR/agent_api.log 2>&1
docker logs --tail=1000 vt-api-backend > $BUNDLE_DIR/backend_api.log 2>&1
docker logs --tail=1000 vt-nginx > $BUNDLE_DIR/nginx.log 2>&1
docker logs --tail=1000 postgres > $BUNDLE_DIR/postgres.log 2>&1

# Network information
ss -tulpn > $BUNDLE_DIR/network_ports.txt
curl -k https://localhost:443/health > $BUNDLE_DIR/health_checks.txt 2>&1
curl -k https://localhost:8443/health >> $BUNDLE_DIR/health_checks.txt 2>&1

# Create archive
tar -czf support_bundle_$TIMESTAMP.tar.gz $BUNDLE_DIR/
rm -rf $BUNDLE_DIR

echo "Support bundle created: support_bundle_$TIMESTAMP.tar.gz"
```

### Agent Support Information

```powershell
# collect-agent-info.ps1

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$bundleDir = "agent_support_$timestamp"
New-Item -Path $bundleDir -ItemType Directory -Force

# System information
Get-ComputerInfo | Out-File "$bundleDir\system_info.txt"
Get-Service VT-Agent | Out-File "$bundleDir\service_status.txt"

# Agent information
& .\agent.exe --check-cert > "$bundleDir\certificate_info.txt" 2>&1
& .\agent.exe --version > "$bundleDir\agent_version.txt" 2>&1

# Configuration
Copy-Item "distribute\agent.conf" "$bundleDir\agent_config.txt" -ErrorAction SilentlyContinue

# Event logs
Get-EventLog -LogName Application -Source "VT-Agent" -Newest 50 | 
  Out-File "$bundleDir\event_log.txt"

# Network connectivity
Test-NetConnection -ComputerName "your-server" -Port 8443 | 
  Out-File "$bundleDir\network_test.txt"

# Create archive
Compress-Archive -Path "$bundleDir\*" -DestinationPath "agent_support_$timestamp.zip"
Remove-Item -Path $bundleDir -Recurse -Force

Write-Output "Agent support bundle created: agent_support_$timestamp.zip"
```

## 🆘 Emergency Procedures

### Complete System Reset

```bash
# Emergency reset (CAUTION: Will lose all data)
docker compose down -v
docker system prune -a -f --volumes
git clean -fdx
git checkout main
cp env/.env.example env/.env
# Edit env/.env with fresh configuration
docker compose up -d
```

### Service Recovery

```bash
# Quick service recovery
docker compose restart

# Individual service restart
docker restart vt-api-agent
docker restart vt-api-backend
docker restart vt-nginx
docker restart postgres
```

## 📞 Getting Help

### Before Contacting Support

1. **Check this troubleshooting guide**
2. **Collect diagnostic information**
3. **Try bypass mode for agent issues**
4. **Check server logs for error messages**
5. **Verify network connectivity**

### Contact Methods

- **GitHub Issues**: [Create issue](https://github.com/vdnamliv/Workstation-Audit/issues) với detailed information
- **Documentation**: Check [Wiki pages](https://github.com/vdnamliv/Workstation-Audit/wiki) for additional guides
- **Community**: [GitHub Discussions](https://github.com/vdnamliv/Workstation-Audit/discussions) for questions

### Include in Support Requests

1. **System Information**: OS, Docker version, system resources  
2. **Error Messages**: Exact error messages và stack traces
3. **Configuration**: Sanitized configuration files (remove passwords)
4. **Logs**: Relevant log excerpts (not entire files)
5. **Steps to Reproduce**: Detailed reproduction steps
6. **Expected vs Actual**: What you expected vs what happened