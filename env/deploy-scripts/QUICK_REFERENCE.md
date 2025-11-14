# VT-Audit Deployment Quick Reference

## 🎯 Deployment Order

1. **Database HA** (.52, .53) → PostgreSQL + Keepalived
2. **NFS Setup** (.47 as server) → StepCA & Nginx certs
3. **Proxy HA** (.45, .46) → Keepalived VIP
4. **Agent APIs** (.47, .48) → StepCA, api-agent, enroll-gateway
5. **Admin APIs** (.49, .50) → Keycloak, api-backend
6. **Proxy Services** (.45, .46) → Nginx, OIDC-proxy

## 📋 Pre-Deployment Checklist

### All VMs
- [ ] Docker installed and running
- [ ] Docker Compose plugin installed
- [ ] Firewall rules configured
- [ ] Network connectivity tested

### Database VMs (.52, .53)
- [ ] PostgreSQL 16 installed
- [ ] Replication configured
- [ ] Keepalived configured
- [ ] VIP 10.221.130.51 assigned to primary

### NFS Server (.47)
- [ ] NFS server running
- [ ] /shared/stepca exported
- [ ] /shared/nginx_certs exported

### NFS Clients
- [ ] .48: /mnt/stepca mounted
- [ ] .45, .46: /mnt/nginx_certs mounted

### Proxy VMs (.45, .46)
- [ ] Keepalived configured
- [ ] VIP 10.221.130.44 assigned to primary

## 🚀 Quick Deploy Commands

### Admin VMs (.49, .50)
```bash
cd /opt/vt-audit
docker compose -f docker-compose.admin.yml up -d
docker compose -f docker-compose.admin.yml ps
docker compose -f docker-compose.admin.yml logs -f
```

### Agent VMs (.47, .48)
```bash
# Deploy .47 FIRST (StepCA will initialize)
cd /opt/vt-audit
docker compose -f docker-compose.agent.yml up -d
docker compose -f docker-compose.agent.yml ps

# Wait for StepCA healthy, then deploy .48
```

### Proxy VMs (.45, .46)
```bash
# On .45 only - generate certs first time
cd /opt/vt-audit
docker compose -f docker-compose.proxy.yml run --rm nginx-certs

# Then start both .45 and .46
docker compose -f docker-compose.proxy.yml up -d
docker compose -f docker-compose.proxy.yml ps
```

## 🔍 Verification Commands

### Check VIPs
```bash
# Proxy VIP (should be on .45)
ip a | grep 10.221.130.44

# Database VIP (should be on .52)
ip a | grep 10.221.130.51
```

### Test Connectivity
```bash
# Database
psql -h 10.221.130.51 -U vtaudit -d vtaudit -c "SELECT version();"

# Keycloak
curl -k https://10.221.130.44/auth/realms/vt-audit

# Admin UI
curl -k https://10.221.130.44/

# StepCA
curl -k https://10.221.130.44:8443/step-ca/health
```

### Check Service Status
```bash
# On any VM with docker compose
docker compose ps
docker compose logs -f [service_name]

# Keycloak health
curl http://localhost:8080/health

# PostgreSQL replication (on .52)
sudo -u postgres psql -c "SELECT * FROM pg_stat_replication;"
```

## 🔧 Common Operations

### Restart Services
```bash
# Restart individual service
docker compose restart [service_name]

# Restart all services
docker compose down
docker compose up -d
```

### View Logs
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f keycloak
docker compose logs -f api-backend
```

### Update Configuration
```bash
# After changing .env or config files
docker compose down
docker compose up -d
```

## 🆘 Troubleshooting

### Service Won't Start
```bash
# Check logs
docker compose logs [service_name]

# Check container status
docker ps -a

# Inspect container
docker inspect [container_name]
```

### Database Connection Failed
```bash
# Test VIP reachability
telnet 10.221.130.51 5432

# Check Keepalived
systemctl status keepalived
ip a | grep 10.221.130.51

# Check PostgreSQL
systemctl status postgresql-16
```

### NFS Mount Issues
```bash
# Check mounts
df -h | grep -E 'stepca|nginx_certs'

# Remount
umount /mnt/stepca
mount -a

# Check NFS exports
showmount -e <NFS_SERVER_IP>
```

### Nginx Config Issues
```bash
# Test nginx config
docker exec vt-nginx nginx -t

# Reload nginx
docker exec vt-nginx nginx -s reload
```

## 📊 Monitoring

### Check Resource Usage
```bash
docker stats
docker compose top
```

### Check Disk Usage
```bash
docker system df
df -h
```

### Check Network
```bash
docker network ls
docker network inspect backend
```

## 🔐 Security Notes

**IMPORTANT: Before production deployment:**
1. Change all default passwords in .env files
2. Generate proper SSL certificates (not self-signed)
3. Restrict firewall rules to specific IPs only
4. Enable SELinux with proper policies
5. Set up monitoring and alerting
6. Configure automated backups
7. Review and harden all configurations

## 📞 Emergency Contacts

- System Administrator: _____________________
- Database Administrator: _____________________
- Network Team: _____________________
- Security Team: _____________________

## 📝 Important Ports

| Service | Port | Protocol | Notes |
|---------|------|----------|-------|
| Nginx (HTTPS) | 443 | TCP | Public access |
| Nginx (mTLS) | 8443 | TCP | Agent access |
| Keycloak | 8080 | TCP | Internal only |
| Admin API | 8081 | TCP | Internal only |
| Agent API | 8080 | TCP | Internal only |
| StepCA | 9000 | TCP | Internal only |
| Enroll Gateway | 8082 | TCP | Internal only |
| PostgreSQL | 5432 | TCP | Internal only |

## 🔄 Update Procedure

1. Stop services: `docker compose down`
2. Pull new images: `docker compose pull`
3. Update configs if needed
4. Start services: `docker compose up -d`
5. Verify: `docker compose ps`
6. Check logs: `docker compose logs -f`

## 📚 Related Documentation

- `DEPLOYMENT_GUIDE.md` - Full deployment guide
- `RUNBOOK.md` - Architecture and detailed procedures
- `deploy-admin.sh` - Admin deployment script
- `deploy-agent.sh` - Agent deployment script
- `deploy-proxy.sh` - Proxy deployment script
- `.env.admin` - Admin environment template
- `.env.agent` - Agent environment template
- `.env.proxy` - Proxy environment template
