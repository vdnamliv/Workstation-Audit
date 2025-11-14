# VT-Audit Deployment Scripts

This directory contains all necessary files and scripts for deploying the VT-Audit system in a High Availability (HA) configuration across 8 VMs.

## 📁 Directory Contents

### Environment Templates
- **`.env.admin`** - Environment variables for Admin API VMs (.49, .50)
- **`.env.agent`** - Environment variables for Agent API VMs (.47, .48)
- **`.env.proxy`** - Environment variables for Reverse Proxy VMs (.45, .46)

### Deployment Scripts
- **`deploy-admin.sh`** - Automated deployment script for Admin VMs
- **`deploy-agent.sh`** - Automated deployment script for Agent VMs
- **`deploy-proxy.sh`** - Automated deployment script for Proxy VMs

### Documentation
- **`DEPLOYMENT_GUIDE.md`** - Complete step-by-step deployment guide with prerequisites
- **`QUICK_REFERENCE.md`** - Quick reference cheat sheet for common operations

## 🎯 Quick Start

### 1. Review Prerequisites
Read `DEPLOYMENT_GUIDE.md` sections on:
- Installing Docker and prerequisites on all VMs
- Setting up PostgreSQL HA (VMs .52, .53)
- Configuring NFS for shared storage
- Setting up Keepalived for VIPs

### 2. Configure Environment Files

Copy and customize the `.env.*` templates:

```bash
# For Admin VMs
cp .env.admin /opt/vt-audit/.env
vi /opt/vt-audit/.env  # Update passwords and secrets

# For Agent VMs
cp .env.agent /opt/vt-audit/.env
vi /opt/vt-audit/.env  # Update passwords and secrets

# For Proxy VMs
cp .env.proxy /opt/vt-audit/.env
vi /opt/vt-audit/.env  # Update passwords and secrets
```

**CRITICAL:** Update all passwords and secrets before deployment!

### 3. Run Deployment Scripts

```bash
# Make scripts executable
chmod +x deploy-*.sh

# Deploy in this order:
# 1. Admin VMs (.49, .50)
./deploy-admin.sh

# 2. Agent VMs (.47 first, then .48)
./deploy-agent.sh

# 3. Proxy VMs (.45, .46)
./deploy-proxy.sh
```

## 🔐 Security Notes

**Before deploying to production:**

1. **Update all passwords** in `.env.*` files:
   - `POSTGRES_PASSWORD`
   - `KEYCLOAK_ADMIN_PASSWORD`
   - `KEYCLOAK_DB_PASSWORD`
   - `STEPCA_PASSWORD`
   - `STEPCA_PROVISIONER_PASSWORD`
   - `OIDC_CLIENT_SECRET`
   - `OIDC_COOKIE_SECRET`
   - `AGENT_BOOTSTRAP_TOKEN`

2. **Generate strong secrets:**
   ```bash
   # For OIDC_COOKIE_SECRET (32 chars base64)
   openssl rand -base64 32
   
   # For AGENT_BOOTSTRAP_TOKEN
   openssl rand -hex 32
   ```

3. **Use proper SSL certificates** (not self-signed)
4. **Restrict firewall rules** to specific IPs only
5. **Enable SELinux** with proper policies

## 📋 Deployment Checklist

- [ ] All 8 VMs have Docker and Docker Compose installed
- [ ] PostgreSQL HA configured on .52/.53 with VIP 10.221.130.51
- [ ] NFS server set up on .47 and mounted on clients
- [ ] Keepalived configured on proxy VMs with VIP 10.221.130.44
- [ ] Firewall rules configured per DEPLOYMENT_GUIDE.md
- [ ] All `.env` files updated with strong passwords
- [ ] Network connectivity tested between all VMs
- [ ] Deployment scripts copied to all VMs
- [ ] Admin VMs deployed and tested
- [ ] Agent VMs deployed (StepCA initialized)
- [ ] Proxy VMs deployed and tested
- [ ] VIPs verified on correct VMs
- [ ] End-to-end testing completed

## 🔍 Verification

After deployment, verify the system:

```bash
# Check VIPs
ip a | grep 10.221.130.44  # On .45
ip a | grep 10.221.130.51  # On .52

# Test services
curl -k https://10.221.130.44/
curl -k https://10.221.130.44/auth/
psql -h 10.221.130.51 -U vtaudit -d vtaudit
```

## 📊 Architecture Summary

```
External Users
     ↓
10.221.130.44 (VIP - Proxy)
     ↓
[Nginx + OIDC] .45, .46
     ↓
┌────────────────┬────────────────┐
│                │                │
Admin APIs      Agent APIs    Database
.49, .50        .47, .48       VIP 10.221.130.51
│                │                │
Keycloak        StepCA         [PostgreSQL]
Admin API       Agent API       .52, .53
                Enroll GW
```

## 🆘 Troubleshooting

If deployment fails:

1. Check logs:
   ```bash
   docker compose logs -f
   journalctl -u keepalived -f
   tail -f /var/log/postgresql/postgresql-*.log
   ```

2. Verify connectivity:
   ```bash
   telnet <target_ip> <port>
   ping <target_ip>
   ```

3. Check firewall:
   ```bash
   firewall-cmd --list-all
   ```

4. Consult `DEPLOYMENT_GUIDE.md` troubleshooting section

## 📞 Support

For detailed instructions and troubleshooting:
- Read `DEPLOYMENT_GUIDE.md` for complete setup procedures
- Check `QUICK_REFERENCE.md` for common operations
- Review `../RUNBOOK.md` for architecture details

## 📝 File Locations on VMs

After deployment, files will be at:
- **Project directory:** `/opt/vt-audit/`
- **Docker compose files:** `/opt/vt-audit/docker-compose.*.yml`
- **Environment file:** `/opt/vt-audit/.env`
- **Configuration:** `/opt/vt-audit/conf/`
- **NFS mounts:** `/mnt/stepca`, `/mnt/nginx_certs`

## 🔄 Updates and Maintenance

To update the system:

```bash
cd /opt/vt-audit
docker compose pull
docker compose down
docker compose up -d
```

To backup:
```bash
# Database backup (on .52)
sudo -u postgres pg_dump vtaudit > vtaudit_backup.sql

# Certificate backup (on .47)
tar -czf stepca_backup.tar.gz /shared/stepca/
tar -czf nginx_backup.tar.gz /shared/nginx_certs/
```

## 📄 License

Internal use only - Viettel Corporation
```
