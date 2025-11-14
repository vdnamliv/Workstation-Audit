# VT-Audit High Availability Deployment Guide

This guide provides complete step-by-step instructions for deploying the VT-Audit system across 8 VMs with High Availability (HA) configuration.

## Architecture Overview

**VIP (Virtual IPs):**
- Proxy VIP: `10.221.130.44` (Active/Passive on .45/.46)
- Database VIP: `10.221.130.51` (Primary/Standby on .52/.53)

**VM Roles:**
- **Proxy VMs (.45, .46):** Nginx reverse proxy + OIDC authentication
- **Admin API VMs (.49, .50):** Keycloak + Admin backend API
- **Agent API VMs (.47, .48):** StepCA + Agent API + Enrollment gateway
- **Database VMs (.52, .53):** PostgreSQL with streaming replication

## Prerequisites (All VMs)

### 1. Base System Setup

Run on all 8 VMs:

```bash
# Update system
dnf update -y

# Install Docker
dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io
systemctl enable --now docker

# Install Docker Compose plugin
dnf install -y docker-compose-plugin

# Verify installation
docker --version
docker compose version

# Install Keepalived (for VMs that need VIP: .45, .46, .52, .53)
dnf install -y keepalived

# Install basic tools
dnf install -y vim net-tools bind-utils telnet
```

### 2. Firewall Configuration

#### Database VMs (.52, .53)

```bash
# Allow PostgreSQL from Admin and Agent VMs
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.49/32" port protocol="tcp" port="5432" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.50/32" port protocol="tcp" port="5432" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.47/32" port protocol="tcp" port="5432" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.48/32" port protocol="tcp" port="5432" accept'

# Allow VRRP for Keepalived
firewall-cmd --permanent --add-rich-rule='rule protocol value="vrrp" accept'

firewall-cmd --reload
```

#### Admin API VMs (.49, .50)

```bash
# Allow Keycloak (8080) and Admin API (8081) from Proxy VMs
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.45/32" port protocol="tcp" port="8080" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.45/32" port protocol="tcp" port="8081" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.46/32" port protocol="tcp" port="8080" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.46/32" port protocol="tcp" port="8081" accept'

firewall-cmd --reload
```

#### Agent API VMs (.47, .48)

```bash
# Allow StepCA (9000), Agent API (8080), Enrollment (8082) from Proxy VMs
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.45/32" port protocol="tcp" port="9000" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.45/32" port protocol="tcp" port="8080" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.45/32" port protocol="tcp" port="8082" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.46/32" port protocol="tcp" port="9000" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.46/32" port protocol="tcp" port="8080" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.46/32" port protocol="tcp" port="8082" accept'

# Allow NFS if this VM is NFS server (example: .47)
firewall-cmd --permanent --add-service=nfs
firewall-cmd --permanent --add-service=rpc-bind
firewall-cmd --permanent --add-service=mountd

firewall-cmd --reload
```

#### Proxy VMs (.45, .46)

```bash
# Allow HTTP/HTTPS from external clients
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --permanent --add-port=8443/tcp

# Allow VRRP for Keepalived
firewall-cmd --permanent --add-rich-rule='rule protocol value="vrrp" accept'

firewall-cmd --reload
```

---

## PHASE 1: Database HA Setup (VMs .52, .53)

### Step 1: Install PostgreSQL (Both VMs)

```bash
# Install PostgreSQL 16
dnf install -y postgresql16-server postgresql16

# Initialize database (only on .52 initially)
/usr/pgsql-16/bin/postgresql-16-setup initdb

# Enable and start (on .52 only for now)
systemctl enable postgresql-16
systemctl start postgresql-16
```

### Step 2: Configure Primary Database (.52)

```bash
# Edit postgresql.conf
vi /var/lib/pgsql/16/data/postgresql.conf

# Add/modify these settings:
listen_addresses = '*'
wal_level = replica
max_wal_senders = 10
wal_keep_size = 512MB
hot_standby = on
```

```bash
# Edit pg_hba.conf
vi /var/lib/pgsql/16/data/pg_hba.conf

# Add these lines at the end:
# Allow replication from standby
host    replication     replicator      10.221.130.53/32        scram-sha-256

# Allow application connections from Admin and Agent VMs
host    all             all             10.211.130.49/32        scram-sha-256
host    all             all             10.211.130.50/32        scram-sha-256
host    all             all             10.211.130.47/32        scram-sha-256
host    all             all             10.211.130.48/32        scram-sha-256
```

```bash
# Create replication user and application databases
sudo -u postgres psql << EOF
CREATE USER replicator WITH REPLICATION PASSWORD 'MyReplicationPass123';
CREATE USER vtaudit WITH PASSWORD 'YourSecurePassword123';
CREATE DATABASE vtaudit OWNER vtaudit;
CREATE USER keycloak WITH PASSWORD 'KeycloakPassword123';
CREATE DATABASE keycloak OWNER keycloak;
EOF

# Restart PostgreSQL
systemctl restart postgresql-16
```

### Step 3: Configure Standby Database (.53)

```bash
# Stop PostgreSQL if running
systemctl stop postgresql-16

# Remove existing data
rm -rf /var/lib/pgsql/16/data/*

# Backup from primary
sudo -u postgres PGPASSWORD='MyReplicationPass123' pg_basebackup \
  -h 10.221.130.52 \
  -U replicator \
  -p 5432 \
  -D /var/lib/pgsql/16/data/ \
  -Fp -Xs -R

# Start standby
systemctl start postgresql-16

# Verify replication status (on primary .52)
sudo -u postgres psql -c "SELECT * FROM pg_stat_replication;"
```

### Step 4: Configure Database VIP with Keepalived

**On VM .52 (Primary):**

```bash
# Create health check script
cat > /etc/keepalived/check_postgres.sh << 'EOF'
#!/bin/bash
/usr/pgsql-16/bin/pg_isready -q
if [ $? -eq 0 ] && [ "$(sudo -u postgres /usr/pgsql-16/bin/psql -t -c "SELECT pg_is_in_recovery();" 2>/dev/null | tr -d ' ')" = "f" ]; then
    exit 0
else
    exit 1
fi
EOF

chmod +x /etc/keepalived/check_postgres.sh

# Configure Keepalived
cat > /etc/keepalived/keepalived.conf << 'EOF'
vrrp_script chk_postgres {
    script "/etc/keepalived/check_postgres.sh"
    interval 2
    weight 50
}

vrrp_instance VI_DB {
    state MASTER
    interface ens192  # Change to your network interface name
    virtual_router_id 51
    priority 150
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
        10.221.130.51/24
    }
    track_script {
        chk_postgres
    }
}
EOF

# Start Keepalived
systemctl enable --now keepalived

# Verify VIP
ip a | grep 10.221.130.51
```

**On VM .53 (Standby):**

```bash
# Create the same health check script
cat > /etc/keepalived/check_postgres.sh << 'EOF'
#!/bin/bash
/usr/pgsql-16/bin/pg_isready -q
if [ $? -eq 0 ] && [ "$(sudo -u postgres /usr/pgsql-16/bin/psql -t -c "SELECT pg_is_in_recovery();" 2>/dev/null | tr -d ' ')" = "f" ]; then
    exit 0
else
    exit 1
fi
EOF

chmod +x /etc/keepalived/check_postgres.sh

# Configure Keepalived (note BACKUP state and lower priority)
cat > /etc/keepalived/keepalived.conf << 'EOF'
vrrp_script chk_postgres {
    script "/etc/keepalived/check_postgres.sh"
    interval 2
    weight 50
}

vrrp_instance VI_DB {
    state BACKUP
    interface ens192  # Change to your network interface name
    virtual_router_id 51
    priority 100
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
        10.221.130.51/24
    }
    track_script {
        chk_postgres
    }
}
EOF

# Start Keepalived
systemctl enable --now keepalived

# Verify VIP is NOT here (should be on .52)
ip a | grep 10.221.130.51
```

**Test Database HA:**

```bash
# From any Admin or Agent VM, test connection to VIP
psql -h 10.221.130.51 -U vtaudit -d vtaudit -c "SELECT version();"

# Test failover (on primary .52)
systemctl stop postgresql-16
# Wait a few seconds, then check VIP moved to .53
ssh root@10.221.130.53 "ip a | grep 10.221.130.51"
```

---

## PHASE 2: NFS Setup (For StepCA and Nginx Certificates)

### Option A: Use VM .47 as NFS Server

**On VM .47:**

```bash
# Install NFS utilities
dnf install -y nfs-utils
systemctl enable --now nfs-server

# Create shared directories
mkdir -p /shared/stepca
mkdir -p /shared/nginx_certs

# Set permissions
chmod 777 /shared/stepca
chmod 777 /shared/nginx_certs

# Configure exports
cat >> /etc/exports << 'EOF'
/shared/stepca 10.211.130.48(rw,sync,no_root_squash)
/shared/nginx_certs 10.211.130.45(rw,sync,no_root_squash) 10.211.130.46(rw,sync,no_root_squash)
EOF

# Apply exports
exportfs -a

# Verify
exportfs -v
```

**On VM .48 (Agent VM):**

```bash
# Install NFS client
dnf install -y nfs-utils

# Create mount point
mkdir -p /mnt/stepca

# Mount NFS
mount 10.211.130.47:/shared/stepca /mnt/stepca

# Add to fstab for persistence
echo "10.211.130.47:/shared/stepca /mnt/stepca nfs defaults 0 0" >> /etc/fstab

# Verify
df -h | grep stepca
```

**On VM .45 and .46 (Proxy VMs):**

```bash
# Install NFS client
dnf install -y nfs-utils

# Create mount point
mkdir -p /mnt/nginx_certs

# Mount NFS
mount 10.211.130.47:/shared/nginx_certs /mnt/nginx_certs

# Add to fstab
echo "10.211.130.47:/shared/nginx_certs /mnt/nginx_certs nfs defaults 0 0" >> /etc/fstab

# Verify
df -h | grep nginx_certs
```

---

## PHASE 3: Proxy HA Setup (VMs .45, .46)

### Configure Keepalived for Proxy VIP

**On VM .45 (Primary):**

```bash
cat > /etc/keepalived/keepalived.conf << 'EOF'
vrrp_instance VI_PROXY {
    state MASTER
    interface ens192  # Change to your network interface name
    virtual_router_id 50
    priority 150
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
        10.221.130.44/24
    }
}
EOF

systemctl enable --now keepalived

# Verify VIP
ip a | grep 10.221.130.44
```

**On VM .46 (Secondary):**

```bash
cat > /etc/keepalived/keepalived.conf << 'EOF'
vrrp_instance VI_PROXY {
    state BACKUP
    interface ens192  # Change to your network interface name
    virtual_router_id 50
    priority 100
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
        10.221.130.44/24
    }
}
EOF

systemctl enable --now keepalived

# Verify VIP is NOT here
ip a | grep 10.221.130.44
```

---

## PHASE 4: Application Deployment

### Prepare Project Files

On your local machine, package the deployment files:

```bash
cd "d:\Documents\WORK\Viettel\Projects\Workstation Audit\Workstation-Audit\env"

# Create deployment packages
tar -czf admin-deploy.tar.gz docker-compose.admin.yml conf/ deploy-scripts/.env.admin deploy-scripts/deploy-admin.sh
tar -czf agent-deploy.tar.gz docker-compose.agent.yml conf/ deploy-scripts/.env.agent deploy-scripts/deploy-agent.sh
tar -czf proxy-deploy.tar.gz docker-compose.proxy.yml conf/ deploy-scripts/.env.proxy deploy-scripts/deploy-proxy.sh
```

### Deploy to Admin VMs (.49, .50)

```bash
# Copy to VM .49
scp admin-deploy.tar.gz root@10.211.130.49:/opt/
ssh root@10.211.130.49 "cd /opt && tar -xzf admin-deploy.tar.gz && mv docker-compose.admin.yml /opt/vt-audit/ && mv conf /opt/vt-audit/ && mv deploy-scripts/.env.admin /opt/vt-audit/.env && chmod +x deploy-scripts/deploy-admin.sh"

# Run deployment
ssh root@10.211.130.49 "cd /opt && ./deploy-scripts/deploy-admin.sh"

# Repeat for VM .50
scp admin-deploy.tar.gz root@10.211.130.50:/opt/
ssh root@10.211.130.50 "cd /opt && tar -xzf admin-deploy.tar.gz && mv docker-compose.admin.yml /opt/vt-audit/ && mv conf /opt/vt-audit/ && mv deploy-scripts/.env.admin /opt/vt-audit/.env && chmod +x deploy-scripts/deploy-admin.sh"
ssh root@10.211.130.50 "cd /opt && ./deploy-scripts/deploy-admin.sh"
```

### Deploy to Agent VMs (.47, .48)

```bash
# Copy to VM .47
scp agent-deploy.tar.gz root@10.211.130.47:/opt/
ssh root@10.211.130.47 "cd /opt && tar -xzf agent-deploy.tar.gz && mv docker-compose.agent.yml /opt/vt-audit/ && mv deploy-scripts/.env.agent /opt/vt-audit/.env && chmod +x deploy-scripts/deploy-agent.sh"

# Run deployment
ssh root@10.211.130.47 "cd /opt && ./deploy-scripts/deploy-agent.sh"

# Wait for StepCA to initialize, then deploy to VM .48
scp agent-deploy.tar.gz root@10.211.130.48:/opt/
ssh root@10.211.130.48 "cd /opt && tar -xzf agent-deploy.tar.gz && mv docker-compose.agent.yml /opt/vt-audit/ && mv deploy-scripts/.env.agent /opt/vt-audit/.env && chmod +x deploy-scripts/deploy-agent.sh"
ssh root@10.211.130.48 "cd /opt && ./deploy-scripts/deploy-agent.sh"
```

### Deploy to Proxy VMs (.45, .46)

```bash
# Copy to VM .45 (Primary)
scp proxy-deploy.tar.gz root@10.211.130.45:/opt/
ssh root@10.211.130.45 "cd /opt && tar -xzf proxy-deploy.tar.gz && mv docker-compose.proxy.yml /opt/vt-audit/ && mv conf /opt/vt-audit/ && mv deploy-scripts/.env.proxy /opt/vt-audit/.env && chmod +x deploy-scripts/deploy-proxy.sh"

# Run deployment
ssh root@10.211.130.45 "cd /opt && ./deploy-scripts/deploy-proxy.sh"

# Repeat for VM .46 (Secondary)
scp proxy-deploy.tar.gz root@10.211.130.46:/opt/
ssh root@10.211.130.46 "cd /opt && tar -xzf proxy-deploy.tar.gz && mv docker-compose.proxy.yml /opt/vt-audit/ && mv conf /opt/vt-audit/ && mv deploy-scripts/.env.proxy /opt/vt-audit/.env && chmod +x deploy-scripts/deploy-proxy.sh"
ssh root@10.211.130.46 "cd /opt && ./deploy-scripts/deploy-proxy.sh"
```

---

## PHASE 5: Verification & Testing

### Check VIPs

```bash
# Proxy VIP (should be on .45)
ssh root@10.211.130.45 "ip a | grep 10.221.130.44"

# Database VIP (should be on .52)
ssh root@10.221.130.52 "ip a | grep 10.221.130.51"
```

### Test Services

```bash
# Test database
psql -h 10.221.130.51 -U vtaudit -d vtaudit -c "SELECT version();"

# Test Keycloak (from proxy VIP)
curl -k https://10.221.130.44/auth/realms/vt-audit

# Test admin UI
curl -k https://10.221.130.44/

# Test StepCA
curl -k https://10.221.130.44:8443/step-ca/health
```

### Test Failover

**Test Proxy Failover:**

```bash
# Stop primary proxy
ssh root@10.211.130.45 "systemctl stop keepalived"

# Check VIP moved to .46
ssh root@10.211.130.46 "ip a | grep 10.221.130.44"

# Test service still works
curl -k https://10.221.130.44/

# Restore primary
ssh root@10.211.130.45 "systemctl start keepalived"
```

**Test Database Failover:**

```bash
# Stop primary database
ssh root@10.221.130.52 "systemctl stop postgresql-16"

# Check VIP moved to .53
ssh root@10.221.130.53 "ip a | grep 10.221.130.51"

# Test connection still works
psql -h 10.221.130.51 -U vtaudit -d vtaudit -c "SELECT version();"

# Promote standby if needed (manual failover)
ssh root@10.221.130.53 "sudo -u postgres /usr/pgsql-16/bin/pg_ctl promote -D /var/lib/pgsql/16/data"
```

---

## Troubleshooting

### Common Issues

1. **Cannot reach VIP**
   - Check Keepalived is running: `systemctl status keepalived`
   - Check VRRP is allowed in firewall: `firewall-cmd --list-all`
   - Check interface name in keepalived.conf matches actual interface

2. **Database connection failed**
   - Check PostgreSQL is running: `systemctl status postgresql-16`
   - Check pg_hba.conf allows connections from your IP
   - Test with: `psql -h 10.221.130.51 -U vtaudit -d vtaudit`

3. **NFS mount failed**
   - Check NFS server is running: `systemctl status nfs-server`
   - Check exports: `exportfs -v`
   - Check firewall allows NFS

4. **Docker containers not starting**
   - Check logs: `docker compose -f <file>.yml logs -f`
   - Check .env file has correct values
   - Verify all required services are reachable

### Useful Commands

```bash
# Check all container status
docker compose ps

# View logs
docker compose logs -f [service_name]

# Restart a service
docker compose restart [service_name]

# Check Keepalived status
systemctl status keepalived
journalctl -u keepalived -f

# Check PostgreSQL replication
sudo -u postgres psql -c "SELECT * FROM pg_stat_replication;"

# Check NFS mounts
df -h | grep -E 'stepca|nginx_certs'
```

---

## Security Recommendations

1. **Change all default passwords** in .env files
2. **Use proper SSL certificates** (not self-signed) in production
3. **Enable SELinux** and configure policies
4. **Set up monitoring** (Prometheus, Grafana)
5. **Configure log aggregation** (ELK stack)
6. **Regular backups** of database and certificates
7. **Update firewall rules** to be more restrictive

---

## Next Steps After Deployment

1. Access admin UI: `https://10.221.130.44`
2. Login to Keycloak admin console: `https://10.221.130.44/auth/admin`
3. Configure policies in the admin dashboard
4. Deploy agents to workstations with bootstrap token
5. Monitor agent check-ins and compliance results

---

## Support & Documentation

For issues or questions, refer to:
- RUNBOOK.md for detailed architecture
- Individual deploy scripts for component-specific instructions
- Docker Compose logs for troubleshooting
