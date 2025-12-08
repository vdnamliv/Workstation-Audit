# VT-AUDIT PRODUCTION DEPLOYMENT GUIDE

## 📋 Yêu Cầu Hệ Thống

### Hardware Requirements (Mỗi Server)
- **CPU:** 4 cores minimum (8 cores recommended)
- **RAM:** 8GB minimum (16GB recommended)
- **Storage:** 100GB SSD minimum
- **Network:** 1Gbps NIC

### Software Requirements
- **OS:** Rocky Linux 9.x (hoặc RHEL 9, AlmaLinux 9)
- **Docker:** 24.x+
- **Docker Compose:** v2.20+
- **OpenSSL:** 3.x (built-in)
- **Firewall:** firewalld

---

## 🏗️ Kiến Trúc Production

```
                   ┌─────────────────────────┐
                   │   HAProxy VIP (Layer 4) │
                   │    10.211.130.44:443    │
                   │    10.211.130.44:8443   │
                   └────────────┬────────────┘
                                │
                ┌───────────────┴───────────────┐
                │                               │
        ┌───────▼──────┐              ┌────────▼─────┐
        │  Nginx GW 1  │              │  Nginx GW 2  │
        │ 10.211.130.45│              │ 10.211.130.46│
        └───────┬──────┘              └───────┬──────┘
                │                             │
    ┌───────────┼─────────────────────────────┼──────────┐
    │           │                             │          │
┌───▼───┐  ┌───▼───┐                    ┌────▼────┐ ┌──▼─────┐
│Agent  │  │Agent  │                    │ Admin   │ │ Admin  │
│API 1  │  │API 2  │                    │ API 1   │ │ API 2  │
│.47:80 │  │.48:80 │                    │ .49:81  │ │.50:81  │
│+StepCA│  │+StepCA│                    │+Keycloak│ │+Keycloak│
└───┬───┘  └───┬───┘                    └────┬────┘ └───┬────┘
    │          │                             │          │
    └──────────┼─────────────────────────────┼──────────┘
               │                             │
         ┌─────▼─────────────────────────────▼─────┐
         │      PostgreSQL Primary + Replica       │
         │  10.211.130.51 (Primary)               │
         │  10.211.130.52 (Replica - Optional)    │
         └─────────────────────────────────────────┘
```

---

## 📦 Chuẩn Bị Pre-Deployment

### 1. Clone Repository và Checkout Production Branch
```bash
cd /opt
git clone https://github.com/vdnamliv/Workstation-Audit.git vt-audit
cd vt-audit
git checkout main

# Verify files
ls -la deploy/
```

### 2. Cài Đặt Docker & Docker Compose
```bash
# Rocky Linux 9
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start Docker
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker compose version
```

### 3. Cấu Hình Firewall
```bash
# Database Server (10.211.130.51)
sudo firewall-cmd --permanent --add-port=5432/tcp
sudo firewall-cmd --reload

# Agent API Servers (.47, .48)
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=9000/tcp  # StepCA
sudo firewall-cmd --reload

# Admin API Servers (.49, .50)
sudo firewall-cmd --permanent --add-port=8080/tcp  # Keycloak
sudo firewall-cmd --permanent --add-port=8081/tcp  # Backend
sudo firewall-cmd --reload

# Nginx Gateway (.45, .46)
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

### 4. Tạo Docker Network
```bash
# Trên TẤT CẢ servers
docker network create --driver bridge --subnet 172.18.0.0/16 vt-system-net
```

---

## 🔐 Tạo SSL Certificates

### Option A: Self-Signed (Testing/Internal Only)
```bash
cd /opt/vt-audit/deploy/02-nginx-gateway/certs

# Generate CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=VN/ST=Hanoi/L=Hanoi/O=VT-Audit/CN=VT-Audit-CA"

# Generate Server Certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=VN/ST=Hanoi/L=Hanoi/O=VT-Audit/CN=10.211.130.44"

# Sign with CA
openssl x509 -req -days 365 -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt \
  -extfile <(printf "subjectAltName=IP:10.211.130.44,IP:10.211.130.45,IP:10.211.130.46")

# Cleanup
rm server.csr ca.srl
chmod 600 server.key ca.key
```

### Option B: Let's Encrypt (Recommended for Internet-Facing)
```bash
# Cài Certbot
sudo dnf install -y certbot

# Generate certificate (cần domain name)
sudo certbot certonly --standalone -d yourdomain.com

# Copy vào project
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem /opt/vt-audit/deploy/02-nginx-gateway/certs/server.crt
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem /opt/vt-audit/deploy/02-nginx-gateway/certs/server.key
sudo chown $USER:$USER /opt/vt-audit/deploy/02-nginx-gateway/certs/*
```

---

## 🗄️ BƯỚC 1: Deploy Database (Server 10.211.130.51)

```bash
cd /opt/vt-audit/deploy/01-database

# Tạo .env từ template
cp .env.example .env

# Chỉnh sửa passwords
nano .env
```

**File `.env`:**
```bash
POSTGRES_PASSWORD=<STRONG_PASSWORD_HERE>
KEYCLOAK_DB_PASSWORD=<STRONG_PASSWORD_HERE>
STEPCA_DB_PASSWORD=<STRONG_PASSWORD_HERE>
VT_APP_PASSWORD=<STRONG_PASSWORD_HERE>
```

```bash
# Start database
docker compose up -d

# Verify
docker logs vt-postgres --tail 20
docker exec vt-postgres psql -U postgres -c "\l"
docker exec vt-postgres psql -U postgres -d vt_db -c "\dt audit.*"
```

**✅ Checklist:**
- [ ] Container `vt-postgres` running
- [ ] 3 databases created: `keycloak`, `stepca`, `vt_db`
- [ ] Schemas `audit`, `policy` exist in `vt_db`
- [ ] Port 5432 open và accessible từ Agent/Admin servers

---

## 🤖 BƯỚC 2: Deploy Agent API (Servers .47, .48)

### 2.1. StepCA Provisioner Key (Tự động - Không cần thao tác thủ công)

✅ **HOÀN TOÀN TỰ ĐỘNG:** Provisioner key được tự động:
- Tạo bởi StepCA khi khởi động lần đầu
- Lưu trong `/home/step/config/ca.json` 
- Agent API đọc trực tiếp từ ca.json qua shared volume

**KHÔNG CẦN** extract ra file `admin.jwk` riêng!

Xem chi tiết: [PROVISIONER_KEY_SETUP.md](04-agent-api/PROVISIONER_KEY_SETUP.md)

### 2.2. Cấu Hình .env

```bash
cp .env.example .env
nano .env
```

**File `.env`:**
```bash
DB_HOST=10.211.130.51
DB_USER=vt_app
DB_PASS=<VT_APP_PASSWORD>
DB_NAME=vt_db

STEPCA_DB_PASSWORD=<STEPCA_DB_PASSWORD>
STEPCA_NAME=VT-Audit-CA
STEPCA_DNS_NAMES=10.211.130.44,10.211.130.47,10.211.130.48,gateway.vt-audit.local
STEPCA_PROVISIONER=vt-audit-provisioner
STEPCA_PASSWORD=<STEPCA_ADMIN_PASSWORD>
STEPCA_PROVISIONER_PASSWORD=<STEPCA_ADMIN_PASSWORD>

AGENT_BOOTSTRAP_TOKEN=<STRONG_RANDOM_TOKEN>
```

### 2.3. Start Services

```bash
# Server .47 (Primary)
docker compose up -d

# Đợi StepCA init xong (30s)
sleep 30

# Verify StepCA đã tạo provisioner trong ca.json
docker exec vt-stepca cat /home/step/config/ca.json | jq '.authority.provisioners[] | {name, type}'

# Lấy StepCA root certificate cho mTLS
docker exec vt-stepca step ca roots > /tmp/stepca_root.crt

# Copy root cert sang Nginx servers
scp /tmp/stepca_root.crt 10.211.130.45:/opt/vt-audit/deploy/02-nginx-gateway/certs/stepca_chain.crt
scp /tmp/stepca_root.crt 10.211.130.46:/opt/vt-audit/deploy/02-nginx-gateway/certs/stepca_chain.crt

# Verify services
docker logs vt-stepca --tail 20
docker logs vt-api-agent --tail 20
curl http://localhost:8080/health
```

### 2.4. Deploy Server .48 (Secondary)

```bash
# Copy TOÀN BỘ stepca volume data từ .47
ssh 10.211.130.47 "docker run --rm -v 04-agent-api_stepca_data:/data -v $(pwd):/backup alpine tar czf /backup/stepca-data.tar.gz -C /data ."
scp 10.211.130.47:/opt/vt-audit/deploy/04-agent-api/stepca-data.tar.gz /tmp/

# Trên server .48
cd /opt/vt-audit/deploy/04-agent-api
cp /path/to/.env .env  # Copy .env từ .47
docker compose up -d
docker compose down
docker run --rm -v 04-agent-api_stepca_data:/data -v /tmp:/backup alpine tar xzf /backup/stepca-data.tar.gz -C /data
docker compose up -d

# Verify (key đã có sẵn trong volume từ .47)
docker exec vt-stepca cat /home/step/config/ca.json | jq '.authority.provisioners[] | {name, type}'
docker logs vt-api-agent --tail 20
curl http://localhost:8080/health

# Cleanup sensitive backup
rm /tmp/stepca-data.tar.gz
```

**✅ Checklist:**
- [ ] StepCA running, root fingerprint giống nhau trên .47 và .48
- [ ] Agent API responding: `curl http://localhost:8080/health`
- [ ] Policy loaded: response chứa `policy_id`

---

## 👤 BƯỚC 3: Deploy Admin API (Servers .49, .50)

```bash
cd /opt/vt-audit/deploy/03-admin-api
cp .env.example .env
nano .env
```

**File `.env`:**
```bash
DB_HOST=10.211.130.51
DB_USER=vt_app
DB_PASS=<VT_APP_PASSWORD>
DB_NAME=vt_db

KC_DB_PASSWORD=<KEYCLOAK_DB_PASSWORD>
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=<STRONG_ADMIN_PASSWORD>

OIDC_ISSUER_URL=https://10.211.130.44:8443/realms/vt-audit
OIDC_CLIENT_ID=vt-dashboard
OIDC_CLIENT_SECRET=<GENERATE_SECRET>

STEPCA_URL=https://10.211.130.44:443/step-ca
```

### 3.1. Sửa docker-compose.yml cho Production

```bash
nano docker-compose.yml
```

**Thay đổi:**
```yaml
services:
  keycloak:
    command: start --optimized  # Đổi từ start-dev
    ports:
      - "8080:8080"  # Đổi từ 8090
```

### 3.2. Import Keycloak Realm

**Download realm configuration:**
```bash
# Tạo file conf/keycloak/vt-audit-realm.json với config realm
# Hoặc export từ Keycloak test environment
```

**Mount realm vào container:**
```yaml
# Thêm vào docker-compose.yml
volumes:
  - ./conf/keycloak/vt-audit-realm.json:/opt/keycloak/data/import/vt-audit-realm.json:ro
environment:
  - KC_IMPORT_FILE=/opt/keycloak/data/import/vt-audit-realm.json
```

### 3.3. Start Services

```bash
docker compose up -d

# Verify
docker logs vt-keycloak --tail 30
docker logs vt-api-backend --tail 20
curl http://localhost:8081/
```

**✅ Checklist:**
- [ ] Keycloak accessible: `http://localhost:8080`
- [ ] Admin Backend responding: `curl http://localhost:8081/`
- [ ] Keycloak realm `vt-audit` created

---

## 🌐 BƯỚC 4: Deploy Nginx Gateway (.45, .46)

### 4.1. Chuẩn Bị Certificates

```bash
cd /opt/vt-audit/deploy/02-nginx-gateway/certs

# Copy certificates đã tạo ở bước Chuẩn Bị
# server.crt, server.key, stepca_root.crt phải có sẵn
ls -la
# Kết quả: server.crt, server.key, stepca_root.crt

# Tạo StepCA chain (root + intermediate)
ssh 10.211.130.47 'docker exec vt-stepca cat /home/step/certs/root_ca.crt' > root_ca.crt
ssh 10.211.130.47 'docker exec vt-stepca cat /home/step/certs/intermediate_ca.crt' > intermediate_ca.crt
cat root_ca.crt intermediate_ca.crt > stepca_chain.crt
```

### 4.2. Sửa Upstream Config

```bash
cd conf/conf.d

# Backup local config
mv 00-upstream.conf 00-upstream.conf.local

# Rename production config
mv 00-upstream.conf.production 00-upstream.conf

# Verify IPs
cat 00-upstream.conf | grep server
```

**Kết quả phải thấy:**
```nginx
server 10.211.130.49:8081;  # Admin Backend
server 10.211.130.50:8081;
server 10.211.130.47:8080;  # Agent API
server 10.211.130.48:8080;
server 10.211.130.49:8080;  # Keycloak
server 10.211.130.50:8080;
```

### 4.3. Enable mTLS và OAuth2-Proxy

**File: `conf/conf.d/20-agent-mtls-443.conf`**
```bash
nano conf/conf.d/20-agent-mtls-443.conf
```

Uncomment:
```nginx
ssl_client_certificate /etc/nginx/certs/stepca_chain.crt;
ssl_verify_client optional;
ssl_verify_depth 2;
```

**File: `conf/conf.d/10-admin-8443.conf`**
```bash
nano conf/conf.d/10-admin-8443.conf
```

Uncomment (nếu có OAuth2-Proxy):
```nginx
location = /oauth2/auth {
  internal;
  proxy_pass http://oidc_proxy;
  # ... (uncomment all)
}

location / {
  auth_request /oauth2/auth;  # Uncomment
  # ...
}
```

### 4.4. Start Nginx

```bash
cd /opt/vt-audit/deploy/02-nginx-gateway
docker compose up -d

# Verify
docker logs vt-nginx-gateway --tail 20
docker exec vt-nginx-gateway nginx -t
```

### 4.5. Test Endpoints

```bash
# Test Agent API (port 443)
curl -k https://localhost:443/health

# Test Admin Dashboard (port 8443)
curl -k https://localhost:8443/

# Test từ external
curl -k https://10.211.130.45:443/health
```

**✅ Checklist:**
- [ ] Nginx container running
- [ ] Port 443, 8443 listening
- [ ] Agent API proxy working
- [ ] Admin Dashboard accessible
- [ ] SSL certificates valid

---

## 🔄 BƯỚC 5: Setup HAProxy Load Balancer

**Cài HAProxy trên dedicated server hoặc Nginx servers:**

```bash
sudo dnf install -y haproxy

sudo nano /etc/haproxy/haproxy.cfg
```

**HAProxy Config:**
```haproxy
global
    log /dev/log local0
    maxconn 4096
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode tcp
    option tcplog
    timeout connect 5s
    timeout client 50s
    timeout server 50s

# Agent API - Port 443
frontend agent_frontend
    bind 10.211.130.44:443
    mode tcp
    default_backend agent_backend

backend agent_backend
    mode tcp
    balance roundrobin
    option tcp-check
    server nginx1 10.211.130.45:443 check
    server nginx2 10.211.130.46:443 check

# Admin Dashboard - Port 8443
frontend admin_frontend
    bind 10.211.130.44:8443
    mode tcp
    default_backend admin_backend

backend admin_backend
    mode tcp
    balance roundrobin
    option tcp-check
    server nginx1 10.211.130.45:8443 check
    server nginx2 10.211.130.46:8443 check
```

```bash
sudo systemctl enable --now haproxy
sudo systemctl status haproxy

# Test
curl -k https://10.211.130.44:443/health
curl -k https://10.211.130.44:8443/
```

---

## 🧪 BƯỚC 6: Verification & Testing

### 6.1. Component Health Check

```bash
# Database
docker exec vt-postgres psql -U postgres -c "SELECT version();"

# Agent API (.47, .48)
curl http://localhost:8080/health

# StepCA
docker exec vt-stepca step ca health

# Admin API (.49, .50)
curl http://localhost:8081/

# Keycloak
curl http://localhost:8080/health/ready

# Nginx (.45, .46)
curl -k https://localhost:443/health
curl -k https://localhost:8443/

# HAProxy VIP
curl -k https://10.211.130.44:443/health
curl -k https://10.211.130.44:8443/
```

### 6.2. Test Agent Enrollment

```bash
# Trên Windows workstation test
cd C:\vt-agent

# Download agent binary
Invoke-WebRequest https://10.211.130.44:443/agent/download -OutFile vt-agent.exe

# Enroll
.\vt-agent.exe enroll `
  --server https://10.211.130.44:443 `
  --token <AGENT_BOOTSTRAP_TOKEN>

# Run audit
.\vt-agent.exe run
```

### 6.3. Monitor Logs

```bash
# Real-time logs
docker logs -f vt-postgres
docker logs -f vt-api-agent
docker logs -f vt-api-backend
docker logs -f vt-keycloak
docker logs -f vt-nginx-gateway
```

---

## 🔐 Security Hardening

### 1. Change Default Passwords
```bash
# Generate strong passwords
openssl rand -base64 32

# Update .env files
# Update Keycloak admin password via UI
```

### 2. Enable Firewall Rules
```bash
# Chỉ cho phép traffic từ known IPs
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.0/24" accept'
sudo firewall-cmd --reload
```

### 3. Setup SSL Certificate Auto-Renewal
```bash
# Nếu dùng Let's Encrypt
sudo crontab -e
# Thêm:
0 3 * * * certbot renew --quiet && docker exec vt-nginx-gateway nginx -s reload
```

### 4. Enable Audit Logging
```bash
# PostgreSQL
docker exec vt-postgres psql -U postgres -c "ALTER SYSTEM SET log_statement = 'all';"
docker exec vt-postgres psql -U postgres -c "SELECT pg_reload_conf();"
```

---

## 📊 Monitoring & Backup

### Backup Script
```bash
#!/bin/bash
# /opt/vt-audit/scripts/backup.sh

BACKUP_DIR="/backup/vt-audit"
DATE=$(date +%Y%m%d_%H%M%S)

# Database backup
docker exec vt-postgres pg_dumpall -U postgres | gzip > $BACKUP_DIR/db_$DATE.sql.gz

# StepCA data
docker run --rm -v 04-agent-api_stepca_data:/data -v $BACKUP_DIR:/backup \
  alpine tar czf /backup/stepca_$DATE.tar.gz -C /data .

# Cleanup old backups (keep 7 days)
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete
```

### Cron Job
```bash
sudo crontab -e
# Daily backup at 2 AM
0 2 * * * /opt/vt-audit/scripts/backup.sh
```

---

## 🚨 Troubleshooting

### Database Connection Issues
```bash
# Check PostgreSQL listening
docker exec vt-postgres netstat -tlnp | grep 5432

# Test connection from Agent server
telnet 10.211.130.51 5432

# Check credentials
docker exec vt-postgres psql -U vt_app -d vt_db -c "SELECT 1;"
```

### StepCA Certificate Issues
```bash
# Re-initialize StepCA
docker compose down
docker volume rm 04-agent-api_stepca_data
docker compose up -d

# Export new root certificate
docker exec vt-stepca step ca roots > stepca_root.crt
```

### Nginx 502 Bad Gateway
```bash
# Check upstream health
curl http://10.211.130.47:8080/health
curl http://10.211.130.49:8081/

# Check Nginx logs
docker logs vt-nginx-gateway | grep error

# Test config
docker exec vt-nginx-gateway nginx -t
```

---

## 📞 Support

- **Documentation:** `/opt/vt-audit/documents/`
- **Logs:** `docker logs <container_name>`
- **GitHub Issues:** https://github.com/vdnamliv/Workstation-Audit/issues

---

**🎉 DEPLOYMENT COMPLETE!**

Access dashboard: `https://10.211.130.44:8443`
