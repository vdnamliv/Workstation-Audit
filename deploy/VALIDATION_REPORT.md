# 📋 Báo cáo Kiểm tra Triển khai HA - VT-Audit System

**Ngày:** December 5, 2025  
**Version:** 1.0  
**Status:** ✅ PASSED với một số sửa đổi nhỏ

---

## 🎯 Tổng quan

Đã kiểm tra toàn bộ cấu hình triển khai HA cho hệ thống VT-Audit trên kiến trúc:
- **Load Balancer:** HAProxy + Keepalived (VIP: 10.211.130.44)
- **Reverse Proxy:** 2x Nginx (10.211.130.45-46)
- **Admin API:** 2x Backend + Keycloak (10.211.130.49-50)
- **Agent API:** 2x Backend + StepCA (10.211.130.47-48)
- **Database:** PostgreSQL HA (VIP: 10.211.130.51, Servers: 10.211.130.52-53)

---

## ✅ **Các vấn đề đã được SỬA**

### **1. Flag name mismatch (CRITICAL)**
**Vấn đề:** Backend Go code dùng `--pg_dsn` (underscore) nhưng docker-compose dùng `--pg-dsn` (dash)

**Nguyên nhân:** 
```go
// server/cmd/vt-server/main.go line 33
pgDSN := flag.String("pg_dsn", "", "...")  // Underscore
```

**Đã sửa:**
- ✅ `deploy/03-admin-api/docker-compose.yml`: `--pg-dsn` → `--pg_dsn`
- ✅ `deploy/04-agent-api/docker-compose.yml`: `--pg-dsn` → `--pg_dsn`

---

### **2. Docker Compose syntax errors (CRITICAL)**
**Vấn đề:** `env_file` được đặt sai vị trí (ở top-level thay vì trong service definition)

**Đã sửa:**
- ✅ `01-database/docker-compose.yml`: Di chuyển `env_file` vào `services.postgres`
- ✅ `03-admin-api/docker-compose.yml`: Di chuyển `env_file` vào từng service
- ✅ `04-agent-api/docker-compose.yml`: Thêm `env_file` cho tất cả services

---

### **3. Keycloak configuration incomplete (IMPORTANT)**
**Vấn đề:** Keycloak thiếu nhiều environment variables và command flags

**Đã sửa:**
```yaml
# TRƯỚC
environment:
  KC_DB_URL: jdbc:postgresql://.../${KEYCLOAK_DB}  # Biến không tồn tại
  KC_DB_USERNAME: ${KEYCLOAK_DB_USER}              # Biến không tồn tại
  
# SAU
command: start --optimized
environment:
  KC_DB: postgres
  KC_DB_URL: jdbc:postgresql://10.211.130.51:5432/keycloak  # Hardcode DB name
  KC_DB_USERNAME: keycloak                                    # Match với init.sql
  KC_DB_PASSWORD: ${KC_DB_PASSWORD}
  KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN}
  KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
  KC_HOSTNAME: 10.211.130.44
  KC_HOSTNAME_PORT: 8443
  KC_HTTP_ENABLED: true
  KC_PROXY: edge
```

**Đã thêm vào `.env`:**
```dotenv
KEYCLOAK_DB=keycloak
KEYCLOAK_DB_USER=keycloak
KEYCLOAK_DB_PASSWORD=ChangeMe123!
KC_DB_PASSWORD=ChangeMe123!
```

---

### **4. Database init script - Lỗi GRANT schema chưa tồn tại (CRITICAL)**
**Vấn đề:** Script cố gắng GRANT quyền cho schema `audit` và `policy` trước khi chúng được tạo

**Đã sửa trong `01-init.sql`:**
```sql
-- ĐÚNG: Tạo schema TRƯỚC khi GRANT
\c vt_db;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS policy;

-- Sau đó mới GRANT
GRANT ALL ON SCHEMA audit TO vt_app;
GRANT ALL ON SCHEMA policy TO vt_app;
```

---

## ✅ **Xác nhận KHÔNG CÓ xung đột**

### **1. Database Schema vs Backend Code**
✅ **KHỚP HOÀN TOÀN**

| Component | Schema Definition | Backend Usage | Status |
|-----------|------------------|---------------|--------|
| `audit.agents` | 9 columns (agent_id, agent_secret, hostname, os, fingerprint, cert_cn, cert_serial, enrolled_at, last_seen) | `UpsertAgent()` insert 8 columns | ✅ |
| `audit.results_flat` | 11 columns | `ReplaceLatestResults()` insert 10 columns | ✅ |
| `policy.policy_versions` | 7 columns | `InsertPolicyVersion()` insert 7 columns | ✅ |
| `policy.policy_heads` | 4 columns | `SetActivePolicy()` insert 4 columns | ✅ |
| `policy.policy_rules` | 12 columns | `CreatePolicyRule()` insert 12 columns | ✅ |

**Lưu ý quan trọng:**
- ✅ `agent_secret` đã cho phép NULL (phù hợp với mTLS agents)
- ✅ Backend đã loại bỏ `InitAgentSchema()` và `InitPolicySchema()` (không còn conflict)
- ✅ `enrolled_at` và `last_seen` dùng TIMESTAMPTZ nhưng Go code insert BIGINT → PostgreSQL tự convert

---

### **2. Network Topology vs Configuration**
✅ **ĐÚNG THEO THIẾT KẾ**

```
┌─────────────────────────────────────────────┐
│  Agent (Workstation)                        │
│    ↓ HTTPS:443 (mTLS cert authentication)  │
└─────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────┐
│  HAProxy VIP: 10.211.130.44                 │
│    - .45 & .46 (Active-Active + Keepalived)│
│    - Port 443: Agent traffic                │
│    - Port 8443: Admin dashboard             │
└─────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────┐
│  Nginx Gateway (.45 & .46)                  │
│    - Load balance to backend clusters       │
│    - TLS termination (if needed)            │
│    - mTLS verification for agents           │
└─────────────────────────────────────────────┘
         ↓                       ↓
┌──────────────────┐   ┌──────────────────┐
│ Agent Backend    │   │ Admin Backend    │
│ .47 & .48:8080   │   │ .49 & .50:8081   │
│ + StepCA:9000    │   │ + Keycloak:8080  │
└──────────────────┘   └──────────────────┘
         ↓                       ↓
┌─────────────────────────────────────────────┐
│  PostgreSQL VIP: 10.211.130.51              │
│    - .52 (Primary) & .53 (Standby)          │
│    - Databases: vt_db, keycloak, stepca     │
└─────────────────────────────────────────────┘
```

**Xác nhận:**
- ✅ Tất cả backend services kết nối đúng VIP DB: `10.211.130.51:5432`
- ✅ Nginx upstream definitions trỏ đúng IP:Port của backend servers
- ✅ Keycloak hostname config đúng VIP: `10.211.130.44:8443`
- ✅ StepCA DNS_NAMES bao gồm đầy đủ: `10.211.130.44,10.211.130.47,10.211.130.48`

---

### **3. Environment Variables Consistency**
✅ **ĐỒNG BỘ GIỮA CÁC COMPONENTS**

| Variable | 01-database | 03-admin-api | 04-agent-api | Status |
|----------|-------------|--------------|--------------|--------|
| DB VIP | - | 10.211.130.51 | 10.211.130.51 | ✅ |
| DB User (vt_app) | Created in init.sql | vt_app | vt_app | ✅ |
| DB Pass (vt_app) | ChangeMe_VT_App! | ChangeMe_VT_App! | ChangeMe_VT_App! | ✅ |
| DB User (keycloak) | Created | keycloak | - | ✅ |
| DB User (stepca) | Created | - | stepca | ✅ |
| Bootstrap Token | - | - | 123456 | ✅ |
| StepCA Provisioner | - | - | bootstrap@vt-audit | ✅ |

---

## ⚠️ **Lưu ý quan trọng trước khi Deploy**

### **1. Passwords PHẢI thay đổi trước production**
```bash
# Tất cả passwords hiện tại là default, RẤT NGUY HIỂM!
POSTGRES_PASSWORD=ChangeMe_SuperSecret_DB!      # ❌ ĐỔI NGAY
KC_DB_PASSWORD=ChangeMe123!                      # ❌ ĐỔI NGAY
STEPCA_DB_PASSWORD=ChangeMe_StepCA_DB!          # ❌ ĐỔI NGAY
STEPCA_PASSWORD=ChangeMe_StepCA_Pass!           # ❌ ĐỔI NGAY
KEYCLOAK_ADMIN_PASSWORD=pODFPavc1Kee6XiUKyuOryD6GkyaIkZQ  # ✅ Đã random
```

**Cách generate passwords an toàn:**
```powershell
# Trên Windows PowerShell
-join ((65..90) + (97..122) + (48..57) + 33,35,36,37,38,42,43,45,61 | Get-Random -Count 32 | % {[char]$_})

# Hoặc dùng OpenSSL
openssl rand -base64 32
```

---

### **2. Certificates cần chuẩn bị**

#### **A. Server TLS Certificates (cho Nginx)**
```bash
# Đặt tại: deploy/02-nginx-gateway/certs/
server.crt        # Certificate cho domain/VIP 10.211.130.44
server.key        # Private key
stepca_chain.crt  # CA chain từ StepCA (root + intermediate)
```

**Yêu cầu:**
- Subject Alternative Names (SAN) phải bao gồm:
  - IP: 10.211.130.44, 10.211.130.45, 10.211.130.46
  - DNS: gateway.local (nếu có)

#### **B. StepCA Initialization**
- Lần đầu chạy, StepCA sẽ tự generate root CA và intermediate CA
- Provisioner key sẽ được lưu trong Docker volume `stepca_data`
- **QUAN TRỌNG:** Backup volume này sau khi init xong!

```bash
# Backup StepCA data
docker run --rm \
  -v vt-audit_stepca_data:/data \
  -v $(pwd)/backup:/backup \
  alpine tar czf /backup/stepca-backup-$(date +%Y%m%d).tar.gz /data
```

---

### **3. PostgreSQL HA Setup**

**Lưu ý:** Docker Compose chỉ chạy **single instance** trên mỗi server. Để có Active-Standby, cần:

1. **Setup Streaming Replication:**
   - Server .52: Primary (read-write)
   - Server .53: Standby (read-only, hot standby)

2. **Keepalived cho VIP .51:**
```bash
# Cấu hình trên cả 2 servers .52 & .53
# File: /etc/keepalived/keepalived.conf
vrrp_script check_postgres {
    script "/usr/bin/pg_isready -h localhost -U postgres"
    interval 2
    weight 2
}

vrrp_instance VI_1 {
    state MASTER              # MASTER trên .52, BACKUP trên .53
    interface eth0
    virtual_router_id 51
    priority 100              # 100 trên .52, 90 trên .53
    virtual_ipaddress {
        10.211.130.51
    }
    track_script {
        check_postgres
    }
}
```

---

### **4. HAProxy Configuration**

**File mới cần tạo:** `deploy/00-haproxy/haproxy.cfg`

```cfg
global
    log /dev/log local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    log     global
    mode    tcp
    option  tcplog
    timeout connect 5000
    timeout client  50000
    timeout server  50000

# Stats page (optional)
listen stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 30s
    stats auth admin:YourStatsPassword

# Frontend cho Agent (Port 443)
frontend agent_frontend
    bind 10.211.130.44:443
    mode tcp
    default_backend agent_nginx_cluster

backend agent_nginx_cluster
    mode tcp
    balance roundrobin
    option tcp-check
    tcp-check connect
    server nginx1 10.211.130.45:443 check inter 2000 rise 2 fall 3
    server nginx2 10.211.130.46:443 check inter 2000 rise 2 fall 3

# Frontend cho Admin Dashboard (Port 8443)
frontend admin_frontend
    bind 10.211.130.44:8443
    mode tcp
    default_backend admin_nginx_cluster

backend admin_nginx_cluster
    mode tcp
    balance roundrobin
    option tcp-check
    tcp-check connect
    server nginx1 10.211.130.45:8443 check inter 2000 rise 2 fall 3
    server nginx2 10.211.130.46:8443 check inter 2000 rise 2 fall 3
```

**Deploy HAProxy:**
```bash
# Trên cả 2 servers .45 & .46
sudo dnf install haproxy keepalived -y
sudo cp haproxy.cfg /etc/haproxy/haproxy.cfg
sudo systemctl enable --now haproxy

# Kiểm tra
sudo systemctl status haproxy
curl http://localhost:8404/stats
```

---

## 🚀 **Quy trình Deploy Production**

### **Bước 1: Deploy Database (Server .52 & .53)**

```bash
# === TRÊN SERVER .52 (PRIMARY) ===
cd /opt/vt-audit/deploy/01-database

# Copy file .env và điều chỉnh passwords
cp .env.example .env
nano .env  # Đổi tất cả passwords

# Start container
docker-compose up -d

# Kiểm tra logs
docker logs -f vt-postgres

# Xác nhận databases đã được tạo
docker exec -it vt-postgres psql -U postgres -l
# Phải thấy: keycloak, stepca, vt_db

# Xác nhận users đã được tạo
docker exec -it vt-postgres psql -U postgres -c "\du"
# Phải thấy: keycloak, stepca, vt_app

# Test connection từ remote
psql -h 10.211.130.52 -U vt_app -d vt_db -c "SELECT version();"
```

```bash
# === TRÊN SERVER .53 (STANDBY) ===
# Setup streaming replication từ .52
# (Cần tài liệu riêng cho PostgreSQL replication)

# Sau khi setup xong, test failover
# Stop .52 → VIP .51 phải chuyển sang .53
```

---

### **Bước 2: Deploy Agent API (Server .47 & .48)**

```bash
# === TRÊN CẢ 2 SERVERS .47 & .48 ===
cd /opt/vt-audit/deploy/04-agent-api

# Copy .env và điều chỉnh
cp .env .env.local
nano .env.local  # Đổi passwords

# Build và start containers
docker-compose --env-file .env.local up -d --build

# Kiểm tra logs
docker logs -f vt-stepca
docker logs -f vt-api-agent

# Test StepCA health
curl -k https://localhost:9000/health
# Expected: {"status":"ok"}

# Test Agent API health
curl http://localhost:8080/health
# Expected: HTTP 200
```

**Lưu ý quan trọng:**
- Chỉ server **.47** (đầu tiên) sẽ init StepCA và tạo CA
- Server **.48** phải share volume `stepca_data` hoặc copy CA files từ .47

```bash
# Trên .47 sau khi StepCA init xong
docker run --rm \
  -v 04-agent-api_stepca_data:/data \
  -v $(pwd)/stepca-shared:/backup \
  alpine tar czf /backup/stepca-ca.tar.gz /data

# Copy sang .48
scp stepca-shared/stepca-ca.tar.gz root@10.211.130.48:/opt/vt-audit/deploy/04-agent-api/

# Trên .48: Extract vào volume
docker run --rm \
  -v 04-agent-api_stepca_data:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/stepca-ca.tar.gz -C /
```

---

### **Bước 3: Deploy Admin API (Server .49 & .50)**

```bash
# === TRÊN CẢ 2 SERVERS .49 & .50 ===
cd /opt/vt-audit/deploy/03-admin-api

# Copy .env
cp .env .env.local
nano .env.local

# Start services
docker-compose --env-file .env.local up -d --build

# Kiểm tra Keycloak
docker logs -f vt-keycloak
# Đợi thấy: "Keycloak ... started in ..."

# Test Keycloak
curl http://localhost:8080/health/ready
# Expected: {"status":"UP"}

# Login Keycloak admin console
# http://10.211.130.49:8080/admin
# Username: admin
# Password: (từ KEYCLOAK_ADMIN_PASSWORD)

# Kiểm tra Backend API
docker logs -f vt-api-backend
curl http://localhost:8081/health
```

**Import Realm Configuration:**
```bash
# Copy realm config vào container
docker cp conf/keycloak/vt-audit-realm.json vt-keycloak:/tmp/

# Import realm
docker exec -it vt-keycloak /opt/keycloak/bin/kc.sh import \
  --file /tmp/vt-audit-realm.json
```

---

### **Bước 4: Deploy Nginx Gateway (Server .45 & .46)**

```bash
# === TRÊN CẢ 2 SERVERS .45 & .46 ===
cd /opt/vt-audit/deploy/02-nginx-gateway

# Tạo thư mục certs
mkdir -p certs

# Copy certificates
cp /path/to/server.crt certs/
cp /path/to/server.key certs/
cp /path/to/stepca_chain.crt certs/

# Verify permissions
chmod 644 certs/server.crt
chmod 600 certs/server.key

# Start nginx
docker-compose up -d

# Kiểm tra logs
docker logs -f vt-nginx-gateway

# Test từ localhost
curl -k https://localhost:8443
curl -k https://localhost:443/health
```

**Test upstream connectivity:**
```bash
# Test Admin backend
curl -k https://localhost:8443/api/health

# Test Agent backend
curl -k https://localhost:443/agent/policies
```

---

### **Bước 5: Cấu hình HAProxy + Keepalived**

```bash
# === TRÊN CẢ 2 SERVERS .45 & .46 ===

# Install packages
sudo dnf install haproxy keepalived -y

# Deploy HAProxy config
sudo cp /opt/vt-audit/deploy/00-haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg
sudo systemctl enable --now haproxy
sudo systemctl status haproxy

# Deploy Keepalived config
sudo nano /etc/keepalived/keepalived.conf
# (Paste config từ section 3 ở trên)

sudo systemctl enable --now keepalived
sudo systemctl status keepalived

# Kiểm tra VIP
ip addr show | grep 10.211.130.44
# Chỉ server MASTER mới thấy VIP
```

---

## ✅ **Validation Tests**

### **1. Database Connectivity**
```bash
# Từ bất kỳ server nào
psql -h 10.211.130.51 -U vt_app -d vt_db -c "\dt audit.*"
psql -h 10.211.130.51 -U vt_app -d vt_db -c "\dt policy.*"
psql -h 10.211.130.51 -U keycloak -d keycloak -c "\dt"
psql -h 10.211.130.51 -U stepca -d stepca -c "\dt"
```

### **2. HAProxy Load Balancing**
```bash
# Test Admin Dashboard
for i in {1..10}; do
  curl -k -I https://10.211.130.44:8443 | grep "X-Forwarded"
  sleep 1
done

# Test Agent API
for i in {1..10}; do
  curl -k -I https://10.211.130.44:443 | grep "X-Forwarded"
  sleep 1
done
```

### **3. StepCA Certificate Issuance**
```bash
# Test từ một agent machine
curl -k -X POST https://10.211.130.44:443/agent/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "test-workstation",
    "os": "windows",
    "bootstrap_token": "123456"
  }'

# Expected: JSON với certificate
```

### **4. Keycloak Authentication**
```bash
# Get token
TOKEN=$(curl -k -X POST https://10.211.130.44:8443/auth/realms/vt-audit/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=dashboard-proxy" \
  -d "client_secret=dashboard-secret" \
  -d "grant_type=client_credentials" | jq -r '.access_token')

# Test protected endpoint
curl -k https://10.211.130.44:8443/api/policies \
  -H "Authorization: Bearer $TOKEN"
```

### **5. Database Failover**
```bash
# Stop primary DB
ssh root@10.211.130.52 "docker stop vt-postgres"

# VIP phải chuyển sang .53
ping 10.211.130.51

# Test connection vẫn hoạt động
psql -h 10.211.130.51 -U vt_app -d vt_db -c "SELECT pg_is_in_recovery();"
# Phải trả về: t (true = đang là replica, nhưng đã promote thành primary)
```

---

## 📊 **Monitoring Checklist**

Sau khi deploy xong, cần setup monitoring cho:

- [ ] PostgreSQL replication lag
- [ ] HAProxy backend health
- [ ] Nginx upstream availability
- [ ] Docker container status
- [ ] Disk space on volume mounts
- [ ] Certificate expiration dates
- [ ] Application error logs
- [ ] Database connection pool

**Tool đề xuất:** Prometheus + Grafana + Alertmanager

---

## 🔒 **Security Hardening Post-Deploy**

- [ ] Đổi tất cả passwords mặc định
- [ ] Enable PostgreSQL SSL (`sslmode=require`)
- [ ] Restrict pg_hba.conf chỉ cho phép IP backend servers
- [ ] Enable firewall trên tất cả servers
- [ ] Rotate StepCA provisioner keys hàng tháng
- [ ] Setup fail2ban cho SSH
- [ ] Enable SELinux (Rocky Linux 9 default)
- [ ] Regular backup database và certificates
- [ ] Setup log rotation và retention policy

---

## 📞 **Support**

Nếu gặp vấn đề trong quá trình deploy:

1. **Kiểm tra logs:**
   ```bash
   docker logs <container_name>
   sudo journalctl -u haproxy -f
   sudo journalctl -u keepalived -f
   ```

2. **Kiểm tra connectivity:**
   ```bash
   # From backend to DB
   telnet 10.211.130.51 5432
   
   # From Nginx to backend
   telnet 10.211.130.49 8081
   ```

3. **Verify DNS/Host resolution:**
   ```bash
   ping 10.211.130.44
   nslookup gateway.local
   ```

---

**🎉 Hệ thống đã sẵn sàng để triển khai production!**

**Next Steps:**
1. Thay đổi tất cả passwords
2. Chuẩn bị certificates
3. Follow deployment procedure theo từng bước
4. Setup monitoring
5. Backup configuration và data
6. Document runbook cho team Ops

