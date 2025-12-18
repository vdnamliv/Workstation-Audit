# ============================================
# PRODUCTION DEPLOYMENT - UPDATED FILES
# ============================================

## 🎯 OVERVIEW
Đã cập nhật cấu hình để sử dụng IP thật thay vì Docker network names.

## 📝 CHANGES MADE

### 1. Server .47 (Agent API) - File thay đổi:
   - `deploy/04-agent-api/.env`
   - `deploy/04-agent-api/docker-compose.yml`
   
   **Key changes:**
   - DB_HOST: vt-postgres → 10.211.130.51 (VIP DB)
   - GATEWAY_HOST: vt-nginx-gateway → 10.211.130.44 (VIP Gateway)
   - STEPCA_DNS_NAMES: Thêm tất cả IP production
   - stepca-external-url: Đổi port 443 → 9443 (HAProxy agent port)

### 2. Server .49 (Admin API) - File thay đổi:
   - `deploy/03-admin-api/.env`
   - `deploy/03-admin-api/docker-compose.yml`
   
   **Key changes:**
   - DB_HOST: vt-postgres → 10.211.130.51 (VIP DB)
   - GATEWAY_HOST: vt-nginx-gateway → 10.211.130.44 (VIP Gateway)
   - OIDC_ISSUER_URL: vt-keycloak → keycloak (tên service trong cùng docker-compose)
   - STEPCA_URL: https://10.211.130.44:9443
   - KC_HOSTNAME: 10.211.130.44 (VIP Gateway)
   - KC_HOSTNAME_PORT: 8443 (HAProxy admin web port)

### 3. New Scripts:
   - `deploy/04-agent-api/restart-production.sh`
   - `deploy/03-admin-api/restart-production.sh`
   - `deploy/production-checklist.sh`

## 🚀 DEPLOYMENT STEPS

### Bước 1: Copy files về servers

**Server .47 (Agent API):**
```bash
cd /root/vt-audit/deploy/04-agent-api/
# Backup file cũ
cp .env .env.backup-$(date +%Y%m%d-%H%M%S)
cp docker-compose.yml docker-compose.yml.backup-$(date +%Y%m%d-%H%M%S)

# Copy file mới từ Windows (dùng WinSCP/scp)
# Hoặc dùng vim/nano để paste nội dung
```

**Server .49 (Admin API):**
```bash
cd /root/vt-audit/deploy/03-admin-api/
# Backup file cũ
cp .env .env.backup-$(date +%Y%m%d-%H%M%S)
cp docker-compose.yml docker-compose.yml.backup-$(date +%Y%m%d-%H%M%S)

# Copy file mới từ Windows
```

### Bước 2: Verify network connectivity

```bash
# Test từ server .47
ping -c 2 10.211.130.51   # DB VIP
ping -c 2 10.211.130.44   # Gateway VIP
ping -c 2 10.211.130.49   # Keycloak server

# Test từ server .49
ping -c 2 10.211.130.51   # DB VIP
ping -c 2 10.211.130.44   # Gateway VIP

# Test DB connection
psql -h 10.211.130.51 -U vt_app -d vt_db -c "SELECT 1;"
```

### Bước 3: Restart services

**Server .49 (Admin API) - Restart trước vì Keycloak cần healthy:**
```bash
cd /root/vt-audit/deploy/03-admin-api/
chmod +x restart-production.sh
./restart-production.sh

# Monitor logs
docker logs -f vt-keycloak
# Ctrl+C để thoát

docker logs -f vt-api-backend
```

**Server .47 (Agent API) - Restart sau:**
```bash
cd /root/vt-audit/deploy/04-agent-api/
chmod +x restart-production.sh
./restart-production.sh

# Monitor logs
docker logs -f vt-stepca
# Ctrl+C để thoát

docker logs -f vt-api-agent
```

### Bước 4: Verify health

```bash
# Check container status
docker compose ps

# Should see:
# - vt-keycloak: healthy
# - vt-api-backend: running
# - vt-stepca: healthy (ignore TLS handshake errors - đó là healthcheck)
# - vt-api-agent: running

# Check if errors are gone:
docker logs vt-api-agent --tail 50 | grep -i error
docker logs vt-api-backend --tail 50 | grep -i error
```

## ⚠️ EXPECTED BEHAVIORS

### Normal (không phải lỗi):
1. **step-ca TLS handshake errors** - Đây là do healthcheck, bình thường
2. **Keycloak startup takes 60-90s** - Health check có start_period: 60s

### Errors đã fix:
1. ✅ "lookup keycloak" error - Fixed bằng cách dùng KEYCLOAK_HOST IP
2. ✅ "connection refused localhost:8080" - Fixed bằng cách dùng service name "keycloak"
3. ✅ DB connection issues - Fixed bằng DB_HOST VIP

## 🔍 TROUBLESHOOTING

### Nếu agent-api vẫn báo "lookup keycloak":
```bash
# Kiểm tra .env đã đúng chưa
grep KEYCLOAK_HOST /root/vt-audit/deploy/04-agent-api/.env
# Phải ra: KEYCLOAK_HOST=10.211.130.49

# Restart lại
docker compose down && docker compose up -d
```

### Nếu admin-api không connect được keycloak:
```bash
# Kiểm tra keycloak healthy
docker exec vt-keycloak curl -f http://localhost:8080/health/ready

# Kiểm tra network
docker network ls
docker network inspect 03-admin-api_default

# api-backend và keycloak phải cùng network
```

### Nếu không connect được DB:
```bash
# Test từ container
docker exec vt-api-backend ping -c 2 10.211.130.51

# Test DB connection
docker exec vt-api-backend psql -h 10.211.130.51 -U vt_app -d vt_db -c "SELECT 1;"
```

## 📋 NEXT STEPS

1. ✅ Database deployed (.52)
2. ✅ Agent API deployed (.47) - Cần restart với config mới
3. ✅ Admin API deployed (.49) - Cần restart với config mới
4. ⏳ Nginx Gateway deploy (.45 & .46) - Chưa deploy
5. ⏳ HAProxy + Keepalived setup
6. ⏳ Testing end-to-end

## 📞 SUPPORT

Nếu có lỗi, gửi:
1. Output của: `docker compose ps`
2. Logs: `docker logs <container-name> --tail 100`
3. .env file (che password)
