# 🧪 Local Test Environment Guide

Hướng dẫn chi tiết để test toàn bộ hệ thống VT-Audit trên môi trường local trước khi deploy production.

---

## 📋 Prerequisites

### 1. **Docker Desktop**
- ✅ Docker Desktop phải đang chạy
- ✅ Minimum: 8GB RAM, 50GB disk space
- ✅ WSL2 backend (recommended for Windows)

### 2. **Kiểm tra Docker**
```powershell
docker --version
docker compose version
```

---

## 🚀 Quick Start (Automated)

### **Bước 1: Switch sang Local mode**
```powershell
cd c:\Users\admin\Desktop\vt-audit\deploy
.\switch-to-local.ps1
```

Script này sẽ:
- ✅ Tạo Docker network `vt-system-net`
- ✅ Backup config production sang `.production` files
- ✅ Kích hoạt config local (`.env.local`, `00-upstream.conf.local`)

### **Bước 2: Start toàn bộ hệ thống**
```powershell
.\start-system.ps1
```

Script này sẽ:
1. Start Database (PostgreSQL)
2. Start Agent API + StepCA
3. Start Admin API + Keycloak
4. Start Nginx Gateway

⏱️ **Thời gian:** Khoảng 2-3 phút

### **Bước 3: Access hệ thống**
- 🌐 **Admin Dashboard:** https://localhost:8443
- 🔐 **Keycloak Admin:** http://localhost:8080/admin
  - Username: `admin`
  - Password: `admin123`
- 🔌 **Agent API:** https://localhost:443
- 🗄️ **Database:** `localhost:5432`

---

## 🛠️ Manual Start (Step by Step)

Nếu muốn kiểm soát từng bước:

### **Bước 1: Tạo Network**
```powershell
docker network create vt-system-net
```

### **Bước 2: Switch config**
```powershell
.\switch-to-local.ps1
```

### **Bước 3: Start Database**
```powershell
cd 01-database
docker compose up -d
cd ..
```

**Verify:**
```powershell
docker logs vt-postgres
docker exec vt-postgres psql -U postgres -l
```
Phải thấy: `keycloak`, `stepca`, `vt_db`

### **Bước 4: Start Agent API**
```powershell
cd 04-agent-api
docker compose up -d
cd ..
```

**Verify:**
```powershell
docker logs vt-stepca
docker logs vt-api-agent

# Test StepCA health
curl -k https://localhost:9000/health
```

### **Bước 5: Start Admin API**
```powershell
cd 03-admin-api
docker compose up -d
cd ..
```

**Verify:**
```powershell
docker logs vt-keycloak
docker logs vt-api-backend

# Test Keycloak
curl http://localhost:8080/health/ready
```

### **Bước 6: Start Nginx**
```powershell
cd 02-nginx-gateway
docker compose up -d
cd ..
```

**Verify:**
```powershell
docker logs vt-nginx-gateway

# Test endpoints
curl -k https://localhost:8443
curl -k https://localhost:443
```

---

## 🔍 Debugging Commands

### **View all logs**
```powershell
.\start-system.ps1 -Logs
```

### **View specific container logs**
```powershell
docker logs vt-postgres -f        # Database
docker logs vt-stepca -f          # StepCA
docker logs vt-api-agent -f       # Agent API
docker logs vt-keycloak -f        # Keycloak
docker logs vt-api-backend -f     # Admin API
docker logs vt-nginx-gateway -f   # Nginx
```

### **Check container status**
```powershell
docker ps --filter "name=vt-"
```

### **Check network**
```powershell
docker network inspect vt-system-net
```

### **Enter container shell**
```powershell
docker exec -it vt-postgres bash
docker exec -it vt-keycloak bash
docker exec -it vt-stepca bash
```

### **Database queries**
```powershell
# Connect to database
docker exec -it vt-postgres psql -U postgres

# List databases
\l

# Connect to vt_db
\c vt_db

# List tables
\dt audit.*
\dt policy.*

# Check users
\du
```

---

## 🧹 Cleanup

### **Stop all services**
```powershell
.\start-system.ps1 -Stop
```

### **Remove all containers and volumes (DANGER!)**
```powershell
cd 01-database
docker compose down -v
cd ../02-nginx-gateway
docker compose down -v
cd ../03-admin-api
docker compose down -v
cd ../04-agent-api
docker compose down -v
cd ..

# Remove network
docker network rm vt-system-net
```

### **Switch back to Production mode**
```powershell
.\switch-to-production.ps1
```

---

## 🧪 Testing Checklist

### **1. Database Tests**
```powershell
# Connect và verify tables
docker exec -it vt-postgres psql -U postgres -d vt_db -c "\dt audit.*"
docker exec -it vt-postgres psql -U postgres -d vt_db -c "\dt policy.*"

# Check users
docker exec -it vt-postgres psql -U postgres -c "\du"
```

### **2. Keycloak Tests**
```powershell
# Access admin console
Start-Process "http://localhost:8080/admin"

# Login: admin / admin123

# Import realm (if needed)
docker cp 03-admin-api/conf/keycloak/vt-audit-realm.json vt-keycloak:/tmp/
docker exec -it vt-keycloak /opt/keycloak/bin/kc.sh import --file /tmp/vt-audit-realm.json
```

### **3. StepCA Tests**
```powershell
# Health check
curl -k https://localhost:9000/health

# Get CA root certificate
curl -k https://localhost:9000/roots > ca-root.pem
```

### **4. Agent API Tests**
```powershell
# Test enrollment endpoint
curl -k -X POST https://localhost:443/agent/enroll `
  -H "Content-Type: application/json" `
  -d '{"hostname":"test-pc","os":"windows","bootstrap_token":"test123456"}'

# Test policies endpoint
curl -k https://localhost:443/agent/policies
```

### **5. Admin API Tests**
```powershell
# Test health
curl http://localhost:8081/health

# Test through Nginx
curl -k https://localhost:8443/api/health
```

### **6. Nginx Gateway Tests**
```powershell
# Test Admin dashboard route
curl -k -I https://localhost:8443

# Test Agent route
curl -k -I https://localhost:443

# Test Keycloak route
curl -k https://localhost:8443/auth/realms/vt-audit/.well-known/openid-configuration
```

---

## 📊 Expected Behavior

### **Container Status**
```
NAME                STATUS              PORTS
vt-postgres         Up (healthy)        5432
vt-stepca           Up (healthy)        9000
vt-api-agent        Up                  8080, 8082
vt-keycloak         Up (healthy)        8080
vt-api-backend      Up                  8081
vt-nginx-gateway    Up                  443, 8443
```

### **Network Connectivity**
```
vt-nginx-gateway → vt-api-backend:8081
vt-nginx-gateway → vt-keycloak:8080
vt-nginx-gateway → vt-api-agent:8080
vt-api-backend → vt-postgres:5432
vt-api-agent → vt-postgres:5432
vt-keycloak → vt-postgres:5432
vt-stepca → vt-postgres:5432
```

---

## ⚠️ Common Issues

### **Issue 1: Port already in use**
```
Error: bind: address already in use
```

**Solution:**
```powershell
# Check what's using the port
netstat -ano | findstr ":8443"
netstat -ano | findstr ":443"

# Stop the conflicting service or change ports in docker-compose
```

### **Issue 2: Database not ready**
```
FATAL: database "keycloak" does not exist
```

**Solution:**
```powershell
# Check if init script ran
docker logs vt-postgres | Select-String "keycloak|stepca|vt_db"

# If not, recreate database
docker compose -f 01-database/docker-compose.yml down -v
docker compose -f 01-database/docker-compose.yml up -d
```

### **Issue 3: Keycloak won't start**
```
KC_HOSTNAME or KC_HOSTNAME_URL must be set
```

**Solution:**
```powershell
# Check .env file has KC_HOSTNAME_* variables
cat 03-admin-api\.env | Select-String "KC_HOSTNAME"

# Restart Keycloak
docker restart vt-keycloak
```

### **Issue 4: Nginx 502 Bad Gateway**
```
upstream: "vt-api-backend:8081" failed (Name does not resolve)
```

**Solution:**
```powershell
# Verify all containers are in same network
docker network inspect vt-system-net

# Verify upstream container is running
docker ps --filter "name=vt-api-backend"

# Restart Nginx
docker restart vt-nginx-gateway
```

### **Issue 5: StepCA won't initialize**
```
error initializing db: connection refused
```

**Solution:**
```powershell
# Wait longer for database
Start-Sleep -Seconds 30
docker restart vt-stepca

# Check StepCA logs
docker logs vt-stepca
```

---

## 🔐 Security Notes for Local Test

⚠️ **Local test sử dụng passwords mặc định - KHÔNG dùng cho production!**

**Passwords trong local test:**
- Database superuser: `postgres` / `ChangeMe_SuperSecret_DB!`
- DB user (vt_app): `vt_app` / `ChangeMe_VT_App!`
- DB user (keycloak): `keycloak` / `ChangeMe123!`
- DB user (stepca): `stepca` / `ChangeMe_StepCA_DB!`
- Keycloak admin: `admin` / `admin123`
- Agent bootstrap token: `test123456`

**Trước khi deploy production:**
1. ✅ Đổi TẤT CẢ passwords
2. ✅ Generate strong bootstrap token
3. ✅ Use production certificates (not self-signed)
4. ✅ Enable SSL/TLS for database connections
5. ✅ Restrict network access

---

## 📚 Next Steps

Sau khi test local thành công:

1. **Switch back to Production:**
   ```powershell
   .\switch-to-production.ps1
   ```

2. **Update production configs:**
   - [ ] Change all passwords in `.env` files
   - [ ] Update IP addresses in `.env` files
   - [ ] Update Nginx upstream to use production IPs
   - [ ] Prepare production TLS certificates

3. **Deploy to Production:**
   - Follow `VALIDATION_REPORT.md` deployment guide
   - Deploy components in correct order
   - Verify each component before proceeding

---

## 📞 Support

Nếu gặp vấn đề:

1. Check logs: `.\start-system.ps1 -Logs`
2. Verify network: `docker network inspect vt-system-net`
3. Restart specific service: `docker restart <container_name>`
4. Full restart: `.\start-system.ps1 -Restart`
5. Clean start: `.\start-system.ps1 -Stop` then `.\start-system.ps1`

---

**Happy Testing! 🎉**
