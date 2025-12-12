# 🔍 Báo Cáo Rà Soát Config - Deploy Không Dùng Docker Network

**Ngày:** 2025-12-12  
**Mục đích:** Xóa docker network config và rà soát các vấn đề khi deploy trên server thật

---

## ✅ **Các Thay Đổi Đã Thực Hiện**

### 1. **Xóa Docker Network Config**

Đã xóa phần `networks:` khỏi tất cả `docker-compose.yml`:

| File | Trạng thái |
|------|------------|
| `01-database/docker-compose.yml` | ✅ Đã xóa |
| `02-nginx-gateway/docker-compose.yml` | ✅ Không có network config |
| `03-admin-api/docker-compose.yml` | ✅ Đã xóa |
| `04-agent-api/docker-compose.yml` | ✅ Đã xóa |

**Lý do:** Khi deploy trên server thật, các service giao tiếp qua IP thực tế, không cần docker network.

---

### 2. **Sửa Container Name References**

#### **04-agent-api/docker-compose.yml**
- ❌ **Trước:** `--stepca-url=https://stepca:9000`
- ✅ **Sau:** `--stepca-url=https://localhost:9000`

**Lý do:** StepCA và Agent API chạy trên cùng server, dùng `localhost` thay vì container name.

---

### 3. **Cập Nhật .env.example Files**

#### **03-admin-api/.env.example**
- ❌ **Trước:** `DB_HOST=vt-postgres`
- ✅ **Sau:** `DB_HOST=10.211.130.51`

- ❌ **Trước:** `OIDC_ISSUER_URL=http://vt-keycloak:8080/realms/vt-audit`
- ✅ **Sau:** `OIDC_ISSUER_URL=http://localhost:8080/realms/vt-audit`

- ✅ **Thêm:** `STEPCA_URL=https://10.211.130.44:443/step-ca`

#### **04-agent-api/.env.example**
- ❌ **Trước:** `DB_HOST=vt-postgres`
- ✅ **Sau:** `DB_HOST=10.211.130.51`

- ❌ **Trước:** `STEPCA_DNS_NAMES=localhost,vt-stepca,127.0.0.1`
- ✅ **Sau:** `STEPCA_DNS_NAMES=localhost,127.0.0.1`

---

## ⚠️ **Các Vấn Đề Cần Lưu Ý Khi Deploy**

### 1. **Firewall Rules**

**Vấn đề:** Các service giao tiếp qua IP, cần mở firewall ports.

**Giải pháp:**
```bash
# Database Server (10.211.130.51)
sudo firewall-cmd --permanent --add-port=5432/tcp
sudo firewall-cmd --reload

# Agent API Servers (.47, .48)
sudo firewall-cmd --permanent --add-port=8080/tcp --add-port=9000/tcp --add-port=8082/tcp
sudo firewall-cmd --reload

# Admin API Servers (.49, .50)
sudo firewall-cmd --permanent --add-port=8080/tcp --add-port=8081/tcp
sudo firewall-cmd --reload

# Nginx Gateway Servers (.45, .46)
sudo firewall-cmd --permanent --add-port=9443/tcp --add-port=9444/tcp
sudo firewall-cmd --reload
```

---

### 2. **Database Connection**

**Vấn đề:** Các service cần kết nối đến database server qua IP.

**Kiểm tra:**
```bash
# Từ Agent/Admin server, test kết nối DB
telnet 10.211.130.51 5432

# Hoặc dùng psql
psql -h 10.211.130.51 -U vt_app -d vt_db
```

**Lưu ý:**
- PostgreSQL phải listen trên `0.0.0.0` (đã config: `listen_addresses=*`)
- File `pg_hba.conf` phải cho phép remote connections

---

### 3. **Service Dependencies**

**Vấn đề:** `depends_on` vẫn hoạt động vì là trong cùng compose file, nhưng cần đảm bảo:

#### **03-admin-api:**
- `api-backend` depends_on `keycloak` → ✅ OK (cùng server)
- Keycloak phải start trước backend

#### **04-agent-api:**
- `api-agent` depends_on `stepca` → ✅ OK (cùng server)
- StepCA phải healthy trước khi agent start

**Lưu ý:** Health checks vẫn hoạt động bình thường.

---

### 4. **Nginx Upstream Configuration**

**Vấn đề:** Nginx cần trỏ đến IP thực tế của backend servers.

**Kiểm tra:**
```bash
# File: 02-nginx-gateway/conf/conf.d/00-upstream.conf
# Phải có IP production:
# - server 10.211.130.47:8080
# - server 10.211.130.49:8081
# - server 10.211.130.49:8080 (Keycloak)
```

**Lưu ý:** File `00-upstream.conf.local` dùng container names, chỉ dùng cho local test.

---

### 5. **SSL/TLS Certificates**

**Vấn đề:** StepCA dùng HTTPS, cần certificate chain.

**Kiểm tra:**
```bash
# Trên Agent API server (.47)
docker exec vt-stepca step ca health

# Export root certificate
docker exec vt-stepca step ca roots > stepca_root.crt

# Copy sang Nginx servers
scp stepca_root.crt user@10.211.130.45:/opt/vt-audit/deploy/02-nginx-gateway/certs/
```

---

### 6. **Volume Mounts**

**Vấn đề:** Volume mounts vẫn hoạt động bình thường vì là local volumes.

**Kiểm tra:**
```bash
# Database volume
docker volume inspect 01-database_db_data

# StepCA volume
docker volume inspect 04-agent-api_stepca_data
```

**Lưu ý:** 
- Volumes là local, không ảnh hưởng bởi network config
- Shared volume `stepca_data` giữa `stepca` và `api-agent` vẫn hoạt động (cùng compose file)

---

### 7. **Port Conflicts**

**Vấn đề:** Các port có thể bị conflict với services khác.

**Kiểm tra:**
```bash
# Check ports đang được sử dụng
netstat -tlnp | grep -E "5432|8080|8081|9000|9443|9444"

# Hoặc dùng ss
ss -tlnp | grep -E "5432|8080|8081|9000|9443|9444"
```

---

### 8. **Environment Variables**

**Vấn đề:** Các biến môi trường phải đúng với IP thực tế.

**Checklist:**
- [ ] `DB_HOST` = IP database server (10.211.130.51)
- [ ] `OIDC_ISSUER_URL` = localhost:8080 (nếu Keycloak cùng server) hoặc VIP
- [ ] `STEPCA_URL` = VIP hoặc IP StepCA server
- [ ] `STEPCA_DNS_NAMES` = không có container names

---

## 🧪 **Kiểm Tra Sau Khi Deploy**

### 1. **Database Connectivity**
```bash
# Từ Agent API server
docker exec vt-api-agent psql -h 10.211.130.51 -U vt_app -d vt_db -c "SELECT 1;"

# Từ Admin API server
docker exec vt-api-backend psql -h 10.211.130.51 -U vt_app -d vt_db -c "SELECT 1;"
```

### 2. **StepCA Health**
```bash
# Trên Agent API server
curl -k https://localhost:9000/health
docker exec vt-stepca step ca health
```

### 3. **Keycloak Health**
```bash
# Trên Admin API server
curl http://localhost:8080/health/ready
```

### 4. **Backend Services**
```bash
# Agent API
curl http://localhost:8080/health

# Admin Backend
curl http://localhost:8081/
```

### 5. **Nginx Upstream**
```bash
# Trên Nginx server
docker exec vt-nginx-gateway nginx -t
docker exec vt-nginx-gateway curl http://10.211.130.47:8080/health
docker exec vt-nginx-gateway curl http://10.211.130.49:8081/
```

---

## 📋 **Checklist Trước Khi Deploy**

- [ ] Xóa docker network config (✅ Đã xong)
- [ ] Sửa container name references (✅ Đã xong)
- [ ] Cập nhật .env.example với IP thực tế (✅ Đã xong)
- [ ] Mở firewall ports trên tất cả servers
- [ ] Kiểm tra PostgreSQL `pg_hba.conf` cho phép remote connections
- [ ] Tạo SSL certificates cho Nginx
- [ ] Export StepCA root certificate
- [ ] Copy StepCA cert sang Nginx servers
- [ ] Kiểm tra Nginx upstream config có IP production
- [ ] Test kết nối database từ các servers
- [ ] Test health checks của tất cả services

---

## 🚨 **Các Lỗi Có Thể Gặp**

### **Lỗi 1: Connection Refused**
```
Error: dial tcp 10.211.130.51:5432: connect: connection refused
```

**Nguyên nhân:** 
- Firewall chưa mở port
- PostgreSQL không listen trên interface đó
- `pg_hba.conf` không cho phép remote connection

**Giải pháp:**
```bash
# Check firewall
sudo firewall-cmd --list-ports

# Check PostgreSQL listen
docker exec vt-postgres netstat -tlnp | grep 5432

# Check pg_hba.conf
docker exec vt-postgres cat /var/lib/postgresql/data/pg_hba.conf | grep -E "host|all"
```

---

### **Lỗi 2: Name Resolution Failed**
```
Error: dial tcp: lookup stepca: no such host
```

**Nguyên nhân:** Vẫn còn dùng container name thay vì IP/localhost

**Giải pháp:** Kiểm tra lại:
- `docker-compose.yml` không có `stepca:9000`
- `.env` file không có container names
- Nginx upstream config dùng IP

---

### **Lỗi 3: SSL Certificate Error**
```
Error: x509: certificate signed by unknown authority
```

**Nguyên nhân:** StepCA root certificate chưa được copy sang Nginx

**Giải pháp:**
```bash
# Export từ StepCA server
docker exec vt-stepca step ca roots > stepca_root.crt

# Copy sang Nginx servers
scp stepca_root.crt user@10.211.130.45:/opt/vt-audit/deploy/02-nginx-gateway/certs/stepca_chain.crt
```

---

## 📝 **Tóm Tắt**

✅ **Đã hoàn thành:**
- Xóa docker network config
- Sửa container name references
- Cập nhật .env.example files

⚠️ **Cần làm khi deploy:**
- Mở firewall ports
- Kiểm tra database connectivity
- Tạo/copy SSL certificates
- Test tất cả health checks

---

**Lưu ý cuối:** Tất cả config hiện tại đã sẵn sàng cho production deployment, chỉ cần:
1. Copy `.env.example` → `.env` và điền IP thực tế
2. Mở firewall ports
3. Tạo SSL certificates
4. Deploy theo thứ tự: Database → Agent API → Admin API → Nginx Gateway

