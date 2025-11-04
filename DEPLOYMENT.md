# Hướng Dẫn Deploy Production - VT Audit System

## Mục Lục
1. [Yêu Cầu Hệ Thống](#yêu-cầu-hệ-thống)
2. [Cấu Hình Biến Môi Trường](#cấu-hình-biến-môi-trường)
3. [Các Lỗi Thường Gặp và Cách Khắc Phục](#các-lỗi-thường-gặp-và-cách-khắc-phục)
4. [Quy Trình Deploy](#quy-trình-deploy)
5. [Kiểm Tra và Xác Nhận](#kiểm-tra-và-xác-nhận)

---

## Yêu Cầu Hệ Thống

### Phần Mềm Cần Thiết
- Docker Engine >= 20.10
- Docker Compose >= 2.0
- OpenSSL (để tạo secrets)
- Linux với quyền sudo hoặc user thuộc group docker

### Quyền Truy Cập Docker
```bash
# Kiểm tra quyền hiện tại
groups

# Nếu không thấy 'docker', thêm user vào group docker
sudo usermod -aG docker $USER

# Hoặc chạy docker với sudo
sudo docker compose up -d
```

---

## Cấu Hình Biến Môi Trường

### Bước 1: Tạo File .env

Tạo file `.env` trong thư mục `env/` với nội dung sau:

```bash
cd env/
cp .env.example .env  # Nếu có file example
# Hoặc tạo mới
nano .env
```

### Bước 2: Cấu Hình Chi Tiết

#### 1. Database Configuration (PostgreSQL)

```properties
# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

# Tên database chính (QUAN TRỌNG: Phải là "audit" để khớp với init scripts)
POSTGRES_DB=audit

# Username cho PostgreSQL
POSTGRES_USER=audit

# Password cho PostgreSQL (ĐỔI MẬT KHẨU NÀY!)
POSTGRES_PASSWORD=DatabasePassword123!SecureDB2025

# Connection string (cập nhật password phải khớp với POSTGRES_PASSWORD)
POSTGRES_DSN=postgres://audit:DatabasePassword123!SecureDB2025@postgres:5432/audit?sslmode=disable

# Cấu hình kết nối
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_SSLMODE=disable
```

**⚠️ LƯU Ý QUAN TRỌNG:**
- `POSTGRES_DB` phải là `audit` (không phải tên khác)
- Lý do: Init scripts trong `conf/postgres/init/20_grants.sql` hardcode tên database là `audit`
- Password trong `POSTGRES_DSN` phải khớp với `POSTGRES_PASSWORD`

#### 2. Keycloak Configuration

```properties
# =============================================================================
# KEYCLOAK AUTHENTICATION
# =============================================================================

# Database cho Keycloak (PHẢI là "audit" - cùng database với app)
KEYCLOAK_DB=audit

# Username database cho Keycloak (PHẢI là "keycloak")
KEYCLOAK_DB_USER=keycloak

# Password (PHẢI là "ChangeMe123!" để khớp với 20_grants.sql)
KEYCLOAK_DB_PASSWORD=ChangeMe123!

# Admin credentials để đăng nhập Keycloak console
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=AdminKeycloak123!Secure2025

# Realm name
KEYCLOAK_REALM=vt-audit
```

**⚠️ LƯU Ý QUAN TRỌNG:**
- `KEYCLOAK_DB_PASSWORD` phải là `ChangeMe123!` vì được hardcode trong `conf/postgres/init/20_grants.sql`
- Nếu muốn đổi password, phải sửa cả file SQL script
- `KEYCLOAK_DB_USER` phải là `keycloak`

#### 3. Certificate Authority (Step-CA) Configuration

```properties
# =============================================================================
# CERTIFICATE AUTHORITY CONFIGURATION
# =============================================================================

# Tên CA
STEPCA_NAME=VT-Audit Certificate Authority

# DNS names cho certificates (QUAN TRỌNG: Mỗi tên phân cách bằng dấu phẩy, KHÔNG có khoảng trắng)
STEPCA_DNS_NAMES=gateway.local,stepca,api-agent,localhost

# Provisioner name
STEPCA_PROVISIONER=bootstrap@vt-audit

# URLs
STEPCA_URL=https://stepca:9000
STEPCA_EXTERNAL_URL=https://gateway.local/step-ca

# Passwords (ĐỔI CÁC MẬT KHẨU NÀY!)
STEPCA_PASSWORD=StepCA123!SecurePassword2025
STEPCA_PROVISIONER_PASSWORD=ChangeMe123!SecurePassword2025

# Key path
STEPCA_KEY_PATH=/stepca/secrets/provisioner.key

# Certificate validity
MTLS_CERT_TTL=24h
CERTIFICATE_VALIDITY_HOURS=24
```

**⚠️ LƯU Ý QUAN TRỌNG:**
- `STEPCA_DNS_NAMES`: KHÔNG được có khoảng trắng sau dấu phẩy
- ✅ Đúng: `gateway.local,stepca,api-agent,localhost`
- ❌ SAI: `gateway.local, stepca, api-agent, localhost` (có khoảng trắng)
- Nếu có khoảng trắng, certificate sẽ không hợp lệ

#### 4. OAuth2/OIDC Configuration

```properties
# =============================================================================
# OAUTH2 / OIDC CONFIGURATION
# =============================================================================

# Client ID cho OAuth2 proxy
OIDC_CLIENT_ID=dashboard-proxy

# Client Secret (tạo secret ngẫu nhiên mạnh)
OIDC_CLIENT_SECRET=replace-with-real-secret-min-32-chars

# Cookie Secret (PHẢI là 32 ký tự hex - 16 bytes)
OIDC_COOKIE_SECRET=7af56af96c655e4fed37b71f1500ab27

# OIDC issuer và roles
OIDC_ISSUER=https://gateway.local/auth/realms/vt-audit
OIDC_ADMIN_ROLE=admin
```

**⚠️ LƯU Ý QUAN TRỌNG về OIDC_COOKIE_SECRET:**

OAuth2-proxy yêu cầu cookie_secret phải có độ dài chính xác 16, 24, hoặc 32 bytes.

**Cách tạo cookie secret hợp lệ:**

```bash
# Tạo secret 32 ký tự hex (16 bytes) - KHUYẾN NGHỊ
openssl rand -hex 16

# Hoặc tạo 48 ký tự hex (24 bytes)
openssl rand -hex 24

# Hoặc tạo 64 ký tự hex (32 bytes)
openssl rand -hex 32
```

**❌ KHÔNG sử dụng:**
- Base64 random strings (thường có độ dài không chuẩn)
- Strings có ký tự đặc biệt như `+`, `/`, `=`
- Strings có độ dài khác 32, 48, hoặc 64 ký tự

**Ví dụ secret hợp lệ:**
```
7af56af96c655e4fed37b71f1500ab27  (32 chars = 16 bytes) ✅
```

#### 5. Agent Configuration

```properties
# =============================================================================
# AGENT CONFIGURATION
# =============================================================================

# Bootstrap token để agents kết nối lần đầu (ĐỔI TOKEN NÀY!)
AGENT_BOOTSTRAP_TOKEN=set-a-strong-secret-token-here
```

---

## Các Lỗi Thường Gặp và Cách Khắc Phục

### Lỗi 1: Permission Denied khi chạy Docker

**Triệu chứng:**
```
permission denied while trying to connect to the Docker daemon socket
```

**Nguyên nhân:** User không có quyền truy cập Docker

**Giải pháp:**
```bash
# Cách 1: Thêm user vào group docker (khuyến nghị)
sudo usermod -aG docker $USER
# Sau đó logout và login lại

# Cách 2: Chạy với sudo
sudo docker compose up -d
```

### Lỗi 2: File .env bị lỗi format

**Triệu chứng:**
- Biến môi trường bị nối liền nhau
- Certificate có SAN không hợp lệ như: `localhostOIDC_CLIENT_SECRET=xxx`

**Nguyên nhân:** File .env bị copy/paste sai, mất line breaks

**Giải pháp:**
```bash
# Kiểm tra file có bị lỗi không
cat -A .env | grep -E '\$OIDC'

# Nếu thấy các dòng nối liền, tạo lại file từ template
# Hoặc sử dụng editor hỗ trợ Unix line endings (LF)
dos2unix .env  # Nếu có dos2unix
```

### Lỗi 3: Keycloak không kết nối được database

**Triệu chứng:**
```
FATAL: password authentication failed for user "keycloak"
```

**Nguyên nhân:** Password trong `.env` không khớp với password trong init script

**Giải pháp:**

**Option 1: Sử dụng password mặc định (nhanh nhất)**
```properties
KEYCLOAK_DB_PASSWORD=ChangeMe123!
```

**Option 2: Thay đổi password trong init script**

Sửa file `env/conf/postgres/init/20_grants.sql`:
```sql
CREATE ROLE keycloak LOGIN PASSWORD 'your-new-password';
```

Sau đó cập nhật `.env`:
```properties
KEYCLOAK_DB_PASSWORD=your-new-password
```

### Lỗi 4: Step-CA Healthcheck Failed

**Triệu chứng:**
```
certificate is valid for gateway.local,stepca,...,localhostOIDC_CLIENT_SECRET=xxx, not localhost
```

**Nguyên nhân:** `STEPCA_DNS_NAMES` có khoảng trắng sau dấu phẩy

**Giải pháp:**
```properties
# ❌ SAI
STEPCA_DNS_NAMES=gateway.local, stepca, localhost

# ✅ ĐÚNG (không có khoảng trắng)
STEPCA_DNS_NAMES=gateway.local,stepca,localhost
```

Sau khi sửa, xóa certificates cũ và restart:
```bash
sudo rm -f certs/nginx/*.crt certs/nginx/*.key
sudo docker compose down -v
sudo docker compose up -d
```

### Lỗi 5: OIDC Proxy Restarting Loop

**Triệu chứng:**
```
cookie_secret must be 16, 24, or 32 bytes to create an AES cipher, but is XX bytes
```

**Nguyên nhân:** Cookie secret không đúng độ dài

**Giải pháp:**
```bash
# Tạo secret mới với độ dài chính xác
openssl rand -hex 16

# Cập nhật vào .env
OIDC_COOKIE_SECRET=<output từ lệnh trên>

# Recreate container
sudo docker compose stop oidc-proxy
sudo docker compose rm -f oidc-proxy
sudo docker compose up -d oidc-proxy
```

### Lỗi 6: Postgres Container Unhealthy

**Triệu chứng:**
```
database "audit" does not exist
```

**Nguyên nhân:** Tên database trong `.env` không phải là "audit"

**Giải pháp:**
```properties
# Phải sử dụng tên database này
POSTGRES_DB=audit
POSTGRES_DSN=postgres://audit:password@postgres:5432/audit?sslmode=disable
```

---

## Quy Trình Deploy

### Bước 1: Chuẩn Bị File .env

```bash
# Di chuyển vào thư mục env
cd /path/to/Workstation-Audit/env

# Backup file .env cũ (nếu có)
cp .env .env.backup.$(date +%Y%m%d_%H%M%S)

# Tạo file .env mới theo template ở trên
nano .env
```

### Bước 2: Tạo Các Secrets

```bash
# Tạo PostgreSQL password
echo "PostgreSQL Password: $(openssl rand -base64 24)"

# Tạo Keycloak admin password
echo "Keycloak Admin Password: $(openssl rand -base64 24)"

# Tạo Step-CA passwords
echo "Step-CA Password: $(openssl rand -base64 24)"
echo "Step-CA Provisioner Password: $(openssl rand -base64 24)"

# Tạo OIDC Cookie Secret (32 chars hex)
echo "OIDC Cookie Secret: $(openssl rand -hex 16)"

# Tạo OAuth Client Secret
echo "OAuth Client Secret: $(openssl rand -base64 32)"

# Tạo Agent Bootstrap Token
echo "Agent Bootstrap Token: $(openssl rand -base64 32)"
```

Sao chép các secrets này vào file `.env` tương ứng.

### Bước 3: Validate File .env

```bash
# Kiểm tra các biến quan trọng
echo "Checking POSTGRES_DB..."
grep "^POSTGRES_DB=" .env

echo "Checking KEYCLOAK_DB_PASSWORD..."
grep "^KEYCLOAK_DB_PASSWORD=" .env

echo "Checking STEPCA_DNS_NAMES..."
grep "^STEPCA_DNS_NAMES=" .env

echo "Checking OIDC_COOKIE_SECRET..."
COOKIE_SECRET=$(grep "^OIDC_COOKIE_SECRET=" .env | cut -d= -f2)
echo "Cookie secret length: ${#COOKIE_SECRET} chars (should be 32, 48, or 64)"
```

### Bước 4: Dọn Dẹp Môi Trường Cũ (Nếu Có)

```bash
# Dừng và xóa containers cũ
sudo docker compose down -v

# Xóa certificates cũ
sudo rm -f certs/nginx/*.crt certs/nginx/*.key

# Xóa volumes cũ (nếu cần reset hoàn toàn)
sudo docker volume prune -f
```

### Bước 5: Deploy

```bash
# Deploy tất cả services
sudo docker compose up -d

# Theo dõi logs
sudo docker compose logs -f
```

### Bước 6: Chờ Services Khởi Động

Services sẽ khởi động theo thứ tự:
1. PostgreSQL (healthy sau ~10s)
2. Step-CA (healthy sau ~15-30s)
3. Keycloak (healthy sau ~60-90s)
4. Backend services
5. OIDC Proxy
6. Nginx

**Tổng thời gian:** ~2-3 phút cho toàn bộ stack

---

## Kiểm Tra và Xác Nhận

### Bước 1: Kiểm Tra Trạng Thái Containers

```bash
# Xem tất cả containers
sudo docker compose ps

# Kiểm tra chi tiết
sudo docker ps --format "table {{.Names}}\t{{.Status}}"
```

**Kết quả mong đợi:**
```
NAMES               STATUS
vt-nginx            Up X minutes
vt-oidc-proxy       Up X minutes
vt-api-backend      Up X minutes
vt-keycloak         Up X minutes (healthy)
vt-enroll-gateway   Up X minutes
vt-api-agent        Up X minutes
vt-postgres         Up X minutes (healthy)
vt-stepca           Up X minutes (healthy)
```

### Bước 2: Kiểm Tra Logs

```bash
# Kiểm tra logs của từng service
sudo docker logs vt-postgres | tail -20
sudo docker logs vt-stepca | tail -20
sudo docker logs vt-keycloak | tail -20
sudo docker logs vt-oidc-proxy | tail -20
sudo docker logs vt-nginx | tail -20

# Kiểm tra lỗi
sudo docker compose logs | grep -i error
sudo docker compose logs | grep -i failed
```

### Bước 3: Kiểm Tra Kết Nối

```bash
# Test PostgreSQL
sudo docker exec vt-postgres psql -U audit -d audit -c "SELECT version();"

# Test Step-CA
curl -k https://localhost:9000/health

# Test Nginx (từ host)
curl -k https://localhost:443

# Kiểm tra certificates
sudo docker exec vt-stepca step ca health --ca-url https://localhost:9000 --root /home/step/certs/root_ca.crt
```

### Bước 4: Truy Cập Web UI

Thêm entry vào `/etc/hosts`:
```bash
echo "127.0.0.1 gateway.local" | sudo tee -a /etc/hosts
```

Truy cập:
- **Admin UI:** https://gateway.local/
- **Keycloak Console:** https://gateway.local/auth/
- **Step-CA:** https://gateway.local:9000/

### Bước 5: Kiểm Tra Ports

```bash
# Kiểm tra các ports đang listen
sudo ss -tlnp | grep -E '443|8443|8742|5432|9000'
```

**Ports mong đợi:**
- `443` - HTTPS Admin/UI
- `8443` - Agent mTLS
- `8742` - HTTP enrollment
- `5432` - PostgreSQL
- `9000` - Step-CA

---

## Template File .env Hoàn Chỉnh

```properties
# =============================================================================
# VT-AUDIT PRODUCTION ENVIRONMENT CONFIGURATION
# =============================================================================
# NEVER commit .env file to version control - it contains sensitive data

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

# PostgreSQL database settings (MUST change passwords)
POSTGRES_DB=audit
POSTGRES_USER=audit
POSTGRES_PASSWORD=DatabasePassword123!SecureDB2025
POSTGRES_DSN=postgres://audit:DatabasePassword123!SecureDB2025@postgres:5432/audit?sslmode=disable

# Database connection settings
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_SSLMODE=disable

# =============================================================================
# KEYCLOAK AUTHENTICATION
# =============================================================================

# Keycloak database settings (MUST use "audit" database and "ChangeMe123!" password)
KEYCLOAK_DB=audit
KEYCLOAK_DB_USER=keycloak
KEYCLOAK_DB_PASSWORD=ChangeMe123!

# Keycloak admin credentials (MUST change for production)
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=AdminKeycloak123!Secure2025

# Keycloak realm
KEYCLOAK_REALM=vt-audit

# =============================================================================
# CERTIFICATE AUTHORITY CONFIGURATION
# =============================================================================

# Step-CA configuration (NO spaces after commas in DNS_NAMES)
STEPCA_NAME=VT-Audit Certificate Authority
STEPCA_DNS_NAMES=gateway.local,stepca,api-agent,localhost
STEPCA_PROVISIONER=bootstrap@vt-audit
STEPCA_URL=https://stepca:9000
STEPCA_EXTERNAL_URL=https://gateway.local/step-ca

# Step-CA passwords (MUST change for production)
STEPCA_PASSWORD=StepCA123!SecurePassword2025
STEPCA_PROVISIONER_PASSWORD=ChangeMe123!SecurePassword2025

# Step-CA key path
STEPCA_KEY_PATH=/stepca/secrets/provisioner.key

# Certificate validity settings
MTLS_CERT_TTL=24h
CERTIFICATE_VALIDITY_HOURS=24

# =============================================================================
# OAUTH2 / OIDC CONFIGURATION
# =============================================================================

# OAuth2 proxy settings
OIDC_CLIENT_ID=dashboard-proxy
OIDC_CLIENT_SECRET=replace-with-real-secret-min-32-chars

# Cookie secret MUST be 32, 48, or 64 hex chars (16, 24, or 32 bytes)
# Generate with: openssl rand -hex 16
OIDC_COOKIE_SECRET=7af56af96c655e4fed37b71f1500ab27

# OIDC issuer and roles
OIDC_ISSUER=https://gateway.local/auth/realms/vt-audit
OIDC_ADMIN_ROLE=admin

# =============================================================================
# AGENT CONFIGURATION
# =============================================================================

# Agent bootstrap token (MUST change for production)
AGENT_BOOTSTRAP_TOKEN=set-a-strong-secret-token-here
```

---

## Checklist Deploy Production

- [ ] Đã cài đặt Docker và Docker Compose
- [ ] User có quyền chạy Docker (thuộc group docker hoặc dùng sudo)
- [ ] Đã tạo file `.env` với tất cả biến cần thiết
- [ ] `POSTGRES_DB=audit` (không đổi tên khác)
- [ ] `KEYCLOAK_DB_PASSWORD=ChangeMe123!` (khớp với init script)
- [ ] `STEPCA_DNS_NAMES` không có khoảng trắng sau dấu phẩy
- [ ] `OIDC_COOKIE_SECRET` có độ dài 32, 48, hoặc 64 ký tự hex
- [ ] Đã thay đổi tất cả passwords/secrets mặc định
- [ ] Đã backup file `.env` cũ (nếu có)
- [ ] Đã xóa containers và volumes cũ
- [ ] Đã xóa certificates cũ trong `certs/nginx/`
- [ ] Đã chạy `docker compose up -d`
- [ ] Đã kiểm tra tất cả containers đang chạy và healthy
- [ ] Đã kiểm tra logs không có lỗi
- [ ] Đã test kết nối đến các services

---

## Troubleshooting Commands

```bash
# Xem tất cả logs
sudo docker compose logs

# Xem logs realtime
sudo docker compose logs -f

# Xem logs của một service cụ thể
sudo docker logs vt-keycloak

# Restart một service
sudo docker compose restart <service-name>

# Recreate một service
sudo docker compose stop <service-name>
sudo docker compose rm -f <service-name>
sudo docker compose up -d <service-name>

# Restart toàn bộ stack
sudo docker compose restart

# Reset hoàn toàn (MẤT DỮ LIỆU)
sudo docker compose down -v
sudo rm -f certs/nginx/*.crt certs/nginx/*.key
sudo docker compose up -d

# Xem resource usage
sudo docker stats

# Kiểm tra network
sudo docker network inspect env_backend
```

---

## Bảo Mật Production

### Passwords/Secrets Cần Thay Đổi

**QUAN TRỌNG:** Đổi TẤT CẢ các giá trị mặc định sau:

1. **PostgreSQL:**
   - `POSTGRES_PASSWORD`

2. **Keycloak:**
   - `KEYCLOAK_ADMIN_PASSWORD` (để đăng nhập console)
   - `KEYCLOAK_DB_PASSWORD` (chỉ đổi nếu sửa init script)

3. **Step-CA:**
   - `STEPCA_PASSWORD`
   - `STEPCA_PROVISIONER_PASSWORD`

4. **OIDC:**
   - `OIDC_CLIENT_SECRET`
   - `OIDC_COOKIE_SECRET`

5. **Agent:**
   - `AGENT_BOOTSTRAP_TOKEN`

### File Permissions

```bash
# Bảo mật file .env
chmod 600 .env
chown root:root .env  # hoặc user deploy của bạn
```

### Firewall Rules

```bash
# Chỉ mở các ports cần thiết
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --permanent --add-port=8742/tcp
sudo firewall-cmd --reload

# KHÔNG mở port 5432 (PostgreSQL) ra ngoài internet
```

---

## Liên Hệ và Hỗ Trợ

Nếu gặp vấn đề không có trong tài liệu này:

1. Kiểm tra logs: `sudo docker compose logs`
2. Kiểm tra file `.env` có đúng format
3. Tham khảo phần [Các Lỗi Thường Gặp](#các-lỗi-thường-gặp-và-cách-khắc-phục)
4. Mở issue trên GitHub repository

---

**Ngày cập nhật:** November 4, 2025  
**Phiên bản:** 1.0
