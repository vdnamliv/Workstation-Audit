# 🔍 Giải Thích: Service Name vs Localhost vs IP

## ❓ **Tại Sao Dùng Service Name Thay Vì Localhost?**

### **1. Docker Compose Tự Động Tạo Default Network**

Khi các services trong cùng một `docker-compose.yml`, Docker Compose **tự động tạo một default bridge network** cho project đó. Các services có thể giao tiếp với nhau qua **service name** (tên service trong file yaml).

**Ví dụ:**
```yaml
# deploy/04-agent-api/docker-compose.yml
services:
  stepca:          # ← Service name
    ...
  api-agent:       # ← Service name
    command:
      - "--stepca-url=https://stepca:9000"  # ✅ Dùng service name
```

### **2. Xóa `networks:` Config Không Ảnh Hưởng Default Network**

Việc xóa phần `networks:` chỉ là xóa **custom external network** (`vt-system-net`), **KHÔNG ảnh hưởng** đến default network mà docker-compose tự tạo.

**Trước (có external network):**
```yaml
services:
  stepca:
    ...
networks:
  default:
    name: vt-system-net
    external: true
```

**Sau (không có networks config):**
```yaml
services:
  stepca:
    ...
# Docker Compose vẫn tự tạo default network!
```

### **3. Khi Nào Dùng Gì?**

| Tình Huống | Nên Dùng | Ví Dụ |
|------------|----------|-------|
| **Services trong cùng docker-compose.yml** | ✅ **Service name** | `stepca:9000`, `keycloak:8080` |
| **Kết nối từ host machine vào container** | ✅ **localhost** | `localhost:8080` (từ máy host) |
| **Services ở khác compose file** | ✅ **IP hoặc hostname** | `10.211.130.51:5432` |
| **Services ở khác server** | ✅ **IP thực tế** | `10.211.130.47:8080` |

---

## 📋 **Các Trường Hợp Cụ Thể Trong Project**

### **Case 1: 04-agent-api/docker-compose.yml**

```yaml
services:
  stepca:
    ports:
      - "9000:9000"
  
  api-agent:
    command:
      - "--stepca-url=https://stepca:9000"  # ✅ ĐÚNG: cùng compose file
```

**Lý do:** `stepca` và `api-agent` trong cùng compose file → dùng service name `stepca:9000`

---

### **Case 2: 03-admin-api/docker-compose.yml**

```yaml
services:
  keycloak:
    ports:
      - "8080:8080"
  
  api-backend:
    command:
      - "--oidc-issuer=${OIDC_ISSUER_URL}"  # Từ .env file
```

**Trong .env.example:**
```bash
# ✅ ĐÚNG: keycloak và api-backend trong cùng compose file
OIDC_ISSUER_URL=http://keycloak:8080/realms/vt-audit
```

**Lý do:** `keycloak` và `api-backend` trong cùng compose file → dùng service name `keycloak:8080`

---

### **Case 3: Database Connection**

```yaml
# 03-admin-api/docker-compose.yml
services:
  api-backend:
    command:
      - "--pg_dsn=postgres://${DB_USER}:${DB_PASS}@${DB_HOST}:5432/${DB_NAME}"
```

**Trong .env.example:**
```bash
# ✅ ĐÚNG: Database ở compose file khác (01-database)
DB_HOST=10.211.130.51  # IP thực tế
```

**Lý do:** Database ở compose file khác → dùng IP thực tế

---

### **Case 4: Health Check**

```yaml
services:
  keycloak:
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8080/health/ready"]
```

**Lý do:** Health check chạy **bên trong container** → dùng `localhost` (container's localhost)

---

## ⚠️ **Lưu Ý Quan Trọng**

### **1. Service Name vs Container Name**

- **Service name** = Tên trong `services:` section của docker-compose.yml
- **Container name** = Tên trong `container_name:` (optional)

```yaml
services:
  stepca:              # ← Service name (dùng để giao tiếp)
    container_name: vt-stepca  # ← Container name (chỉ để dễ nhận biết)
```

**Dùng service name để giao tiếp, KHÔNG dùng container name!**

---

### **2. Port Mapping**

```yaml
services:
  stepca:
    ports:
      - "9000:9000"  # host:container
```

- **Từ container khác:** Dùng `stepca:9000` (port container)
- **Từ host machine:** Dùng `localhost:9000` (port host)

---

### **3. HTTPS với Service Name**

Khi dùng HTTPS với service name, cần đảm bảo certificate có SAN (Subject Alternative Name) cho service name:

```yaml
# 04-agent-api/docker-compose.yml
services:
  api-agent:
    command:
      - "--stepca-url=https://stepca:9000"  # ✅ OK nếu cert có SAN
```

**Lưu ý:** StepCA thường tự động tạo cert với SAN cho service name.

---

## 🧪 **Test Connectivity**

### **Test từ container này sang container khác:**

```bash
# Từ api-agent container → stepca
docker exec vt-api-agent curl -k https://stepca:9000/health

# Từ api-backend container → keycloak
docker exec vt-api-backend curl http://keycloak:8080/health/ready
```

### **Test từ host machine:**

```bash
# Từ host → container (qua port mapping)
curl http://localhost:8080/health/ready
curl -k https://localhost:9000/health
```

---

## 📝 **Tóm Tắt**

✅ **Dùng Service Name khi:**
- Services trong cùng docker-compose.yml
- Cần giao tiếp giữa containers

✅ **Dùng Localhost khi:**
- Health check bên trong container
- Kết nối từ host machine vào container

✅ **Dùng IP khi:**
- Services ở khác compose file
- Services ở khác server
- Database connection (thường ở server riêng)

---

**Kết luận:** Trong project này, các service trong cùng compose file nên dùng **service name** thay vì localhost để đảm bảo tính nhất quán và dễ maintain.

