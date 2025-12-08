# Build và Transfer Docker Images cho Server Không Có Internet

## 📋 Danh sách Images Cần Thiết

| Image | Dùng cho | Server |
|-------|----------|--------|
| `postgres:16-alpine` | Database | .52, .53 |
| `smallstep/step-ca:0.27.4` | StepCA | .47, .48 |
| `quay.io/keycloak/keycloak:25.0` | Keycloak | .49, .50 |
| `nginx:1.27` | Nginx Gateway | .45, .46 |
| `vt-api-agent:latest` | Agent API (cần build) | .47, .48 |
| `vt-api-backend:latest` | Admin API (cần build) | .49, .50 |

---

## 🔧 BƯỚC 1: Build Images (Trên máy có internet)

```bash
cd /path/to/vt-audit

# Build VT Server image (dùng cho cả agent và backend)
docker build -t vt-api-agent:latest -f env/docker/Dockerfile.vt-server .
docker tag vt-api-agent:latest vt-api-backend:latest

# Pull các images cần thiết
docker pull postgres:16-alpine
docker pull smallstep/step-ca:0.27.4
docker pull quay.io/keycloak/keycloak:25.0
docker pull nginx:1.27
```

---

## 📦 BƯỚC 2: Save Images thành File

```bash
# Tạo folder chứa images
mkdir -p docker-images

# Save từng image
docker save postgres:16-alpine | gzip > docker-images/postgres-16-alpine.tar.gz
docker save smallstep/step-ca:0.27.4 | gzip > docker-images/step-ca-0.27.4.tar.gz
docker save quay.io/keycloak/keycloak:25.0 | gzip > docker-images/keycloak-25.0.tar.gz
docker save nginx:1.27 | gzip > docker-images/nginx-1.27.tar.gz
docker save vt-api-agent:latest | gzip > docker-images/vt-api-agent.tar.gz
docker save vt-api-backend:latest | gzip > docker-images/vt-api-backend.tar.gz

# Kiểm tra
ls -lh docker-images/
```

---

## 🚀 BƯỚC 3: Copy sang các Server

```bash
# Copy sang Database Server (.52)
scp docker-images/postgres-16-alpine.tar.gz root@10.211.130.52:/tmp/

# Copy sang Agent API Server (.47, .48)
scp docker-images/step-ca-0.27.4.tar.gz docker-images/vt-api-agent.tar.gz root@10.211.130.47:/tmp/
scp docker-images/step-ca-0.27.4.tar.gz docker-images/vt-api-agent.tar.gz root@10.211.130.48:/tmp/

# Copy sang Admin API Server (.49, .50)
scp docker-images/keycloak-25.0.tar.gz docker-images/vt-api-backend.tar.gz root@10.211.130.49:/tmp/
scp docker-images/keycloak-25.0.tar.gz docker-images/vt-api-backend.tar.gz root@10.211.130.50:/tmp/

# Copy sang Nginx Server (.45, .46)
scp docker-images/nginx-1.27.tar.gz root@10.211.130.45:/tmp/
scp docker-images/nginx-1.27.tar.gz root@10.211.130.46:/tmp/
```

---

## 📥 BƯỚC 4: Load Images trên từng Server

### Server .52 (Database):
```bash
docker load < /tmp/postgres-16-alpine.tar.gz
docker images | grep postgres
```

### Server .47, .48 (Agent API):
```bash
docker load < /tmp/step-ca-0.27.4.tar.gz
docker load < /tmp/vt-api-agent.tar.gz
docker images
```

### Server .49, .50 (Admin API):
```bash
docker load < /tmp/keycloak-25.0.tar.gz
docker load < /tmp/vt-api-backend.tar.gz
docker images
```

### Server .45, .46 (Nginx):
```bash
docker load < /tmp/nginx-1.27.tar.gz
docker images | grep nginx
```

---

## ✅ BƯỚC 5: Chạy với docker-compose.production.yml

### Agent API Server (.47, .48):
```bash
cd /opt/vt-audit/deploy/04-agent-api
docker compose -f docker-compose.production.yml up -d
```

### Admin API Server (.49, .50):
```bash
cd /opt/vt-audit/deploy/03-admin-api
docker compose -f docker-compose.production.yml up -d
```

### Database Server (.52):
```bash
cd /opt/vt-audit/deploy/01-database
docker compose up -d  # Không cần file production vì chỉ dùng image postgres
```

### Nginx Server (.45, .46):
```bash
cd /opt/vt-audit/deploy/02-nginx-gateway
docker compose up -d  # Không cần file production vì chỉ dùng image nginx
```

---

## 🧹 Cleanup sau khi load xong

```bash
# Xóa file tar.gz để tiết kiệm disk
rm /tmp/*.tar.gz
```

---

## ⚠️ Lưu ý

1. **Phải build image trên máy có cùng architecture** (x86_64 hoặc arm64)
2. **Kiểm tra disk space** trước khi copy (mỗi image ~100-500MB)
3. **Verify images** sau khi load:
   ```bash
   docker images
   ```

