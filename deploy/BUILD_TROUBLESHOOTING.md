# Docker Build Issues - Troubleshooting Guide

## ❌ Problem: SSL Certificate Error

```
go: filippo.io/edwards25519@v1.1.0: Get "https://proxy.golang.org/...": 
tls: failed to verify certificate: x509: certificate signed by unknown authority
```

This occurs when the server cannot verify SSL certificates for Go proxy.

## ✅ Solutions (Pick One)

### **Solution 1: Fix SSL Certificates on Server (RECOMMENDED)**

Run on Rocky Linux server:

```bash
# Install/update CA certificates
sudo dnf install -y ca-certificates
sudo update-ca-trust

# Test connection
curl -I https://proxy.golang.org

# Now build
cd /opt/vt-audit/deploy/04-agent-api
docker compose up -d
```

**Or use the script:**
```bash
chmod +x fix-ssl.sh
bash fix-ssl.sh
```

---

### **Solution 2: Use Alternative Go Proxy**

Already fixed in `docker-compose.yml`:

```yaml
api-agent:
  build:
    args:
      - GOPROXY=https://goproxy.io,https://proxy.golang.org,direct
      - GOSUMDB=off
```

Just rebuild:
```bash
docker compose build --no-cache
docker compose up -d
```

---

### **Solution 3: Pre-pull Base Images**

Pull all required images before building:

```bash
cd /opt/vt-audit/deploy
chmod +x pull-images.sh
bash pull-images.sh

# Then build
cd 04-agent-api
docker compose up -d
```

**Manual pull:**
```bash
docker pull smallstep/step-ca:0.27.4
docker pull postgres:16.10-alpine
docker pull keycloak:25.0
docker pull nginx:1.27-alpine
docker pull golang:1.25-alpine
docker pull gcr.io/distroless/static-debian12:latest
```

---

### **Solution 4: Build Locally & Transfer (FASTEST)**

Build on your Windows machine and transfer to servers:

```powershell
# On Windows
cd C:\Users\admin\Desktop\vt-audit\deploy
.\build-and-transfer.ps1 -TargetServer 10.211.130.47 -Username root
```

**Manual steps:**
```powershell
# Build locally
cd C:\Users\admin\Desktop\vt-audit
docker build -f env/docker/Dockerfile.vt-server -t vt-server:latest .

# Save to tar
docker save -o vt-server.tar vt-server:latest

# Transfer
scp vt-server.tar root@10.211.130.47:/tmp/

# Load on server
ssh root@10.211.130.47 "docker load -i /tmp/vt-server.tar && rm /tmp/vt-server.tar"
```

Then on server:
```bash
cd /opt/vt-audit/deploy/04-agent-api
# Edit docker-compose.yml: change build to image
# image: vt-server:latest
docker compose up -d
```

---

### **Solution 5: Use Pre-built Image from Registry (PRODUCTION)**

If you have a Docker registry:

```bash
# On build machine
docker build -f env/docker/Dockerfile.vt-server -t registry.company.com/vt-server:v1.0.0 .
docker push registry.company.com/vt-server:v1.0.0

# On production servers
docker pull registry.company.com/vt-server:v1.0.0

# Update docker-compose.yml
sed -i 's|build:|image: registry.company.com/vt-server:v1.0.0 #build:|' docker-compose.yml
docker compose up -d
```

---

## 🔍 Debugging Build Issues

### Check Go proxy connectivity:
```bash
docker run --rm golang:1.25-alpine sh -c "go env GOPROXY && curl -I https://proxy.golang.org"
```

### Build with verbose output:
```bash
docker compose build --progress=plain --no-cache
```

### Check Dockerfile:
```bash
cat ../../env/docker/Dockerfile.vt-server
```

### Test build context:
```bash
cd ../../
docker build -f env/docker/Dockerfile.vt-server --target build .
```

---

## 📊 Comparison Matrix

| Solution | Speed | Complexity | Best For |
|----------|-------|------------|----------|
| Fix SSL | ⭐⭐⭐ | Low | All environments |
| Alt Proxy | ⭐⭐⭐⭐ | Very Low | China/restricted networks |
| Pre-pull | ⭐⭐ | Low | Slow connections |
| Build Local | ⭐⭐⭐⭐⭐ | Medium | Multiple servers |
| Registry | ⭐⭐⭐⭐⭐ | High | Production deployment |

---

## 🚀 Quick Fix Commands

**If build fails, try in order:**

```bash
# 1. Quick fix with alternative proxy
docker compose build --build-arg GOPROXY=https://goproxy.io,direct

# 2. Fix SSL and retry
sudo dnf install -y ca-certificates && sudo update-ca-trust
docker compose build --no-cache

# 3. Skip build, use pre-built image
# (Build on local machine first)
docker compose up -d --no-build
```

---

## 📚 Related Files

- `fix-ssl.sh` - SSL certificate fix script
- `pull-images.sh` - Pre-pull all Docker images
- `build-and-transfer.ps1` - Build locally and transfer to servers
- `docker-compose.yml` - Already configured with alternative GOPROXY

---

## 🆘 Still Having Issues?

1. **Check network:**
   ```bash
   curl -I https://proxy.golang.org
   curl -I https://goproxy.io
   ```

2. **Check Docker:**
   ```bash
   docker --version
   docker compose version
   systemctl status docker
   ```

3. **Check disk space:**
   ```bash
   df -h
   docker system df
   ```

4. **Clean and retry:**
   ```bash
   docker system prune -a
   docker compose build --no-cache
   ```
