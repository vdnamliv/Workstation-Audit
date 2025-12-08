# Validation Scripts Usage Guide

Bộ script validation cho từng server component trong production deployment.

## 📁 Cấu Trúc

```
deploy/
├── 01-database/
│   └── validate.sh          # Database server (10.211.130.51)
├── 02-nginx-gateway/
│   └── validate.sh          # Nginx servers (.45, .46)
├── 03-admin-api/
│   └── validate.sh          # Admin API servers (.49, .50)
└── 04-agent-api/
    └── validate.sh          # Agent API servers (.47, .48)
```

## 🚀 Cách Sử Dụng

### Trên từng server Linux:

```bash
# Clone repository
cd /opt
git clone https://github.com/vdnamliv/Workstation-Audit.git vt-audit
cd vt-audit/deploy

# Chạy script validation tương ứng với server
cd <component-directory>
chmod +x validate.sh
bash validate.sh
```

### Ví dụ cụ thể:

**Server 10.211.130.51 (Database):**
```bash
cd /opt/vt-audit/deploy/01-database
chmod +x validate.sh
bash validate.sh
```

**Server 10.211.130.47 hoặc .48 (Agent API):**
```bash
cd /opt/vt-audit/deploy/04-agent-api
chmod +x validate.sh
bash validate.sh
```

**Server 10.211.130.49 hoặc .50 (Admin API):**
```bash
cd /opt/vt-audit/deploy/03-admin-api
chmod +x validate.sh
bash validate.sh
```

**Server 10.211.130.45 hoặc .46 (Nginx Gateway):**
```bash
cd /opt/vt-audit/deploy/02-nginx-gateway
chmod +x validate.sh
bash validate.sh
```

## ✅ Các Kiểm Tra

### Tất cả servers:
- ✓ OS version (Rocky Linux 9+)
- ✓ Docker installed
- ✓ Docker Compose installed
- ✓ Docker daemon running
- ✓ Docker network `vt-system-net` exists
- ✓ Configuration files exist
- ✓ Weak password detection
- ✓ Firewall rules

### Database Server (01-database):
- ✓ PostgreSQL port 5432 open
- ✓ Database init script valid
- ✓ Container health status

### Agent API Servers (04-agent-api):
- ✓ Ports 8080, 9000 open
- ✓ StepCA provisioner configured (in ca.json, auto-generated)
- ✓ Database connectivity
- ✓ Production IPs configured

### Admin API Servers (03-admin-api):
- ✓ Ports 8080, 8081 open
- ✓ Keycloak production mode (`start --optimized`)
- ✓ OIDC configuration
- ✓ Keycloak realm file
- ✓ Database connectivity

### Nginx Gateway Servers (02-nginx-gateway):
- ✓ Ports 443, 8443 open
- ✓ SSL certificates exist
- ✓ StepCA chain for mTLS
- ✓ Certificate permissions secure
- ✓ Production upstream IPs
- ✓ mTLS enabled
- ✓ Rate limiting configured
- ✓ Backend connectivity

## 📊 Kết Quả

### Exit Codes:
- `0` - All checks passed or only warnings
- `1` - Critical errors found

### Output Colors:
- 🟢 **GREEN [OK]** - Check passed
- 🟡 **YELLOW [WARN]** - Warning, review required
- 🔴 **RED [FAIL]** - Critical error, must fix
- 🔵 **CYAN [INFO]** - Informational message

## 🔧 Fix Common Issues

### Docker not running:
```bash
sudo systemctl enable --now docker
```

### Docker network missing:
```bash
docker network create --driver bridge --subnet 172.18.0.0/16 vt-system-net
```

### Firewall ports not open:
```bash
# Database
sudo firewall-cmd --permanent --add-port=5432/tcp
sudo firewall-cmd --reload

# Agent API
sudo firewall-cmd --permanent --add-port=8080/tcp --add-port=9000/tcp
sudo firewall-cmd --reload

# Admin API
sudo firewall-cmd --permanent --add-port=8080/tcp --add-port=8081/tcp
sudo firewall-cmd --reload

# Nginx Gateway
sudo firewall-cmd --permanent --add-port=443/tcp --add-port=8443/tcp
sudo firewall-cmd --reload
```

### .env file missing:
```bash
cp .env.example .env
nano .env  # Edit with production values
```

### StepCA chain certificate missing:
```bash
# Run on Agent API server after StepCA is running
docker exec vt-stepca step ca roots > /opt/vt-audit/deploy/02-nginx-gateway/certs/stepca_chain.crt

# Copy to Nginx servers
scp /path/to/stepca_chain.crt user@10.211.130.45:/opt/vt-audit/deploy/02-nginx-gateway/certs/
scp /path/to/stepca_chain.crt user@10.211.130.46:/opt/vt-audit/deploy/02-nginx-gateway/certs/
```

### Weak passwords detected:
```bash
# Generate strong passwords
openssl rand -base64 32

# Update .env file
nano .env
```

## 🔄 Deployment Workflow

1. **Pre-deployment validation:**
   ```bash
   bash validate.sh
   ```

2. **Fix all errors** reported by script

3. **Review warnings** and update config if needed

4. **Run validation again** until clean:
   ```bash
   bash validate.sh
   echo $?  # Should return 0
   ```

5. **Deploy component:**
   ```bash
   docker compose up -d
   ```

6. **Post-deployment check:**
   ```bash
   bash validate.sh  # Should show containers running
   docker logs <container-name>
   ```

## 📝 Notes

- Scripts require **sudo** for firewall checks
- Install `jq` for better JSON validation: `sudo dnf install -y jq`
- Install `postgresql` client for DB connectivity tests: `sudo dnf install -y postgresql`
- Scripts are **idempotent** - safe to run multiple times
- Use in **CI/CD pipelines** for automated validation

## 🆘 Troubleshooting

### Script permission denied:
```bash
chmod +x validate.sh
```

### Command not found errors:
```bash
# Install missing tools
sudo dnf install -y jq postgresql openssl
```

### Cannot connect to Docker daemon:
```bash
sudo systemctl start docker
sudo usermod -aG docker $USER
newgrp docker
```

## 📚 Related Documentation

- [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md) - Full deployment guide
- [README.md](README.md) - Deployment directory overview
- [pre-deployment-check.ps1](pre-deployment-check.ps1) - Windows validation script
