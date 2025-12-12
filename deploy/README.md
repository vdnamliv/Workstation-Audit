# VT-AUDIT Deployment Guide

This directory contains Docker Compose configurations for deploying VT-AUDIT system components.

## Directory Structure

```
deploy/
├── 01-database/         # PostgreSQL database server
├── 02-nginx-gateway/    # Nginx reverse proxy & SSL termination
├── 03-admin-api/        # Admin Dashboard + Keycloak
├── 04-agent-api/        # Agent API + StepCA
├── PRODUCTION_DEPLOYMENT.md   # Complete production deployment guide
└── switch-to-production.ps1   # Automated config switch script
```

## Quick Start

### Local Testing

1. **Start Database**
   ```powershell
   cd 01-database
   cp .env.example .env
   # Edit .env with test passwords
   docker compose up -d
   ```

2. **Start Agent API**
   ```powershell
   cd ../04-agent-api
   cp .env.example .env
   # Edit .env, set DB_HOST=postgres-vt-audit
   docker compose up -d
   ```

3. **Start Admin API**
   ```powershell
   cd ../03-admin-api
   cp .env.example .env
   # Edit .env, set DB_HOST=postgres-vt-audit
   docker compose up -d
   ```

4. **Start Nginx Gateway**
   ```powershell
   cd ../02-nginx-gateway
   docker compose up -d
   ```

### Production Deployment

For complete production deployment instructions, see **[PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md)**.

**Quick production setup:**

1. **Clone repository on all servers**
2. **Run switch script:**
   ```powershell
   .\switch-to-production.ps1
   ```
3. **Update .env files with production IPs and passwords**
4. **Follow PRODUCTION_DEPLOYMENT.md step-by-step**

## Component Overview

### 01-database (10.211.130.51)
- PostgreSQL 16.10
- 3 databases: `keycloak`, `stepca`, `vt_db`
- Schemas: `audit`, `policy`
- Users: `keycloak`, `stepca`, `vt_app`

### 02-nginx-gateway (10.211.130.45, .46)
- Nginx 1.27 reverse proxy
- SSL termination (443, 8443)
- mTLS for agent connections
- Rate limiting
- Load balancing to backends

### 03-admin-api (10.211.130.49, .50)
- Keycloak 25.0 (Identity Provider)
- VT-Server Dashboard mode (port 8081)
- Admin UI frontend
- OIDC authentication

### 04-agent-api (10.211.130.47, .48)
- StepCA 0.27.4 (Certificate Authority)
- VT-Server Agent mode (port 8080)
- Agent enrollment & certificate signing
- Policy distribution
- Audit data collection

## Network Architecture

```
Internet
   ↓
[HAProxy VIP 10.211.130.44]
   ↓
[Nginx Gateway :443,:8443] ← .45, .46
   ↓
├─→ [Agent API :8080] ← .47, .48
│      ↓
│   [StepCA :9000]
│
└─→ [Admin API :8081] ← .49, .50
       ↓
    [Keycloak :8080]
       ↓
[PostgreSQL :5432] ← .51
```

## Configuration Files

### Environment Variables (.env)
Each component has `.env.example` template:
- Copy to `.env` and fill in production values
- **NEVER commit .env files to git**
- Required changes for production:
  - Database IPs → actual server IPs
  - Passwords → strong random passwords
  - Bootstrap tokens → cryptographically secure tokens

### Docker Compose Files
- `docker-compose.yml` - Main configuration
- Local test uses service names (e.g., `vt-api-agent`)
- Production uses IP addresses (e.g., `10.211.130.47`)

### Nginx Configuration
- `conf/nginx.conf` - Main nginx config
- `conf/conf.d/00-upstream.conf` - Backend servers (local test)
- `conf/conf.d/00-upstream.conf.production` - Backend servers (production)
- Switch with `switch-to-production.ps1`

## Security Checklist

Before production deployment:

- [ ] All passwords changed from defaults
- [ ] SSL certificates generated (not self-signed)
- [ ] Firewall rules configured per PRODUCTION_DEPLOYMENT.md
- [ ] StepCA root CA backed up securely
- [ ] Keycloak admin password rotated
- [ ] Database passwords are strong (32+ characters)
- [ ] Agent bootstrap token is cryptographically random
- [ ] .env files excluded from git (check .gitignore)
- [ ] mTLS enabled for agent connections
- [ ] Rate limiting configured in nginx

## Troubleshooting

### Database Connection Failed
```bash
# Check database is running
docker exec postgres-vt-audit pg_isready

# Test connection from backend
docker exec vt-api-backend psql -h postgres-vt-audit -U vt_app -d vt_db -c "SELECT 1"
```

### StepCA Provisioner Not Found
```bash
# List provisioners
docker exec vt-stepca step ca provisioner list

# Check admin.jwk exists
docker exec vt-stepca ls -la /stepca/secrets/admin.jwk
```

### Nginx Upstream Error
```bash
# Check upstream configuration
docker exec vt-nginx nginx -T | grep upstream

# Test backend connectivity
docker exec vt-nginx curl -k http://vt-api-agent:8080/health
```

### Keycloak Not Starting
```bash
# Check logs
docker logs vt-keycloak

# Verify database connection
docker exec vt-keycloak bash -c 'echo $KC_DB_URL'
```

## Useful Commands

```powershell
# View all container status
docker ps -a

# Check container logs
docker logs -f <container-name>

# Execute command in container
docker exec -it <container-name> sh

# Restart component
docker compose restart

# Rebuild after code changes
docker compose up -d --build

# Stop all containers
docker compose down

# Remove volumes (WARNING: data loss)
docker compose down -v
```

## Support

For detailed deployment procedures, see:
- **[PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md)** - Full production guide
- **[LOCAL_TEST_GUIDE.md](LOCAL_TEST_GUIDE.md)** - Local testing procedures
- **[VALIDATION_REPORT.md](VALIDATION_REPORT.md)** - Testing validation results

For issues:
1. Check container logs: `docker logs <container>`
2. Review troubleshooting section in PRODUCTION_DEPLOYMENT.md
3. Verify network connectivity between components
4. Ensure .env files have correct values
