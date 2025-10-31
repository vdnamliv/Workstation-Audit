# Deployment Guide

Complete production deployment guide for VT-Audit system.

## 📋 Prerequisites

### Server Environment
- **OS**: Linux (Ubuntu 20.04+ recommended)
- **Docker**: Docker Engine 20.10+ và Docker Compose v2+
- **Memory**: 4GB RAM minimum, 8GB recommended for production
- **Storage**: 20GB available disk space minimum
- **Network**: Ports 443, 8443, 8742 accessible từ agents
- **Domain**: Valid SSL certificate cho production deployment

### Agent Environment
- **OS**: Windows 10/11 (Build 22H2+ recommended)
- **PowerShell**: Version 5.1+ (built-in với Windows)
- **Network**: HTTPS outbound access đến server
- **Privileges**: Administrator rights cho service installation

## 🚀 Server Deployment

### Step 1: Environment Setup

```bash
# Clone repository
git clone https://github.com/vdnamliv/vt-audit.git
cd vt-audit

# Create production environment
cp env/.env.example env/.env
```

### Step 2: Configure Production Environment

Edit `env/.env` với production values:

```bash
# =============================================================================
# VT-AUDIT PRODUCTION CONFIGURATION
# =============================================================================

# Certificate Authority Configuration
STEPCA_PROVISIONER_PASSWORD=YourSecurePassword123!
STEPCA_PROVISIONER_NAME=vt-audit-provisioner

# Database Configuration
POSTGRES_DB=vtaudit
POSTGRES_USER=vtaudit
POSTGRES_PASSWORD=YourDBPassword456!
POSTGRES_HOST=postgres
POSTGRES_PORT=5432

# Keycloak Authentication
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=YourKeycloakPassword789!
KEYCLOAK_DB_PASSWORD=YourKeycloakDBPassword!

# Network Configuration
NGINX_HOST=gateway.your-domain.com
NGINX_SSL_CERT_PATH=/etc/nginx/certs/server.crt
NGINX_SSL_KEY_PATH=/etc/nginx/certs/server.key

# Security Settings
JWT_SECRET=YourJWTSecretKey_MinLength32Characters!
ENCRYPTION_KEY=YourEncryptionKey_Exactly32Characters

# Agent Configuration
DEFAULT_POLLING_INTERVAL=600
CERTIFICATE_VALIDITY_HOURS=24

# Monitoring và Logging
LOG_LEVEL=info
ENABLE_DEBUG=false
METRICS_ENABLED=true
```

### Step 3: Generate SSL Certificates

```bash
# Generate nginx certificates
cd env
./scripts/generate-mtls-assets.sh
./scripts/issue-nginx-cert.sh gateway.your-domain.com
```

### Step 4: Start Services

```bash
# Start server stack
docker compose up -d

# Verify all services running
docker compose ps

# Check service health
curl -k https://localhost:443/health
curl -k https://localhost:8443/health
curl -k https://localhost:8742/health
```

## 🏢 Production Configuration

### Load Balancer Setup

For high availability, configure load balancer:

```nginx
# nginx load balancer config
upstream vt_audit_backend {
    server vt-server-1:8443;
    server vt-server-2:8443;
    server vt-server-3:8443;
}

server {
    listen 443 ssl;
    server_name gateway.company.com;
    
    location /agent {
        proxy_pass https://vt_audit_backend;
        proxy_ssl_verify off;
    }
}
```

### Database Clustering

For production PostgreSQL clustering:

```yaml
# docker-compose.prod.yml
services:
  postgres-primary:
    image: postgres:15
    environment:
      POSTGRES_REPLICATION_MODE: master
      POSTGRES_REPLICATION_USER: replicator
    
  postgres-replica:
    image: postgres:15
    environment:
      POSTGRES_REPLICATION_MODE: slave
      POSTGRES_MASTER_SERVICE: postgres-primary
```

### Monitoring Setup

```yaml
# monitoring stack
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    
  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    
  node-exporter:
    image: prom/node-exporter
    ports:
      - "9100:9100"
```

## 🔐 Security Hardening

### SSL/TLS Configuration

```nginx
# Enhanced TLS configuration
ssl_protocols TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;

# Security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header X-XSS-Protection "1; mode=block" always;
```

### Firewall Configuration

```bash
# UFW firewall rules
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 443/tcp   # HTTPS Dashboard
sudo ufw allow 8443/tcp  # Agent API
sudo ufw allow 8742/tcp  # Enrollment
sudo ufw deny 8080/tcp   # Block direct API access
sudo ufw enable
```

### Network Segmentation

```yaml
# Docker network isolation
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # No external access
  database:
    driver: bridge
    internal: true  # Database isolation
```

## 📊 Monitoring và Maintenance

### Health Checks

```bash
# Automated health check script
#!/bin/bash
services=(
    "https://localhost:443/health"
    "https://localhost:8443/health"  
    "https://localhost:8742/health"
)

for service in "${services[@]}"; do
    if curl -sf "$service" > /dev/null; then
        echo "✅ $service - OK"
    else
        echo "❌ $service - FAILED"
        # Send alert
    fi
done
```

### Backup Procedures

```bash
# Automated backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)

# Database backup
docker exec postgres pg_dump -U vtaudit vtaudit > backup/db_$DATE.sql

# Certificate backup
cp -r env/certs/ backup/certs_$DATE/

# Configuration backup
cp env/.env backup/env_$DATE.backup

# Upload to S3 or backup storage
```

### Log Management

```yaml
# Centralized logging with ELK stack
  elasticsearch:
    image: elasticsearch:7.17.0
    
  logstash:
    image: logstash:7.17.0
    
  kibana:
    image: kibana:7.17.0
    ports:
      - "5601:5601"
```

## 🔧 Maintenance Tasks

### Regular Updates

```bash
# Update containers
docker compose pull
docker compose up -d

# Database maintenance
docker exec postgres psql -U vtaudit -d vtaudit -c "VACUUM ANALYZE;"

# Certificate monitoring
docker exec stepca step certificate inspect /home/step/certs/intermediate_ca.crt
```

### Performance Tuning

```sql
-- PostgreSQL performance tuning
ALTER SYSTEM SET shared_buffers = '1GB';
ALTER SYSTEM SET effective_cache_size = '3GB';
ALTER SYSTEM SET maintenance_work_mem = '256MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
```

## 🚨 Disaster Recovery

### Backup Strategy

1. **Database**: Daily automated backups với 30-day retention
2. **Certificates**: Weekly backup của certificate store
3. **Configuration**: Version control của environment configs
4. **Application**: Container images trong private registry

### Recovery Procedures

```bash
# Database recovery
docker exec postgres psql -U vtaudit -d vtaudit < backup/db_backup.sql

# Certificate recovery
cp -r backup/certs_latest/* env/certs/

# Service restart
docker compose down
docker compose up -d
```

### Testing Recovery

```bash
# Test backup integrity monthly
docker run --rm -v backup_volume:/backup postgres:15 \
    pg_restore --verbose --clean --no-acl --no-owner \
    -d test_db /backup/latest.sql
```

## 📝 Deployment Checklist

### Pre-deployment
- [ ] Server requirements verified
- [ ] SSL certificates generated
- [ ] Environment configuration completed  
- [ ] Network ports configured
- [ ] Backup strategy implemented

### Deployment
- [ ] Services started successfully
- [ ] Health checks passing
- [ ] Database schema initialized
- [ ] Admin account configured
- [ ] Test agent enrollment working

### Post-deployment  
- [ ] Monitoring configured
- [ ] Backup testing completed
- [ ] Performance baseline established
- [ ] Security scan completed
- [ ] Documentation updated

## 🆘 Rollback Procedures

```bash
# Emergency rollback
docker compose down
git checkout previous-stable-tag
cp backup/env_working.backup env/.env
docker compose up -d

# Verify rollback
curl -k https://localhost:443/health
```

## 📞 Support

- **Production Issues**: Create GitHub Issue với priority label
- **Security Concerns**: Email security@vt-audit.local
- **Emergency**: Follow incident response procedures