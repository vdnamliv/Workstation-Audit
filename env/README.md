# Environment Configuration

This directory contains environment configuration files for the VT-Audit system.

## Quick Start

### Option 1: Automatic Setup (Recommended)

Run the automated setup script to generate a secure `.env` file:

```bash
./setup-env.sh
```

This script will:
- Generate secure random passwords and secrets
- Create a properly formatted `.env` file
- Display important credentials
- Optionally deploy the stack immediately

### Option 2: Manual Setup

1. Copy the template:
   ```bash
   cp .env.template .env
   ```

2. Generate secrets:
   ```bash
   # PostgreSQL password
   openssl rand -base64 24
   
   # Keycloak admin password
   openssl rand -base64 24
   
   # Step-CA passwords
   openssl rand -base64 24
   
   # OIDC cookie secret (must be 32 hex chars)
   openssl rand -hex 16
   
   # OAuth client secret
   openssl rand -base64 32
   
   # Agent bootstrap token
   openssl rand -base64 32
   ```

3. Edit `.env` and replace all `CHANGE_ME_*` values with generated secrets

4. Verify configuration:
   ```bash
   grep "CHANGE_ME" .env  # Should return nothing
   ```

## Important Configuration Notes

### Database Configuration
- `POSTGRES_DB` must be `audit` (matches init scripts)
- `POSTGRES_DSN` password must match `POSTGRES_PASSWORD`

### Keycloak Configuration
- `KEYCLOAK_DB` must be `audit` (same database)
- `KEYCLOAK_DB_PASSWORD` must be `ChangeMe123!` (hardcoded in `conf/postgres/init/20_grants.sql`)
- Only change `KEYCLOAK_ADMIN_PASSWORD` (for admin console access)

### Step-CA Configuration
- `STEPCA_DNS_NAMES`: **NO spaces after commas**
- ✅ Correct: `gateway.local,stepca,localhost`
- ❌ Wrong: `gateway.local, stepca, localhost`

### OIDC Configuration
- `OIDC_COOKIE_SECRET` must be exactly 32, 48, or 64 hex characters
- Use `openssl rand -hex 16` (for 32 chars)

## Files

- `.env` - Your active environment configuration (gitignored)
- `.env.template` - Template with placeholders
- `.env.example` - Example configuration (may be outdated)
- `setup-env.sh` - Automated setup script
- `docker-compose.yml` - Docker Compose configuration

## Configuration Directories

- `conf/postgres/init/` - PostgreSQL initialization scripts
- `conf/nginx/` - Nginx configuration
- `conf/keycloak/` - Keycloak realm configuration
- `conf/oidc/` - OAuth2 proxy configuration
- `certs/nginx/` - Generated SSL certificates (auto-created)

## Deployment

After creating `.env`:

```bash
# Clean up old deployment (if any)
sudo docker compose down -v
sudo rm -f certs/nginx/*.crt certs/nginx/*.key

# Deploy
sudo docker compose up -d

# Monitor
sudo docker compose logs -f

# Check status
sudo docker compose ps
```

## Troubleshooting

See the main [DEPLOYMENT.md](../DEPLOYMENT.md) for:
- Common errors and solutions
- Detailed configuration guide
- Security best practices
- Complete troubleshooting steps

## Security

- **Never commit `.env` to version control**
- Set proper permissions: `chmod 600 .env`
- Change all default passwords in production
- Use strong, randomly generated secrets

## Additional Resources

- [Full Deployment Guide](../DEPLOYMENT.md) - Comprehensive deployment documentation
- [Architecture](../ARCHITECTURE.md) - System architecture overview
- [Troubleshooting](../docs/wiki/Troubleshooting.md) - Common issues and solutions
