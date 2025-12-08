# StepCA Provisioner Key Setup

## ⚠️ Security Warning

**NEVER commit these files to git:**
- `admin.jwk` - Provisioner private key
- `admin.json` - Provisioner configuration  
- `admin-provisioner.json` - Provisioner metadata

These files are already in `.gitignore` and must remain private!

## 🔐 Automatic Key Extraction

After deploying StepCA container, extract the provisioner key automatically:

```bash
cd /opt/vt-audit/deploy/04-agent-api

# Start StepCA
docker compose up -d stepca

# Wait for initialization (30 seconds)
sleep 30

# Extract provisioner key
chmod +x extract-provisioner-key.sh
bash extract-provisioner-key.sh
```

This script will:
1. ✓ Check if StepCA container is running
2. ✓ Wait for StepCA to be healthy
3. ✓ Extract the provisioner JWK key from StepCA config
4. ✓ Save to `admin.jwk` with secure permissions (600)
5. ✓ Verify the key is valid JSON

## 📝 Manual Extraction (if automatic fails)

### Method 1: Extract from StepCA config

```bash
# Access container
docker exec -it vt-stepca sh

# View provisioners
step ca provisioner list

# Extract provisioner key from config
cat /home/step/config/ca.json | jq '.authority.provisioners[] | select(.name=="vt-audit-provisioner") | .key' > /tmp/admin.jwk

# Exit container
exit

# Copy key to host
docker cp vt-stepca:/tmp/admin.jwk ./admin.jwk
chmod 600 admin.jwk
```

### Method 2: Create new JWK provisioner

```bash
# Access container
docker exec -it vt-stepca sh

# Create new JWK provisioner
step ca provisioner add vt-audit-provisioner \
  --type JWK \
  --create \
  --password-file <(echo "$STEPCA_PASSWORD")

# The key will be in /home/step/secrets/ or /home/step/config/
```

## ✅ Verification

After extracting the key:

```bash
# Check file exists
ls -la admin.jwk

# Verify JSON format
jq empty admin.jwk && echo "Valid JSON" || echo "Invalid JSON"

# Check required fields
jq -r '{use, kty, kid, crv, alg, encryptedKey}' admin.jwk

# Verify it's not tracked by git
git status admin.jwk  # Should show: "Untracked files" or nothing
```

Expected output:
```json
{
  "use": "sig",
  "kty": "EC",
  "kid": "...",
  "crv": "P-256",
  "alg": "ES256",
  "encryptedKey": "eyJhbGci..."
}
```

## 🔄 Production Deployment Process

**PRIMARY Server (10.211.130.47):**

```bash
cd /opt/vt-audit/deploy/04-agent-api

# 1. Create .env from template
cp .env.example .env
nano .env  # Set strong passwords

# 2. Start StepCA
docker compose up -d stepca
sleep 30

# 3. Extract provisioner key
bash extract-provisioner-key.sh

# 4. Verify key extracted
ls -la admin.jwk

# 5. Start Agent API
docker compose up -d

# 6. Backup StepCA data for secondary server
docker run --rm \
  -v 04-agent-api_stepca_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/stepca-data.tar.gz -C /data .
```

**SECONDARY Server (10.211.130.48):**

```bash
cd /opt/vt-audit/deploy/04-agent-api

# 1. Copy .env from primary
scp user@10.211.130.47:/opt/vt-audit/deploy/04-agent-api/.env .env

# 2. Copy StepCA data archive
scp user@10.211.130.47:/opt/vt-audit/deploy/04-agent-api/stepca-data.tar.gz .

# 3. Create volume and restore data
docker volume create 04-agent-api_stepca_data
docker run --rm \
  -v 04-agent-api_stepca_data:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/stepca-data.tar.gz -C /data

# 4. Extract provisioner key
docker compose up -d stepca
sleep 10
bash extract-provisioner-key.sh

# 5. Start Agent API
docker compose up -d

# 6. Cleanup sensitive files
rm stepca-data.tar.gz
```

## 🛡️ Security Best Practices

1. **Never commit keys:**
   ```bash
   # Always verify before commit
   git status | grep -i "admin"
   ```

2. **Secure file permissions:**
   ```bash
   chmod 600 admin.jwk
   chown root:root admin.jwk  # Or specific user
   ```

3. **Backup keys securely:**
   ```bash
   # Encrypt backup
   tar czf - admin.jwk | gpg -c > admin.jwk.tar.gz.gpg
   
   # Store in secure location (not in git!)
   mv admin.jwk.tar.gz.gpg /secure/backup/location/
   ```

4. **Rotate keys periodically:**
   - Create new provisioner
   - Update agent configurations
   - Revoke old provisioner

## 🆘 Troubleshooting

### Key extraction fails

**Problem:** `extract-provisioner-key.sh` cannot find the key

**Solution:**
```bash
# Check StepCA logs
docker logs vt-stepca

# Verify StepCA is initialized
docker exec vt-stepca step ca health

# Check ca.json exists
docker exec vt-stepca ls -la /home/step/config/

# View provisioners
docker exec vt-stepca step ca provisioner list
```

### Invalid JWK format

**Problem:** `admin.jwk` is not valid JSON

**Solution:**
```bash
# Re-extract from StepCA
docker exec vt-stepca cat /home/step/config/ca.json | \
  jq '.authority.provisioners[0].key' > admin.jwk

# Verify
jq empty admin.jwk
```

### Container cannot read key

**Problem:** Agent API fails with "cannot read provisioner key"

**Solution:**
```bash
# Check volume mount
docker inspect vt-api-agent | jq '.[0].Mounts'

# Verify key is in stepca_data volume
docker run --rm -v 04-agent-api_stepca_data:/data alpine ls -la /data/secrets/

# If missing, check path in docker-compose.yml
# Should be: /home/step/secrets/admin.jwk or in config
```

## 📚 Related Documentation

- [PRODUCTION_DEPLOYMENT.md](../PRODUCTION_DEPLOYMENT.md) - Full deployment guide
- [StepCA Documentation](https://smallstep.com/docs/step-ca/)
- [JWK Specification](https://datatracker.ietf.org/doc/html/rfc7517)
