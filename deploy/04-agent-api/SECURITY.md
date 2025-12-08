# Security - Provisioner Key Management

## ⚠️ CRITICAL SECURITY NOTICE

The following files contain **PRIVATE CRYPTOGRAPHIC KEYS** and must **NEVER** be committed to git:

- `admin.jwk` - StepCA provisioner private key (JWK format)
- `admin.json` - Provisioner configuration
- `admin-provisioner.json` - Provisioner metadata

## 🔒 Gitignore Protection

These patterns are in `.gitignore`:
```gitignore
*.jwk
**/admin.json
**/admin-provisioner.json
**/admin.jwk
```

## ✅ Verification

Before committing, always check:
```bash
git status | grep -i admin
# Should return nothing if properly ignored
```

## 🚀 Automatic Key Generation

Keys are automatically extracted from StepCA after deployment:

```bash
# 1. Deploy StepCA
docker compose up -d stepca
sleep 30

# 2. Extract provisioner key
bash extract-provisioner-key.sh

# 3. Verify
ls -la admin.jwk  # Should exist with 600 permissions
```

## 📖 Full Documentation

See [PROVISIONER_KEY_SETUP.md](PROVISIONER_KEY_SETUP.md) for complete setup instructions.

## 🆘 If Key Was Accidentally Committed

If you accidentally committed these files:

```bash
# Remove from git history
git rm --cached admin.jwk admin.json admin-provisioner.json
git commit -m "Remove accidentally committed secrets"
git push

# Rotate the keys immediately
# Generate new provisioner in StepCA
# Update all agent configurations with new bootstrap token
```

## 🛡️ Best Practices

1. ✅ Keys generated automatically on deployment
2. ✅ Never stored in source control
3. ✅ Encrypted at rest with StepCA password
4. ✅ Secure file permissions (600)
5. ✅ Backed up separately from code
6. ✅ Rotated periodically
