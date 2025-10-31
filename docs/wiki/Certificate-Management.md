# Certificate Management

Complete guide for managing mTLS certificates trong VT-Audit system.

## 🔐 Overview

VT-Audit sử dụng **automatic mTLS certificate enrollment** với Step-CA, providing zero-configuration certificate management cho Windows agents.

### Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Windows       │───▶│   Enroll Gateway │───▶│    Step-CA      │
│   Agent         │    │   Port :8742     │    │   Certificate   │
│   (Auto-enroll) │◀───│   (Bootstrap)    │◀───│   Authority     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚀 Automatic Certificate Enrollment

### Zero-Config Process

Agent tự động enroll certificate mà không cần pre-configured tokens:

1. **Agent Request**: Gửi hostname tới `/api/enroll`
2. **Auto-Generate OTT**: Enroll-gateway tự động tạo OTT từ Step-CA
3. **Certificate Issue**: Agent nhận certificate và lưu local
4. **mTLS Ready**: Sử dụng certificate cho subsequent requests

### Enrollment Flow

```bash
# Agent automatically enrolls when needed
.\agent.exe --once --server https://gateway.local:8443

# Certificate stored at:
# %PROGRAMDATA%\VT-Agent\certs\client.crt
# %PROGRAMDATA%\VT-Agent\certs\client.key
# %PROGRAMDATA%\VT-Agent\certs\ca.crt
```

## 📋 Certificate Configuration

### Step-CA Configuration

```json
{
  "root": "/home/step/certs/root_ca.crt",
  "crt": "/home/step/certs/intermediate_ca.crt",
  "key": "/home/step/secrets/intermediate_ca_key",
  "provisioners": [
    {
      "type": "JWK",
      "name": "bootstrap@vt-audit",
      "key": {
        "use": "sig",
        "kty": "EC",
        "kid": "...",
        "crv": "P-256",
        "alg": "ES256"
      },
      "claims": {
        "maxTLSCertDuration": "24h",
        "defaultTLSCertDuration": "24h"
      }
    }
  ]
}
```

### Agent Certificate Configuration

```ini
# distribute/agent.conf
[security]
mtls_enabled = true
certificate_path = %PROGRAMDATA%\VT-Agent\certs\client.crt
private_key_path = %PROGRAMDATA%\VT-Agent\certs\client.key
ca_certificate_path = %PROGRAMDATA%\VT-Agent\certs\ca.crt
verify_server_cert = true

[enrollment]
enroll_gateway_url = https://gateway.local:8443/api/enroll
step_ca_url = https://gateway.local:8443/step-ca
certificate_ttl = 24h
renewal_threshold = 1h
```

## 🔄 Certificate Lifecycle

### Automatic Renewal

Agent tự động renew certificate trước khi hết hạn:

- **Certificate TTL**: 24 giờ (configurable)
- **Renewal Window**: 1 giờ trước expiry
- **Fallback**: Re-enroll với enroll-gateway nếu renewal failed

```bash
# Check certificate expiration
.\agent.exe --check-cert

# Force manual renewal
.\agent.exe --renew-cert

# Reset certificates và auto re-enroll
.\agent.exe --reset-cert
```

### Certificate Validation

Server validates client certificates với:

- **Certificate Authority**: Signed by Step-CA intermediate
- **Subject**: Hostname match với agent identity
- **Expiration**: Certificate còn valid
- **Revocation**: Check certificate không bị revoke

## 🛠️ Manual Certificate Management

### Check Certificate Status

```bash
# Agent certificate information
.\agent.exe --check-cert

# Output example:
# Certificate Path: C:\ProgramData\VT-Agent\certs\client.crt
# Subject: CN=DESKTOP-ABC123
# Issuer: CN=VT-Audit Intermediate CA
# Valid From: 2025-10-31 10:00:00
# Valid To: 2025-11-01 10:00:00
# Status: Valid (expires in 23h 45m)
```

### Certificate Inspection

```bash
# Using OpenSSL (if available)
openssl x509 -in "%PROGRAMDATA%\VT-Agent\certs\client.crt" -text -noout

# Using PowerShell
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import("C:\ProgramData\VT-Agent\certs\client.crt")
$cert | Format-List Subject, Issuer, NotBefore, NotAfter
```

### Manual Certificate Cleanup

```powershell
# Stop agent service
Stop-Service VT-Agent -Force

# Remove existing certificates
Remove-Item "C:\ProgramData\VT-Agent\certs\*" -Force -Recurse

# Start service (will auto-enroll new certificate)
Start-Service VT-Agent
```

## 🔧 Server-Side Certificate Management

### Step-CA Management

```bash
# Check Step-CA status
docker logs stepca

# View certificate authority info
docker exec stepca step ca health

# List active certificates
docker exec stepca step ca certificate list
```

### Nginx mTLS Configuration

```nginx
# /env/conf/nginx/conf.d/20-agent-mtls-443.conf
server {
    listen 443 ssl;
    server_name gateway.local;

    # SSL Configuration
    ssl_certificate /certs/nginx/server.crt;
    ssl_certificate_key /certs/nginx/server.key;

    # mTLS Configuration
    ssl_client_certificate /certs/stepca/intermediate_ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;

    # Agent API endpoints
    location /agent {
        proxy_pass http://api-agent;
        proxy_set_header X-SSL-Client-Cert $ssl_client_cert;
        proxy_set_header X-SSL-Client-S-DN $ssl_client_s_dn;
        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
    }

    # Enrollment gateway
    location /api/enroll {
        proxy_pass http://enroll-gateway;
    }
}
```

## 🧪 Testing Certificate Setup

### Test Enrollment Process

```bash
# Test enrollment endpoint
curl -k https://gateway.local:8443/api/enroll \
  -H "Content-Type: application/json" \
  -d '{"subject": "test-hostname", "sans": ["test-hostname"]}'

# Expected response:
{
  "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2025-10-31T12:00:00Z",
  "stepca_url": "https://gateway.local:8443/step-ca"
}
```

### Test mTLS Connection

```bash
# Test với automatic mTLS
.\agent.exe --once --debug

# Test certificate authentication
curl --cert client.crt --key client.key --cacert ca.crt \
  https://gateway.local:8443/agent/health
```

### Test Bypass Mode

```bash
# Test với bypass authentication
.\agent.exe --skip-mtls --once --debug

# Verify bypass headers
curl -k -H "X-Test-Mode: true" \
  https://gateway.local:8443/agent/policies
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Certificate Enrollment Failed

**Symptoms:**
- Agent không thể kết nối server
- "Certificate enrollment failed" errors
- Empty certificate directory

**Solutions:**
```bash
# Check enroll-gateway connectivity
curl -k https://gateway.local:8443/api/enroll -v

# Check Step-CA connectivity  
curl -k https://gateway.local:8443/step-ca/health

# Reset và retry enrollment
.\agent.exe --reset-cert --debug
```

#### 2. mTLS Handshake Failed

**Symptoms:**
- "TLS handshake failed" errors
- "Certificate verification failed"
- Connection refused

**Solutions:**
```bash
# Test với bypass mode
.\agent.exe --skip-mtls --once --debug

# Check nginx mTLS config
docker exec vt-nginx nginx -t

# Check certificate validity
.\agent.exe --check-cert
```

#### 3. Certificate Expired

**Symptoms:**
- "Certificate has expired" errors
- Authentication failures
- Agent không thể renew

**Solutions:**
```bash
# Force certificate renewal
.\agent.exe --renew-cert

# If renewal fails, reset certificates
.\agent.exe --reset-cert

# Check renewal threshold settings
Get-Content distribute\agent.conf | Select-String renewal
```

### Debug Commands

```bash
# Agent debug với full logging
.\agent.exe --once --debug --log-level debug

# Check certificate chain
openssl verify -CAfile ca.crt -intermediate intermediate_ca.crt client.crt

# Test Step-CA connection
step ca health --ca-url https://gateway.local:8443/step-ca --root ca.crt
```

## 📊 Certificate Monitoring

### Automated Monitoring

```powershell
# PowerShell script to monitor certificate expiration
function Check-CertificateExpiration {
    $certPath = "$env:PROGRAMDATA\VT-Agent\certs\client.crt"
    if (Test-Path $certPath) {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certPath
        $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
        
        if ($daysUntilExpiry -lt 1) {
            Write-Warning "Certificate expires in $daysUntilExpiry days!"
            # Trigger renewal
            & "C:\Program Files\VT-Agent\agent.exe" --renew-cert
        }
    }
}
```

### Metrics Collection

```bash
# Certificate metrics for monitoring
docker exec stepca step certificate inspect /home/step/certs/intermediate_ca.crt | \
  grep -E "(Valid|Serial|Subject)"

# Agent certificate status
.\agent.exe --check-cert --json | jq '.expires_in_hours'
```

## 🔐 Security Best Practices

### Certificate Security

1. **Private Key Protection**: Private keys stored với restricted permissions
2. **Certificate Rotation**: Automatic 24-hour certificate rotation
3. **Revocation Support**: Implement certificate revocation cho compromised agents
4. **Audit Trail**: Log tất cả certificate operations

### Production Recommendations

```bash
# Set strict file permissions
icacls "C:\ProgramData\VT-Agent\certs" /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T
icacls "C:\ProgramData\VT-Agent\certs" /grant:r "BUILTIN\Administrators:(OI)(CI)F" /T
icacls "C:\ProgramData\VT-Agent\certs" /inheritance:r

# Enable certificate monitoring
schtasks /create /tn "VT-Agent Certificate Check" \
  /tr "C:\Program Files\VT-Agent\agent.exe --check-cert" \
  /sc daily /st 09:00
```

### Certificate Backup

```bash
# Automated certificate backup
$backupPath = "C:\Backup\VT-Agent\certs\$(Get-Date -Format 'yyyyMMdd')"
New-Item -Path $backupPath -ItemType Directory -Force
Copy-Item "$env:PROGRAMDATA\VT-Agent\certs\*" $backupPath -Recurse
```

## 📞 Support

For certificate-related issues:
- Check [Troubleshooting Guide](Troubleshooting.md)
- Create GitHub Issue với "certificate" label
- Include output từ `.\agent.exe --check-cert --debug`