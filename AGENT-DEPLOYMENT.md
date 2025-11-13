# VT-Audit Agent Deployment Guide

## ✅ **SOLUTION** - Agent Enrollment Fixed!

**Issue**: Agent getting 401 Unauthorized on `/api/enroll`  
**Root Cause**: Nginx routing `/api/enroll` to `enroll_gateway/enroll` instead of `enroll_gateway/api/enroll`  
**Fix**: Updated nginx config to route correctly

## 🚀 **Agent Port Configuration**

### **Correct Setup:**
- **Agent Port**: `443` (for both enrollment + runtime)
- **Admin Dashboard**: `8443` (for web UI)

```bash
# Agent connects to port 443
agent.exe --server https://gateway.local:443

# Admin accesses dashboard on port 8443  
https://gateway.local:8443
```

## 📁 **Files Required for Agent Distribution**

### **Single File Deployment:**
```
✅ vt-agent.exe        # Only file needed!
❌ No config files     # Zero-config deployment
❌ No certificates     # Auto-generated on first run
❌ No policy files     # Downloaded from server
```

### **How Agent Works:**

#### **1. First Time (Automatic Enrollment):**
```cmd
vt-agent.exe --server https://your-server:443
```

**Agent Process:**
1. 🔗 POST `https://server:443/api/enroll` → Get OTT token
2. 🔐 POST `https://server:9000/1.0/sign` → Get mTLS certificate 
3. 📁 Create `data/certs/` with certificates
4. 📋 Download policies via mTLS
5. ✅ Start regular auditing

#### **2. Subsequent Runs:**
```cmd
vt-agent.exe --server https://your-server:443
```
- Uses cached certificates from `data/certs/`
- Updates policies automatically
- Submits audit results via mTLS

### **Auto-Generated Files:**
```
data/
├── certs/
│   ├── agent.crt      # Client certificate (auto-generated)
│   ├── agent.key      # Private key (auto-generated)  
│   └── ca.pem         # CA certificate (auto-downloaded)
├── policy_cache.json  # Cached policies (auto-updated)
└── YYYYMMDD_HHMMSS_HOSTNAME.json  # Audit results
```

## 🌐 **Network Ports Summary**

| Port | Service | Used By | Purpose |
|------|---------|---------|---------|
| **443** | nginx → api-agent | **Agents** | Agent enrollment + runtime API |
| **8443** | nginx → api-backend | **Admins** | Web dashboard + policy management |
| 8080 | keycloak | Admins (setup) | User management console |
| 9000 | step-ca | Agents (direct) | Certificate signing |

## 🛠️ **Deployment Steps**

### **1. Server Setup**
```bash
# Deploy server stack
docker-compose -f env/docker-compose.yml up -d

# Verify enrollment endpoint
curl -k -X POST https://your-server:443/api/enroll \
  -H "Content-Type: application/json" \  
  -d '{"subject":"test-host"}'
```

### **2. Agent Distribution**
```bash
# Build agent
cd agent && go build -o vt-agent.exe cmd/vt-agent/main.go

# Copy to workstations (single file!)
copy vt-agent.exe \\workstation\C$\Tools\

# Run on workstation (zero-config)
vt-agent.exe --server https://your-server:443
```

### **3. Verification**
```bash
# Check agent enrollment
docker-compose logs nginx | grep "api/enroll"

# Check certificate generation  
docker-compose logs stepca | grep "sign"

# Check policy fetch
docker-compose logs api-agent | grep "policies"
```

## 🔧 **Troubleshooting**

### **Agent 401 Unauthorized**
```bash
# Check nginx routing
docker-compose logs nginx

# Verify enroll-gateway is running
docker-compose ps enroll-gateway

# Test enrollment endpoint
curl -k -X POST https://server:443/api/enroll \
  -H "Content-Type: application/json" \
  -d '{"subject":"test"}'
```

### **Agent Connection Failed**
```bash  
# Check Step-CA health
curl -k https://server:9000/health

# Check certificate generation
ls data/certs/  # Should have agent.crt, agent.key, ca.pem
```

### **Policy Fetch Failed**
```bash
# Check API agent logs
docker-compose logs api-agent

# Verify mTLS certificate
openssl x509 -in data/certs/agent.crt -text -noout
```

## 🎯 **Success Criteria**

- [ ] Agent runs `--server https://server:443` without errors
- [ ] Agent auto-generates certificates in `data/certs/`  
- [ ] Agent fetches policies successfully
- [ ] Admin dashboard accessible on `https://server:8443`
- [ ] No configuration files needed for agent deployment

**🚀 Result: Single-file agent deployment with automatic enrollment!**