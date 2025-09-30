# KẾ HOẠCH KIỂM TRA LUỒNG HOẠT ĐỘNG - VT AUDIT PLATFORM

## TỔNG QUAN HỆ THỐNG

### Mô tả tổng quát
VT Audit là một hệ thống giám sát tuân thủ bảo mật gồm hai phần chính:
- **Agent**: Cài trên máy trạm Windows để rà quét theo tiêu chuẩn ATTT
- **Dashboard**: Giao diện tập trung cho quản trị viên để xem kết quả và quản lý policy

### Kiến trúc tổng thể
```
[Agent Windows] --mTLS--> [Nginx Gateway] ---> [Server Components]
[Admin Browser] --HTTPS--> [Nginx Gateway] ---> [OAuth2 Proxy] ---> [Keycloak] 
                                              ---> [Dashboard SPA]
```

## 1. PHÂN TÍCH CẤU TRÚC HỆ THỐNG

### 1.1 Các thành phần chính
| Thành phần | Mục đích | Port | Exposure |
|------------|----------|------|----------|
| Nginx Gateway | Entry point duy nhất, xử lý mTLS cho agent, proxy traffic | 443/8443 | Public |
| Step-CA | Cấp phát certificate mTLS cho agent | 9000 | Internal |
| API Agent (vt-server) | Xử lý enrollment agent, policy delivery, nhận kết quả | 8080 | Internal |
| API Dashboard (vt-server) | API cho dashboard, xác thực OIDC | 8081 | Internal |
| OAuth2-Proxy | Middleware xác thực OIDC cho admin | 4180 | Internal |
| Keycloak | Identity Provider cho admin | 8080 | Internal |
| Dashboard SPA | Giao diện web tĩnh | 80 | Internal |
| PostgreSQL | Database lưu trữ | 5432 | Internal |

### 1.2 Cấu trúc code
```
agent/                     # Agent Windows
├── cmd/vt-agent/          # Entry point agent
├── pkg/audit/             # Audit engine
├── pkg/collector/         # Thu thập dữ liệu Windows
├── pkg/enroll/            # Enrollment & certificate
├── pkg/evaluator/         # Đánh giá compliance
├── pkg/policy/            # Policy management
├── pkg/render/            # Export HTML/Excel/JSON
├── pkg/report/            # Submit results
├── pkg/svcwin/            # Windows service
└── pkg/tlsclient/         # mTLS client

server/                    # Server components
├── cmd/vt-server/         # Entry point server
├── pkg/dashboard/         # Dashboard API & auth
├── pkg/httpagent/         # Agent API handlers
├── pkg/model/             # Data models
├── pkg/policy/            # Policy processing
├── pkg/server/            # Server runtime
├── pkg/stepca/            # Step-CA integration
└── pkg/storage/           # Database layer

env/                       # Deployment
├── docker-compose.yml     # Stack definition
├── conf/                  # Configurations
└── docker/                # Dockerfiles

rules/                     # Policy definitions
└── windows.yml            # Windows baseline

server/ui/                 # Dashboard frontend
├── index.html             # Audit dashboard
└── policy.html            # Policy editor
```

## 2. LUỒNG HOẠT ĐỘNG CHI TIẾT

### 2.1 Luồng Agent (mTLS Enrollment & Audit)

#### Bước 1: Bootstrap & Enrollment
```
1. Agent → POST https://gateway.local:8443/agent/bootstrap/ott
   - Headers: bootstrap token từ VT_AGENT_BOOTSTRAP_TOKEN
   - Gateway → nginx proxy → api-agent:8080/bootstrap/ott
   
2. API Agent → Step-CA: tạo JWK one-time token
   - Step-CA validate provisioner key
   - Trả về: OTT token + Step-CA URL + CA bundle
   
3. Agent → Step-CA: exchange OTT for certificate
   - Agent tạo CSR với hostname
   - Step-CA validate OTT → cấp client certificate
   - Agent lưu cert/key vào data/certs/
   
4. Agent → POST https://gateway.local:8443/agent/enroll  
   - mTLS với client certificate vừa nhận
   - Gateway verify cert → forward với X-Client-* headers
   - API Agent tạo/update agent record trong DB
```

#### Bước 2: Policy Fetch & Audit
```
5. Agent → GET https://gateway.local:8443/agent/policy/enroll
   - mTLS authentication
   - API Agent → DB: LoadActivePolicy("windows")
   - Trả về policy bundle (version, policies, hash)
   
6. Agent thực hiện audit cục bộ:
   - audit.Execute() → collector.CollectWindows() cho từng rule
   - Hỗ trợ query types: powershell, cmd, service, registry, process
   - evaluator.Evaluate() so sánh actual vs expected
   - Tạo report.Result[] với status PASS/FAIL
   
7. Agent → POST https://gateway.local:8443/agent/results
   - Submit kết quả audit với mTLS
   - API Agent → DB: ReplaceLatestResults()
```

#### Bước 3: Service Mode vs Local Mode
```
Service Mode:
- Chạy như Windows Service
- Định kỳ fetch policy → audit → submit results
- Interval configurable qua PollInterval()

Local Mode (--local):
- Chỉ fetch policy → audit → export file
- Không submit lên server
- Hỗ trợ export: JSON, HTML, Excel
- File output: audit_<hostname>_<timestamp>.<ext>
```

### 2.2 Luồng Admin (OIDC Authentication & Dashboard)

#### Bước 1: Authentication Flow
```
1. Browser → https://gateway.local:8443/dashboard/
   - Nginx load SPA từ dashboard container
   - SPA client-side routing
   
2. SPA → fetch('/dashboard/api/results')
   - Gateway → oauth2-proxy:4180
   - Nếu chưa có session → redirect to Keycloak
   
3. Keycloak Login:
   - Browser → Keycloak login form
   - User nhập credentials
   - Keycloak verify → issue OIDC tokens
   - Redirect về oauth2-proxy với authorization code
   
4. OAuth2-Proxy:
   - Exchange code for ID token
   - Set secure session cookie  
   - Forward request to api-user:8081 với OIDC bearer token
   
5. API Dashboard:
   - Verify OIDC token với Keycloak
   - Check role permissions
   - Trả về JSON data
```

#### Bước 2: Dashboard Operations
```
View Results:
- GET /dashboard/api/results?host=&from=&to=&q=
- Filter theo hostname, timerange, search terms
- Trả về latest audit results từ tất cả agents

View Policy:
- GET /dashboard/api/policy/active
- Load active Windows policy từ DB
- Trả về YAML format để edit

Edit Policy (Admin only):
- POST /dashboard/api/policy/save 
- Check admin role: realm_access.roles[] contains "admin"
- Parse YAML → validate → save new version
- Auto-activate new version

Policy History:
- GET /dashboard/api/policy/history
- List all policy versions với timestamps
```

## 3. KẾ HOẠCH KIỂM TRA STEP-BY-STEP

### Phase 1: Infrastructure Testing

#### 1.1 Docker Stack Verification
```bash
# Bước 1: Kiểm tra Docker Compose
cd env/
docker-compose up -d

# Bước 2: Verify containers
docker ps
# Expected: postgres, stepca, keycloak, api-agent, api-backend, dashboard, gateway, oidc-proxy

# Bước 3: Health checks
docker-compose logs -f stepca
docker-compose logs -f keycloak
curl -k https://localhost:8443/health
```

#### 1.2 Network Connectivity
```bash
# Kiểm tra internal networks
docker network ls | grep vt-audit

# Test Step-CA accessibility
docker exec -it vt-stepca curl -k https://localhost:9000/health

# Test database
docker exec -it vt-postgres pg_isready -U vtaudit -d vtaudit
```

#### 1.3 Certificate Infrastructure
```bash
# Kiểm tra Step-CA provisioner
docker exec -it vt-stepca step ca provisioner list

# Verify nginx certificates
docker exec -it vt-gateway ls -la /etc/nginx/certs/
```

### Phase 2: Agent Flow Testing

#### 2.1 Agent Bootstrap Test
```powershell
# Bước 1: Build agent
go build -o agent.exe ./agent/cmd/vt-agent

# Bước 2: Set environment
$env:VT_AGENT_BOOTSTRAP_TOKEN = "your-bootstrap-token"

# Bước 3: Test bootstrap
.\agent.exe --server https://gateway.local:8443/agent --bootstrap-token $env:VT_AGENT_BOOTSTRAP_TOKEN --once

# Expected: 
# - OTT token received
# - Certificate issued by Step-CA
# - Files created in data/certs/: agent.crt, agent.key, ca.pem
```

#### 2.2 Enrollment & Policy Fetch Test
```powershell
# Kiểm tra enrollment
.\agent.exe --server https://gateway.local:8443/agent --once

# Expected logs:
# - "Enrolled successfully"
# - "Fetched policy version X"
# - "Sent Y results"

# Verify certificate files
ls data/certs/
ls data/credentials.json
```

#### 2.3 Local Audit Test
```powershell
# Test offline audit
.\agent.exe audit --policy-file rules/windows.yml --html --json --excel

# Expected outputs:
# - audit_<hostname>_<timestamp>.html
# - audit_<hostname>_<timestamp>.json  
# - audit_<hostname>_<timestamp>.xlsx

# Verify content
Get-Content audit_*.json | ConvertFrom-Json
```

#### 2.4 Service Mode Test
```powershell
# Install service
.\agent.exe service --action install

# Start service
sc start VTAgent

# Check service status
sc query VTAgent

# Verify logs
Get-EventLog -LogName Application -Source "VTAgent" -Newest 10

# Uninstall
.\agent.exe service --action uninstall
```

### Phase 3: Admin Dashboard Testing

#### 3.1 Authentication Flow Test
```bash
# Kiểm tra Keycloak realm
curl -k http://localhost:8080/realms/vt-audit/.well-known/openid_configuration

# Test OAuth2-Proxy health
docker exec -it vt-oidc-proxy curl http://localhost:4180/ping
```

#### 3.2 Dashboard Access Test
```javascript
// Browser test:
// 1. Navigate to https://gateway.local:8443/dashboard/
// 2. Should redirect to Keycloak login
// 3. Login with admin credentials
// 4. Should redirect back to dashboard
// 5. Verify API calls work:

fetch('/dashboard/api/results')
  .then(r => r.json())
  .then(data => console.log('Results:', data));

fetch('/dashboard/api/policy/active')
  .then(r => r.json())
  .then(data => console.log('Policy:', data));
```

#### 3.3 Policy Management Test
```javascript
// Test policy editor
// 1. Navigate to https://gateway.local:8443/dashboard/policy.html
// 2. Load active policy
// 3. Edit YAML content
// 4. Save & activate

const newPolicy = `
- id: TEST-RULE
  rationale: Test rule for validation
  query:
    type: powershell
    cmd: echo "test"
  expect:
    equals: "test"
  pass_text: Test passed
  fail_text: Test failed
`;

fetch('/dashboard/api/policy/save', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({yaml: newPolicy})
});
```

### Phase 4: Integration Testing

#### 4.1 End-to-End Agent-Server Flow
```bash
# Scenario: Agent audit cycle with new policy
# 1. Update policy via dashboard
# 2. Agent picks up new policy
# 3. Results show in dashboard

# Monitor logs
docker-compose logs -f api-agent
docker-compose logs -f api-backend
```

#### 4.2 Multi-Agent Testing
```powershell
# Deploy multiple agents
# Test concurrent enrollment
# Verify results aggregation in dashboard
```

#### 4.3 Failure Scenarios
```bash
# Test network interruptions
# Test certificate expiry
# Test database connectivity issues
# Test Step-CA unavailability
```

### Phase 5: Security & Performance Testing

#### 5.1 mTLS Validation
```bash
# Test without client certificate
curl -k https://gateway.local:8443/agent/enroll
# Expected: 401 Unauthorized

# Test with invalid certificate
curl -k --cert invalid.pem --key invalid.key https://gateway.local:8443/agent/enroll
# Expected: 401/403 Forbidden
```

#### 5.2 OIDC Security
```bash
# Test unauthorized admin operations
curl -k https://gateway.local:8443/dashboard/api/policy/save
# Expected: Redirect to login

# Test role-based access
# Login with non-admin user
# Try policy save operation
# Expected: 403 Forbidden
```

#### 5.3 Performance Testing
```bash
# Load testing với multiple agents
# Database performance với large result sets  
# Memory usage monitoring
```

## 4. CHECKLIST KIỂM TRA

### 4.1 Infrastructure Checklist
- [ ] Docker Compose services all running
- [ ] Networks configured correctly (frontend/backend)
- [ ] Health checks passing
- [ ] DNS resolution (gateway.local)
- [ ] TLS certificates valid
- [ ] Step-CA provisioner configured
- [ ] Database schema initialized
- [ ] Keycloak realm imported

### 4.2 Agent Checklist
- [ ] Bootstrap token authentication works
- [ ] OTT exchange successful
- [ ] Client certificate issued
- [ ] mTLS enrollment successful
- [ ] Policy fetch working
- [ ] Audit execution functional
- [ ] Results submission successful
- [ ] Local mode exports work (JSON/HTML/Excel)
- [ ] Service installation/removal works
- [ ] Service runs automatically
- [ ] Periodic audit cycles execute

### 4.3 Dashboard Checklist
- [ ] SPA loads correctly
- [ ] Keycloak login flow works
- [ ] OIDC token validation
- [ ] Results API returns data
- [ ] Filtering/search functional
- [ ] Policy editor loads
- [ ] Policy save/activate works (admin only)
- [ ] Policy history displays
- [ ] Role-based access control enforced
- [ ] Session management works

### 4.4 Security Checklist
- [ ] Only port 443/8443 exposed publicly
- [ ] mTLS required for agent endpoints
- [ ] Invalid certificates rejected
- [ ] OIDC authentication required for admin
- [ ] Admin role required for policy changes
- [ ] Session cookies secure
- [ ] Secrets not logged/exposed
- [ ] Database access restricted

## 5. CÔNG CỤ KIỂM TRA

### 5.1 Scripts kiểm tra tự động
```bash
#!/bin/bash
# health-check.sh
echo "Checking VT Audit Platform Health..."

# Check containers
echo "Container Status:"
docker-compose ps

# Check endpoints
echo "Testing endpoints:"
curl -k -s https://gateway.local:8443/health && echo "Gateway: OK" || echo "Gateway: FAIL"

# Check database
docker exec vt-postgres pg_isready -U vtaudit -d vtaudit && echo "Database: OK" || echo "Database: FAIL"
```

### 5.2 Monitoring & Logging
```bash
# Centralized logging
docker-compose logs -f --tail=100

# Specific service logs
docker-compose logs api-agent
docker-compose logs api-backend
docker-compose logs gateway

# Database queries
docker exec -it vt-postgres psql -U vtaudit -d vtaudit -c "SELECT COUNT(*) FROM agents;"
docker exec -it vt-postgres psql -U vtaudit -d vtaudit -c "SELECT COUNT(*) FROM latest_results;"
```

## 6. XỬ LÝ SỰ CỐ

### 6.1 Các sự cố thường gặp

#### Agent không thể enroll
```bash
# Check Step-CA logs
docker-compose logs stepca

# Verify bootstrap token
echo $VT_AGENT_BOOTSTRAP_TOKEN

# Check nginx mTLS config
docker exec vt-gateway nginx -t
```

#### Dashboard không load được
```bash
# Check oauth2-proxy logs
docker-compose logs oidc-proxy

# Verify Keycloak realm
curl -k http://localhost:8080/realms/vt-audit/.well-known/openid_configuration

# Check API backend
docker-compose logs api-backend
```

#### Policy không update
```bash
# Check admin permissions
# Verify YAML syntax
# Check database constraints
docker exec -it vt-postgres psql -U vtaudit -d vtaudit -c "SELECT * FROM policy_versions ORDER BY updated_at DESC LIMIT 5;"
```

### 6.2 Recovery procedures
```bash
# Reset Step-CA
docker-compose down
docker volume rm vt-audit_stepca_data
docker-compose up -d stepca

# Reset database
docker-compose down
docker volume rm vt-audit_db_data  
docker-compose up -d postgres

# Regenerate certificates
# Update agent configurations
```

## 7. KẾT LUẬN

Kế hoạch này cung cấp framework toàn diện để kiểm tra luồng hoạt động của VT Audit Platform. Thực hiện theo từng phase để đảm bảo hệ thống hoạt động đúng như thiết kế và đáp ứng các yêu cầu bảo mật.

### Ưu tiên kiểm tra:
1. **High Priority**: Infrastructure, Agent enrollment, Authentication
2. **Medium Priority**: Dashboard functionality, Policy management  
3. **Low Priority**: Performance testing, Edge cases

### Cập nhật thường xuyên:
- Monitor logs for errors
- Update test cases khi có code changes
- Document issues và solutions
- Review security configurations định kỳ