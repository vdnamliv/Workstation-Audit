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