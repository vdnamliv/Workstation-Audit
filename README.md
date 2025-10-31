# VT-Audit - Enterprise Windows Compliance Platform# VT-Audit - Enterprise Windows Compliance Monitoring# VT-Audit - Enterprise Windows Compliance Platform



[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)

[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://docker.com)

[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://microsoft.com)[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)

[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://docker.com)[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://docker.com)

VT-Audit là một hệ thống **enterprise-grade** để giám sát tuân thủ baseline security cho Windows workstations. Hệ thống cung cấp dashboard tập trung, agent tự động với mTLS authentication, và analytics real-time.

[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://microsoft.com)[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://microsoft.com)

## ✨ Key Features

[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

- 🎯 **Server-Controlled Scheduling**: Dashboard điều khiển polling intervals của tất cả agents

- 🔄 **Real-time Policy Updates**: Central policy management với automatic distribution

- 📊 **Multi-format Reporting**: JSON, HTML, Excel export với rich analytics

- 🛡️ **Security-First**: mTLS authentication với bypass mode for testingVT-Audit là hệ thống **enterprise-grade** giám sát tuân thủ baseline security cho Windows workstations với dashboard tập trung, agent tự động, và mTLS authentication.VT-Audit là một hệ thống **enterprise-grade** để giám sát tuân thủ baseline security cho Windows workstations. Hệ thống cung cấp dashboard tập trung, agent tự động, và analytics real-time.

- 🚀 **Zero-Touch Deployment**: Agent tự cài đặt như Windows service

- 💾 **Intelligent Caching**: Offline operation với policy caching

- 📈 **Scalable Architecture**: Support hàng trăm agents simultaneous

## 🚀 Quick Start - Production Deployment## ✨ Key Features

## 🏗️ System Architecture



```mermaid

graph TB### Step 1: Server Environment Setup- 🎯 **Server-Controlled Scheduling**: Dashboard điều khiển polling intervals của tất cả agents

    subgraph "VT-Server Environment"

        Dashboard[Dashboard SPA]- 🔄 **Real-time Policy Updates**: Central policy management với automatic distribution

        Server[VT-Server Backend]

        DB[(PostgreSQL)]```bash- 📊 **Multi-format Reporting**: JSON, HTML, Excel export với rich analytics

        Auth[Keycloak OIDC]

        Proxy[Nginx Gateway]# 1. Clone và setup environment- 🛡️ **Security-First**: mTLS authentication với bypass mode for testing

        StepCA[Step-CA Certificate Authority]

    endgit clone https://github.com/your-org/vt-audit.git- 🚀 **Zero-Touch Deployment**: Agent tự cài đặt như Windows service

    

    subgraph "Agent Network"cd vt-audit- 💾 **Intelligent Caching**: Offline operation với policy caching

        A1[Windows Agent 1]

        A2[Windows Agent 2]- 📈 **Scalable Architecture**: Support hàng trăm agents simultaneous

        AN[Windows Agent N]

    end# 2. Tạo production environment config

    

    Dashboard --> Servercp env/.env.example env/.env## 🏗️ System Architecture

    Server --> DB

    Proxy --> Dashboard# Edit env/.env với production values (xem bên dưới)

    Proxy --> Auth

    StepCA -.-> A1```mermaid

    StepCA -.-> A2

    StepCA -.-> AN# 3. Generate certificates và khởi động servicesgraph TB

    A1 -.mTLS.-> Proxy

    A2 -.mTLS.-> Proxycd env    subgraph "VT-Server Environment"

    AN -.mTLS.-> Proxy

```./scripts/generate-mtls-assets.sh        Dashboard[Dashboard SPA]



### Component Overview./scripts/issue-nginx-cert.sh gateway.your-domain.com        Server[VT-Server Backend]



- **🌐 Dashboard**: Web UI với Alpine.js, real-time policy managementdocker-compose up -d        DB[(PostgreSQL)]

- **⚙️ VT-Server**: Go backend với REST API, multi-mode operation

- **💽 PostgreSQL**: Centralized audit storage với advanced querying        Auth[Keycloak OIDC]

- **🔐 Authentication**: Keycloak OIDC cho dashboard, mTLS cho agents

- **🚪 Gateway**: Nginx reverse proxy với SSL termination và mTLS validation# 4. Verify deployment        Proxy[Nginx Gateway]

- **📜 Certificate Authority**: Step-CA cho automatic certificate enrollment

- **📱 Windows Agent**: Service mode với health checks và smart retrydocker-compose ps    end



## 🚀 Quick Startcurl -k https://localhost:443/health    



### Prerequisites```    subgraph "Agent Network"



- **Docker & Docker Compose** (for server environment)        A1[Windows Agent 1]

- **Go 1.21+** (for building agent)

- **Windows 10/11** (for agent deployment)### Step 2: Agent Deployment (Windows)        A2[Windows Agent 2]

- **PowerShell** (for automation scripts)

        AN[Windows Agent N]

### Server Setup

```powershell    end

```bash

# 1. Clone repository# 1. Build agent executable    

git clone https://github.com/your-org/vt-audit.git

cd vt-auditgo build -o agent.exe ./agent/cmd/vt-agent    Dashboard --> Server



# 2. Start server environment    Server --> DB

cd env

docker compose up -d# 2. Production deployment với mTLS    Proxy --> Dashboard



# 3. Access dashboardcd distribute    Proxy --> Auth

open https://localhost:8443

# Login: admin / admin123.\Deploy-VTAgent.ps1 -Mode Production -ServerUrl "https://gateway.your-domain.com"    A1 -.-> Proxy

```

    A2 -.-> Proxy

### Agent Deployment

# 3. Verify agent service    AN -.-> Proxy

```bash

# 1. Build agentGet-Service VT-Agent```

go build -o agent.exe ./agent/cmd/vt-agent

Get-EventLog -LogName Application -Source "VT-Agent" -Newest 5

# 2. Configure agent

# Edit distribute/agent.conf with your server IP```### Component Overview



# 3. Install as Windows service- **🌐 Dashboard**: Web UI với Alpine.js, real-time policy management

sc.exe create VT-Agent binPath="C:\path\to\agent.exe --service --skip-mtls" start=auto DisplayName="VT Compliance Agent"

sc.exe start VT-Agent### Step 3: Access Dashboard- **⚙️ VT-Server**: Go backend với REST API, multi-mode operation

```

- **💽 PostgreSQL**: Centralized audit storage với advanced querying

### Quick Test

```- **🔐 Authentication**: Keycloak OIDC cho dashboard, mTLS/bypass cho agents

```bash

# Test agent locallyURL: https://gateway.your-domain.com- **🚪 Gateway**: Nginx reverse proxy với SSL termination

.\agent.exe --once --skip-mtls --html

Login: admin / [from Keycloak setup]- **📱 Windows Agent**: Service mode với health checks và smart retry

# Test agent connectivity

.\agent.exe --local --json --server https://your-server:8443/agent```

```

## � Quick Start

## 🤖 Agent Operation Modes

## ⚙️ Production Environment Configuration

### 1. Local Mode (Fetch Policy, Run Local, No Submit)

### Prerequisites

Fetch policy từ server, chạy audit local, không gửi results:

### Required Environment Variables (env/.env)- **Docker & Docker Compose** (for server environment)

```bash

.\agent.exe --local --html --skip-mtls- **Go 1.21+** (for building agent)

```

```bash- **Windows 10/11** (for agent deployment)

- Kết nối server để lấy policy mới nhất

- Chạy audit trên máy local# =============================================================================- **PowerShell** (for automation scripts)

- Tạo file HTML report để xem kết quả

- KHÔNG gửi results lên server# VT-AUDIT PRODUCTION CONFIGURATION



### 2. Once Mode (Fetch Policy, Run Once, Submit Results)# =============================================================================### Server Setup



Fetch policy từ server, chạy audit, gửi results lên server:



```bash# Certificate Authority Configuration```bash

.\agent.exe --once --skip-mtls

```STEPCA_PROVISIONER_PASSWORD=YourSecurePassword123!# 1. Clone repository



- Kết nối server để lấy policy mới nhấtSTEPCA_PROVISIONER_NAME=vt-audit-provisionergit clone https://github.com/your-org/vt-audit.git

- Chạy audit một lần duy nhất

- Gửi kết quả audit lên servercd vt-audit

- Thoát sau khi hoàn thành

# Database Configuration  

### 3. Service Mode (Continuous Periodic Audits)

POSTGRES_DB=vtaudit# 2. Start server environment

Chạy như Windows service với interval điều khiển từ server:

POSTGRES_USER=vtauditcd env

**Manual Installation (Recommended):**

POSTGRES_PASSWORD=YourDBPassword456!docker compose up -d

```cmd

# Chạy PowerShell as AdministratorPOSTGRES_HOST=postgres

sc.exe create VT-Agent binPath= "C:\Path\To\agent.exe --service --skip-mtls" start= auto DisplayName= "VT Compliance Agent"

sc.exe start VT-AgentPOSTGRES_PORT=5432# 3. Access dashboard



# Kiểm tra service statusopen https://localhost:8443

sc.exe query VT-Agent

```# Keycloak Authentication# Login: admin / admin123



**Service Features:**KEYCLOAK_ADMIN=admin```



- 🔍 **Health Check tự động**: Kiểm tra server connection, interval changes, policy versionKEYCLOAK_ADMIN_PASSWORD=YourKeycloakPassword789!

- ⏱️ **Server-controlled interval**: Dashboard control polling frequency (5m, 10m, 1h, etc.)

- 📋 **Smart caching**: Chỉ fetch policy khi version thay đổiKEYCLOAK_DB_PASSWORD=YourKeycloakDBPassword!### Agent Deployment

- 🔄 **Dynamic updates**: Tự động update interval khi admin thay đổi từ dashboard

- 🛡️ **Graceful fallback**: Sử dụng cache khi server unreachable



### 4. Service Installation (Windows Service Deployment)# Network Configuration```bash



Cài đặt và chạy agent như Windows service:NGINX_HOST=gateway.your-domain.com# 1. Build agent



```bashNGINX_SSL_CERT_PATH=/etc/nginx/certs/server.crtgo build -o agent.exe ./agent/cmd/vt-agent

# Cài đặt service

.\agent.exe --installNGINX_SSL_KEY_PATH=/etc/nginx/certs/server.key



# Khởi động service # 2. Configure agent

sc start VT-Agent

# Security Settings# Edit distribute/agent.conf with your server IP

# Kiểm tra status

sc query VT-AgentJWT_SECRET=YourJWTSecretKey_MinLength32Characters!



# Gỡ cài đặt serviceENCRYPTION_KEY=YourEncryptionKey_Exactly32Characters# 3. Install as Windows service

.\agent.exe --uninstall

```sc.exe create VT-Agent binPath="C:\path\to\agent.exe --service --skip-mtls" start=auto DisplayName="VT Compliance Agent"



## 🔐 mTLS Authentication với Step-CA# Agent Configurationsc.exe start VT-Agent



### Bootstrap Agent với CertificateDEFAULT_POLLING_INTERVAL=600```



Để sử dụng mTLS authentication trong production, agent cần được bootstrap với certificate từ Step-CA:BOOTSTRAP_TOKEN_EXPIRY=3600



#### Bước 1: Lấy Bootstrap TokenCERTIFICATE_VALIDITY_HOURS=24### Quick Test



Từ dashboard hoặc admin API, tạo bootstrap token cho agent:



```bash# Monitoring và Logging```bash

# Từ server hoặc admin interface

curl -X POST https://gateway.local:8443/api/enroll \LOG_LEVEL=info# Test agent locally

  -H "Content-Type: application/json" \

  -d '{"subject": "hostname.domain.com", "sans": ["hostname"]}'ENABLE_DEBUG=false.\agent.exe --once --skip-mtls --html

```

METRICS_ENABLED=true

Response sẽ chứa OTT (One-Time Token):

```# Test agent connectivity

```json

{.\agent.exe --local --json --server https://your-server:8443/agent

  "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",

  "expires_at": "2025-10-31T12:00:00Z",## 🏗️ System Architecture Overview```

  "issuer": "bootstrap@vt-audit",

  "audience": "https://stepca:9000"

}

``````## 📊 Dashboard Features



#### Bước 2: Bootstrap Agent với OTTProduction Network



Sử dụng OTT để enroll agent và nhận certificate:        │### Policy Management



```bash        ▼- ⚙️ **Centralized Policies**: Manage Windows compliance rules từ web interface

# Bootstrap với OTT token

.\agent.exe --bootstrap-token "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..." --server https://gateway.local:8443┌─────────────────────────────────┐- 🕐 **Interval Control**: Set polling intervals per agent group (5min - 24h)



# Sau khi bootstrap thành công, certificate sẽ được lưu tại:│     Nginx Gateway (443)         │ ← mTLS Certificate Validation- 📋 **Rule Templates**: Pre-built baseline templates cho different security levels

# %PROGRAMDATA%\VT-Agent\certs\client.crt

# %PROGRAMDATA%\VT-Agent\certs\client.key├─────────────────────────────────┤- 🔄 **Live Updates**: Policy changes propagate to agents automatically

```

│  VT-Server Stack                │

#### Bước 3: Chạy Agent với mTLS

│  ├─ Dashboard UI                │### Results Analytics

Sau khi có certificate, agent có thể chạy với full mTLS authentication:

│  ├─ Agent API (8081)            │- 📈 **Real-time Dashboards**: Agent status và compliance metrics

```bash

# Production mode với mTLS certificates│  ├─ Admin API (8080)            │- 🔍 **Advanced Filtering**: Search by hostname, time range, compliance status

.\agent.exe --once

│  └─ Bootstrap API (8082)        │- 📊 **Trend Analysis**: Historical compliance trends và improvement tracking

# Hoặc production service mode

.\agent.exe --service├─────────────────────────────────┤- 📱 **Export Options**: JSON, HTML, Excel reports với custom formatting



# Install service với mTLS│  ├─ PostgreSQL Database         │

.\agent.exe --install --server https://gateway.local:8443

```│  ├─ Keycloak OIDC              │### Agent Management



### Certificate Management│  └─ Step-CA Certificate Authority│- 🖥️ **Fleet Overview**: All connected agents với last-seen status



#### Automatic Certificate Renewal└─────────────────────────────────┘- 🔧 **Remote Control**: Start/stop audit cycles, update intervals



Agent tự động renew certificate trước khi hết hạn:        ▲- 🏥 **Health Monitoring**: Agent connectivity, version tracking, error reporting



- **Certificate TTL**: 24 giờ (configurable)        │ HTTPS + mTLS- 📍 **Group Management**: Organize agents by location, department, compliance level

- **Renewal Window**: 1 giờ trước expiry

- **Fallback**: Sử dụng bootstrap token để re-enroll nếu renewal failed        ▼```



#### Certificate Validation┌──────────────┐ ┌──────────────┐ ┌──────────────┐



Server validates client certificates với các checks:│  Windows     │ │  Windows     │ │  Windows     │### Bước 4: Kiểm tra services



- **Certificate Authority**: Signed by Step-CA intermediate│  Agent #1    │ │  Agent #2    │ │  Agent #N    │```bash

- **Subject**: Hostname match với agent identity

- **Expiration**: Certificate còn valid│  (Service)   │ │  (Service)   │ │  (Service)   │# Kiểm tra tất cả containers đang chạy

- **Revocation**: Check certificate không bị revoke

└──────────────┘ └──────────────┘ └──────────────┘docker ps

#### Manual Certificate Management

```

```bash

# Kiểm tra certificate hiện tại# Kiểm tra logs

.\agent.exe --check-cert

## 📦 Component Detailsdocker logs vt-nginx

# Force renewal certificate

.\agent.exe --renew-certdocker logs vt-api-agent



# Reset certificates (xóa và bootstrap lại)### VT-Agent (Windows Service)docker logs vt-api-backend

.\agent.exe --reset-cert --bootstrap-token "new-token"

```- **Compliance Monitoring**: Automated Windows baseline security checksdocker logs postgres



### mTLS Configuration- **mTLS Authentication**: Certificate-based authentication với Step-CA```



#### Server-side Configuration (nginx)- **Service Mode**: Runs as Windows service với configurable intervals



```nginx- **Multi-format Reports**: JSON, HTML, Excel export capabilities### Bước 5: Truy cập Dashboard

# /env/conf/nginx/conf.d/20-agent-mtls-443.conf

server {- Mở browser: https://localhost:443

    listen 443 ssl;

    server_name gateway.local;### VT-Server (Docker Stack)- Login với Keycloak credentials (admin/admin)



    # SSL Configuration- **Dashboard API**: Web interface cho policy management- Dashboard hiển thị policy editor và audit results

    ssl_certificate /certs/nginx/server.crt;

    ssl_certificate_key /certs/nginx/server.key;- **Agent API**: Handles agent communication và result collection

    

    # mTLS Configuration- **Certificate Management**: Integrated Step-CA cho automatic enrollment## 🤖 Sử dụng Agent

    ssl_client_certificate /certs/stepca/intermediate_ca.crt;

    ssl_verify_client on;- **Data Storage**: PostgreSQL với optimized schema cho compliance data

    ssl_verify_depth 2;

### Build Agent

    # Agent API endpoints

    location /agent {## 🔐 Security Features```bash

        proxy_pass http://api-agent;

        proxy_set_header X-SSL-Client-Cert $ssl_client_cert;# Từ thư mục gốc

        proxy_set_header X-SSL-Client-S-DN $ssl_client_s_dn;

        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;### Authentication & Authorizationgo build -o agent.exe ./agent/cmd/vt-agent

    }

}- **mTLS Certificates**: All production agents use client certificates```

```

- **OIDC Integration**: Keycloak authentication cho dashboard access

#### Agent-side Configuration

- **Role-based Access**: Admin, operator, và viewer roles### Các mode chạy Agent

```ini

# distribute/agent.conf- **Certificate Rotation**: Automatic 24-hour certificate renewal

[security]

mtls_enabled = true#### 1. Local Mode (Fetch Policy, Run Local, No Submit)

certificate_path = %PROGRAMDATA%\VT-Agent\certs\client.crt

private_key_path = %PROGRAMDATA%\VT-Agent\certs\client.key### Network SecurityFetch policy từ server, chạy audit local, không gửi results:

ca_certificate_path = %PROGRAMDATA%\VT-Agent\certs\ca.crt

verify_server_cert = true- **TLS 1.3**: Strong encryption cho all communications```bash



[enrollment]- **Rate Limiting**: Protection against DoS attacks.\agent.exe --local --html --skip-mtls

step_ca_url = https://gateway.local:8443/step-ca

bootstrap_audience = https://stepca:9000- **Security Headers**: HSTS, CSP, và other security headers```

certificate_ttl = 24h

renewal_threshold = 1h- **Network Isolation**: Docker network segmentation- Kết nối server để lấy policy mới nhất

```

- Chạy audit trên máy local

### Testing mTLS Setup

### Data Protection- Tạo file HTML report để xem kết quả

#### 1. Test Certificate Enrollment

- **Encrypted Storage**: Database encryption at rest- KHÔNG gửi results lên server

```bash

# Test bootstrap process- **Secure Configuration**: No secrets in code, environment-based config

.\agent.exe --bootstrap-token "test-token" --server https://gateway.local:8443 --debug

- **Audit Logging**: Complete audit trail cho all activities#### 2. Once Mode (Fetch Policy, Run Once, Submit Results)

# Kiểm tra certificate được tạo

dir "%PROGRAMDATA%\VT-Agent\certs\"- **Data Retention**: Configurable data lifecycle policiesFetch policy từ server, chạy audit, gửi results lên server:

```

```bash

#### 2. Test mTLS Connection

## 🚀 Deployment Modes.\agent.exe --once --skip-mtls

```bash

# Test với mTLS enabled```

.\agent.exe --once --debug

### 1. Development Environment- Kết nối server để lấy policy mới nhất

# Kiểm tra logs cho certificate validation

type "%PROGRAMDATA%\VT-Agent\logs\agent.log"```bash- Chạy audit một lần duy nhất

```

# Start with default test settings- Gửi kết quả audit lên server

#### 3. Test Certificate Renewal

cd env- Thoát sau khi hoàn thành

```bash

# Force certificate renewal testdocker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

.\agent.exe --renew-cert --debug

#### 3. Service Mode (Continuous Periodic Audits)

# Kiểm tra certificate mới

openssl x509 -in "%PROGRAMDATA%\VT-Agent\certs\client.crt" -text -noout# Test agent với bypass modeChạy như Windows service với interval điều khiển từ server:

```

.\agent.exe --once --skip-mtls --server http://localhost:8081

### Troubleshooting mTLS

```**Manual Installation (Recommended):**

#### Common mTLS Issues

```cmd

**Certificate Enrollment Failed:**

### 2. Production Environment  # Chạy PowerShell as Administrator

```bash

# Kiểm tra bootstrap token validity```powershellsc.exe create VT-Agent binPath= "C:\Path\To\agent.exe --service --skip-mtls" start= auto DisplayName= "VT Compliance Agent"

.\agent.exe --check-bootstrap-token "your-token"

# Deploy với full securitysc.exe start VT-Agent

# Kiểm tra Step-CA connectivity

curl -k https://gateway.local:8443/step-ca/health.\Deploy-VTAgent.ps1 -Mode Production -ServerUrl "https://gateway.company.com"

```

# Kiểm tra service status

**mTLS Handshake Failed:**

# Or manual production deploymentsc.exe query VT-Agent

```bash

# Test với bypass mode để isolate issue.\agent.exe --install --server "https://gateway.company.com"```

.\agent.exe --skip-mtls --once --debug

Start-Service VT-Agent

# Kiểm tra nginx logs

docker logs vt-nginx | Select-String "SSL"```**Service Features:**

```

- 🔍 **Health Check tự động**: Kiểm tra server connection, interval changes, policy version

**Certificate Expired:**

### 3. Testing Environment- ⏱️ **Server-controlled interval**: Dashboard control polling frequency (5m, 10m, 1h, etc.)

```bash

# Reset và re-enroll```powershell- 📋 **Smart caching**: Chỉ fetch policy khi version thay đổi

.\agent.exe --reset-cert --bootstrap-token "new-token"

# Enable bypass cho testing environments- 🔄 **Dynamic updates**: Tự động update interval khi admin thay đổi từ dashboard

# Hoặc manual certificate cleanup

Remove-Item "%PROGRAMDATA%\VT-Agent\certs\*" -Force$env:VT_AGENT_FORCE_BYPASS="true"- 🛡️ **Graceful fallback**: Sử dụng cache khi server unreachable

```

.\agent.exe --skip-mtls --once --server http://test-server:8081Chạy agent như Windows service với audit định kỳ:

### Security Considerations

```bash

- **Bootstrap Token Security**: OTT tokens expire trong 1 giờ và chỉ sử dụng một lần

- **Certificate Storage**: Private keys được lưu với restricted permissions# Or run test data generation.\agent.exe --service --skip-mtls

- **Network Security**: Tất cả communications qua TLS 1.3

- **Certificate Rotation**: Automatic 24h rotation cho enhanced security.\generate_vtn_test_data.ps1```

- **Revocation**: Support certificate revocation cho compromised agents

```- Chạy liên tục với interval do server hardcode (1 giờ)

### 5. Custom Server Endpoint

- Tự động fetch policy mới nhất từ server

```bash

.\agent.exe --server https://your-server:8443/agent --once --skip-mtls## 📋 Agent Operation Modes- Gửi results lên server theo định kỳ

```

- Phù hợp cho production deployment

### Tham số Agent

### Local Audit (No Server Submission)

| Tham số | Mô tả | Ví dụ |

|---------|-------|-------|```powershell#### 4. Service Installation (Windows Service Deployment)

| `--local` | Fetch policy, run audit locally, no submit | `--local --html` |

| `--once` | Fetch policy, run once, submit results | `--once` |# Fetch policy và run audit locally, no submissionCài đặt và chạy agent như Windows service:

| `--service` | Run as Windows service (periodic) | `--service` |

| `--install` | Install as Windows service | `--install` |.\agent.exe --local --html --server https://gateway.company.com```bash

| `--uninstall` | Uninstall Windows service | `--uninstall` |

| `--html` | Create HTML report (with --local) | `--local --html` |```# Cài đặt service

| `--json` | Create JSON report (with --local) | `--local --json` |

| `--excel` | Create Excel report (with --local) | `--local --excel` |.\agent.exe --install

| `--skip-mtls` | Skip mTLS authentication (testing) | `--skip-mtls` |

| `--server URL` | Custom server endpoint | `--server https://server:8443/agent` |### Single Audit (Submit Results)

| `--bootstrap-token TOKEN` | Bootstrap OTT token for mTLS enrollment | `--bootstrap-token abc123` |

| `--check-cert` | Check current certificate status | `--check-cert` |```powershell# Khởi động service 

| `--renew-cert` | Force certificate renewal | `--renew-cert` |

| `--reset-cert` | Reset certificates and re-enroll | `--reset-cert` |# Fetch policy, run once, submit resultssc start VT-Agent



## ⚙️ Production Environment Configuration.\agent.exe --once --server https://gateway.company.com



### Required Environment Variables (env/.env)```# Kiểm tra status



```bashsc query VT-Agent

# =============================================================================

# VT-AUDIT PRODUCTION CONFIGURATION### Service Mode (Continuous Monitoring)

# =============================================================================

```powershell  # Gỡ cài đặt service

# Certificate Authority Configuration

STEPCA_PROVISIONER_PASSWORD=YourSecurePassword123!# Install và run as Windows service.\agent.exe --uninstall

STEPCA_PROVISIONER=bootstrap@vt-audit

.\agent.exe --install --server https://gateway.company.com```

# Database Configuration  

POSTGRES_DB=vtauditStart-Service VT-Agent

POSTGRES_USER=vtaudit

POSTGRES_PASSWORD=YourDBPassword456!```#### 5. Production Mode (Full mTLS Authentication)

POSTGRES_HOST=postgres

POSTGRES_PORT=5432```bash



# Keycloak Authentication### Certificate Enrollment# Production với mTLS certificates

KEYCLOAK_ADMIN=admin

KEYCLOAK_ADMIN_PASSWORD=YourKeycloakPassword789!```powershell.\agent.exe --once

KEYCLOAK_DB_PASSWORD=YourKeycloakDBPassword!

# Bootstrap với OTT token để get certificate

# Network Configuration

NGINX_HOST=gateway.your-domain.com.\agent.exe --bootstrap-token "your-ott-token" --server https://gateway.company.com# Hoặc production service mode

NGINX_SSL_CERT_PATH=/etc/nginx/certs/server.crt

NGINX_SSL_KEY_PATH=/etc/nginx/certs/server.key```.\agent.exe --service



# Security Settings```

JWT_SECRET=YourJWTSecretKey_MinLength32Characters!

ENCRYPTION_KEY=YourEncryptionKey_Exactly32Characters## 🔧 Configuration Management



# Agent Configuration#### 6. Custom Server Endpoint

DEFAULT_POLLING_INTERVAL=600

BOOTSTRAP_TOKEN_EXPIRY=3600### Agent Configuration (distribute/agent.conf)```bash

CERTIFICATE_VALIDITY_HOURS=24

```ini.\agent.exe --server https://your-server:8443/agent --once --skip-mtls

# Monitoring và Logging

LOG_LEVEL=info# VT-Agent Configuration File```

ENABLE_DEBUG=false

METRICS_ENABLED=trueserver_url = https://gateway.company.com

```

bootstrap_token = <obtain-from-admin>### Tham số Agent

## 🔧 Cấu hình

log_level = info

### Agent Configuration

polling_interval = 600| Tham số | Mô tả | Ví dụ |

- **Policy source**: Luôn fetch từ server (không có local policy files)

- **Policy cache**: `data/policy_cache.json` (tự động tạo)enable_html_reports = true|---------|-------|-------|

- **Log file**: `agent.log` (hoặc Program Files cho service)

- **Default server**: `https://127.0.0.1:8443/agent`certificate_path = %PROGRAMDATA%\VT-Agent\certs| `--local` | Fetch policy, run audit locally, no submit | `--local --html` |

- **Bootstrap token**: `123456` (mặc định)

- **Service interval**: 1 giờ (server hardcoded)```| `--once` | Fetch policy, run once, submit results | `--once` |



### Server Configuration| `--service` | Run as Windows service (periodic) | `--service` |



- Database: PostgreSQL với schema `audit`### Policy Management| `--install` | Install as Windows service | `--install` |

- Tables: `agents`, `runs`, `check_results`, `results_flat`

- mTLS bypass mode với header `X-Test-Mode: true`- **Centralized Policies**: All compliance rules managed from dashboard| `--uninstall` | Uninstall Windows service | `--uninstall` |



## 📊 Database Schema- **Version Control**: Policy versioning với rollback capabilities  | `--html` | Create HTML report (with --local) | `--local --html` |



```sql- **Rule Categories**: Security, compliance, configuration checks| `--json` | Create JSON report (with --local) | `--local --json` |

-- Bảng agents

CREATE TABLE audit.agents (- **Custom Rules**: Support cho organization-specific compliance requirements| `--excel` | Create Excel report (with --local) | `--local --excel` |

    id TEXT PRIMARY KEY,

    hostname TEXT,| `--skip-mtls` | Skip mTLS authentication (testing) | `--skip-mtls` |

    os TEXT,

    created_at TIMESTAMP DEFAULT NOW(),## 📊 Monitoring & Analytics| `--server URL` | Custom server endpoint | `--server https://server:8443/agent` |

    last_seen TIMESTAMP DEFAULT NOW()

);| `--bootstrap-token TOKEN` | Bootstrap OTT token | `--bootstrap-token 123456` |



-- Bảng runs### Dashboard Features

CREATE TABLE audit.runs (

    id TEXT PRIMARY KEY,- **Fleet Management**: Overview của all registered agents## 🔧 Cấu hình

    agent_id TEXT REFERENCES audit.agents(id),

    created_at TIMESTAMP DEFAULT NOW()- **Compliance Trends**: Historical compliance scoring và improvement tracking

);

- **Real-time Status**: Live agent connectivity và health monitoring### Agent Configuration

-- Bảng check_results

CREATE TABLE audit.check_results (- **Custom Reports**: Flexible reporting với multiple export formats- **Policy source**: Luôn fetch từ server (không có local policy files)

    id SERIAL PRIMARY KEY,

    run_id TEXT REFERENCES audit.runs(id),- **Policy cache**: `data/policy_cache.json` (tự động tạo)

    policy_id TEXT,

    rule_id TEXT,### Performance Metrics- **Log file**: `agent.log` (hoặc Program Files cho service)

    title TEXT,

    severity TEXT,- **Agent Health**: Last seen, version, connectivity status- **Default server**: `https://127.0.0.1:8443/agent`

    status TEXT,

    expected TEXT,- **Compliance Scoring**: Overall và per-rule compliance percentages  - **Bootstrap token**: `123456` (mặc định)

    reason TEXT,

    fix TEXT- **System Performance**: Database performance, API response times- **Service interval**: 1 giờ (server hardcoded)

);

- **Certificate Status**: Expiration monitoring và renewal tracking

-- View results_flat

CREATE VIEW audit.results_flat AS ### Server Configuration

SELECT ...

```## 🛠️ Maintenance & Operations- Database: PostgreSQL với schema `audit`



## 🔍 Troubleshooting- Tables: `agents`, `runs`, `check_results`, `results_flat`



### Agent Issues### Regular Maintenance Tasks- mTLS bypass mode với header `X-Test-Mode: true`



#### Agent không kết nối được server```bash



```bash# Database maintenance## 📊 Database Schema

# Kiểm tra server có chạy không

docker ps | findstr nginxdocker exec postgres psql -U vtaudit -d vtaudit -c "VACUUM ANALYZE;"



# Test connectivity```sql

curl -k https://127.0.0.1:8443/agent/health

```# Certificate monitoring-- Bảng agents



#### Authentication faileddocker exec stepca step certificate inspect /home/step/certs/intermediate_ca.crtCREATE TABLE audit.agents (



```bash    id TEXT PRIMARY KEY,

# Dùng skip-mtls mode để test

.\agent.exe --skip-mtls --once --debug# Log rotation    hostname TEXT,



# Kiểm tra logsdocker-compose logs --tail=1000 vt-server > server-logs-$(date +%Y%m%d).log    os TEXT,

docker logs vt-api-agent

``````    created_at TIMESTAMP DEFAULT NOW(),



#### Policy fetch failed    last_seen TIMESTAMP DEFAULT NOW()



```bash### Backup Procedures);

# Kiểm tra api-agent service

docker logs vt-api-agent```bash



# Test policy endpoint# Database backup-- Bảng runs

curl -k -H "X-Test-Mode: true" https://127.0.0.1:8443/agent/policies

```docker exec postgres pg_dump -U vtaudit vtaudit > backup-$(date +%Y%m%d).sqlCREATE TABLE audit.runs (



### Server Issues    id TEXT PRIMARY KEY,



#### Database connection failed# Certificate backup    agent_id TEXT REFERENCES audit.agents(id),



```bashcp -r env/certs/ backup/certs-$(date +%Y%m%d)/    created_at TIMESTAMP DEFAULT NOW()

# Kiểm tra PostgreSQL

docker logs postgres);



# Test database connection# Configuration backup

docker exec -it postgres psql -U postgres -d vtaudit

```cp env/.env backup/env-$(date +%Y%m%d).bak-- Bảng check_results



#### Nginx routing issues```CREATE TABLE audit.check_results (



```bash    id SERIAL PRIMARY KEY,

# Kiểm tra nginx config

docker exec vt-nginx nginx -t## 🔍 Troubleshooting    run_id TEXT REFERENCES audit.runs(id),



# Restart nginx    policy_id TEXT,

docker restart vt-nginx

```### Common Issues    rule_id TEXT,



#### Certificate issues    title TEXT,



```bash#### Agent Connection Problems    severity TEXT,

# Regenerate certificates

cd env```powershell    status TEXT,

./scripts/generate-mtls-assets.sh

./scripts/issue-nginx-cert.sh# Check network connectivity    expected TEXT,

docker restart vt-nginx

```Test-NetConnection gateway.company.com -Port 443    reason TEXT,



## 📝 Development    fix TEXT



### Build từ source# Verify certificate validity);



```bash.\agent.exe --test-connection

# Build agent

go build -o agent.exe ./agent/cmd/vt-agent-- View results_flat



# Build server# Check service logsCREATE VIEW audit.results_flat AS 

cd env

docker compose buildGet-EventLog -LogName Application -Source "VT-Agent" -Newest 10SELECT ...

```

``````

### Logs và Debugging



```bash

# Agent logs#### Server Issues## 🔍 Troubleshooting

tail -f agent.log

```bash

# Server logs

docker logs -f vt-api-agent# Check all services### Agent Issues

docker logs -f vt-api-backend

docker logs -f vt-nginxdocker-compose ps



# Database logs#### Agent không kết nối được server

docker logs -f postgres

```# Review server logs```bash



### Testing Flowdocker-compose logs vt-server# Kiểm tra server có chạy không



1. Chạy `.\agent.exe --local --html --skip-mtls` để test local auditdocker ps | findstr nginx

2. Chạy `.\agent.exe --once --skip-mtls` để test với server submission

3. Kiểm tra dashboard tại https://localhost:443# Database connectivity

4. Xem results trong PostgreSQL

5. Bootstrap mTLS: `.\agent.exe --bootstrap-token "token"`docker exec postgres psql -U vtaudit -d vtaudit -c "SELECT version();"# Test connectivity

6. Cài đặt production: `.\agent.exe --install` và `sc start VT-Agent`

```curl -k https://127.0.0.1:8443/agent/health

## 🔐 Security

```

- **Server-Controlled Policy**: Agent luôn fetch policy từ server, không có local files

- **mTLS Authentication**: Client certificates cho production mode với Step-CA#### Certificate Issues

- **Certificate Rotation**: Automatic 24h certificate renewal

- **Bypass Mode**: Test mode với header `X-Test-Mode: true` và `--skip-mtls````bash#### Authentication failed

- **OIDC Integration**: Keycloak authentication cho dashboard

- **TLS Encryption**: Tất cả communications đều encrypted# Regenerate certificates```bash

- **Centralized Management**: Tất cả policy và configuration từ server

cd env/scripts# Dùng skip-mtls mode để test

## 📖 API Endpoints

./generate-mtls-assets.sh.\agent.exe --skip-mtls --once --debug

### Agent API (port 8443)

docker-compose restart nginx stepca

- `GET /agent/policies` - Lấy policy hiện tại

- `POST /agent/results` - Gửi audit results```# Kiểm tra logs

- `POST /agent/bootstrap/ott` - Bootstrap với OTT token

- `POST /agent/enroll` - Enroll để lấy certificatedocker logs vt-api-agent

- `GET /agent/health` - Health check endpoint

## 📚 Additional Resources```

### Dashboard API (port 443)



- `GET /api/dashboard` - Dashboard data

- `GET /api/policy` - Policy management- **ARCHITECTURE.md**: Detailed system architecture và design patterns#### Policy fetch failed

- `POST /api/auth/login` - Authentication

- **API.md**: Complete API reference documentation  ```bash

## 🤝 Contributing

# Kiểm tra api-agent service

1. Fork repository

2. Tạo feature branch## 🤝 Supportdocker logs vt-api-agent

3. Commit changes

4. Push và tạo Pull Request



## 📚 Additional ResourcesFor technical support:# Test policy endpoint



- **ARCHITECTURE.md**: Detailed system architecture và API reference1. Check troubleshooting section abovecurl -k -H "X-Test-Mode: true" https://127.0.0.1:8443/agent/policies

- **env/.env.example**: Production environment template

- **scripts/**: Automation scripts cho certificate management2. Review service logs cho error details```



## 📄 License3. Verify network connectivity và certificates



MIT License - see LICENSE file for details4. Contact system administrators với log details### Server Issues



---



**Production Status**: ✅ Ready for enterprise deployment với comprehensive security, mTLS authentication, và monitoring capabilities.---#### Database connection failed

```bash

**Production Status**: ✅ Ready for enterprise deployment với comprehensive security và monitoring capabilities.# Kiểm tra PostgreSQL
docker logs postgres

# Test database connection
docker exec -it postgres psql -U postgres -d vtaudit
```

#### Nginx routing issues
```bash
# Kiểm tra nginx config
docker exec vt-nginx nginx -t

# Restart nginx
docker restart vt-nginx
```

#### Certificate issues
```bash
# Regenerate certificates
cd env
./scripts/generate-mtls-assets.sh
./scripts/issue-nginx-cert.sh
docker restart vt-nginx
```

## 📝 Development

### Build từ source
```bash
# Build agent
go build -o agent.exe ./agent/cmd/vt-agent

# Build server
cd env
docker compose build
```

### Logs và Debugging
```bash
# Agent logs
tail -f agent.log

# Server logs
docker logs -f vt-api-agent
docker logs -f vt-api-backend
docker logs -f vt-nginx

# Database logs
docker logs -f postgres
```

### Testing Flow
1. Chạy `.\agent.exe --local --html --skip-mtls` để test local audit
2. Chạy `.\agent.exe --once --skip-mtls` để test với server submission
3. Kiểm tra dashboard tại https://localhost:443
4. Xem results trong PostgreSQL
5. Cài đặt production: `.\agent.exe --install` và `sc start VT-Agent`

## 🔐 Security

- **Server-Controlled Policy**: Agent luôn fetch policy từ server, không có local files
- **mTLS Authentication**: Client certificates cho production mode
- **Bypass Mode**: Test mode với header `X-Test-Mode: true` và `--skip-mtls`
- **OIDC Integration**: Keycloak authentication cho dashboard
- **TLS Encryption**: Tất cả communications đều encrypted
- **Centralized Management**: Tất cả policy và configuration từ server

## 📖 API Endpoints

### Agent API (port 8443)
- `GET /agent/policies` - Lấy policy hiện tại
- `POST /agent/results` - Gửi audit results
- `POST /agent/bootstrap/ott` - Bootstrap với OTT token
- `POST /agent/enroll` - Enroll để lấy certificate

### Dashboard API (port 443)
- `GET /api/dashboard` - Dashboard data
- `GET /api/policy` - Policy management
- `POST /api/auth/login` - Authentication

## 🤝 Contributing

1. Fork repository
2. Tạo feature branch
3. Commit changes
4. Push và tạo Pull Request

## 📄 License

[License information here]
