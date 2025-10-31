# VT-Audit - Enterprise Windows Compliance Platform# VT-Audit - Enterprise Windows Compliance Platform# VT-Audit - Enterprise Windows Compliance Platform# VT-Audit - Enterprise Windows Compliance Monitoring# VT-Audit - Enterprise Windows Compliance Platform



[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)

[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://docker.com)

[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://microsoft.com)[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)

[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://docker.com)

VT-Audit là hệ thống **enterprise-grade** giám sát tuân thủ baseline security cho Windows workstations với dashboard tập trung, zero-config mTLS authentication, và policy management tự động.

[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://microsoft.com)[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)

## ✨ Key Features

[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

- 🔒 **Zero-Config mTLS**: Automatic certificate enrollment với Step-CA

- 📊 **Centralized Dashboard**: Web-based policy management và compliance analytics[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://docker.com)

- 🚀 **Auto-deployment**: Agent tự cài đặt như Windows service

- ⚡ **Smart Caching**: Offline operation với intelligent policy cachingVT-Audit là một hệ thống **enterprise-grade** để giám sát tuân thủ baseline security cho Windows workstations. Hệ thống cung cấp dashboard tập trung, agent tự động với mTLS authentication, và analytics real-time.

- 🛡️ **Fallback Authentication**: X-Test-Mode cho development và testing

- 📈 **Scalable**: Support hàng trăm agents đồng thời[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://microsoft.com)[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)



## 🏗️ System Architecture## ✨ Key Features



```[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐

│   Windows       │───▶│   Nginx Gateway  │───▶│   API Server    │- 🎯 **Server-Controlled Scheduling**: Dashboard điều khiển polling intervals của tất cả agents

│   Agents        │    │   (mTLS Proxy)   │    │   + Database    │ 

│  (Service Mode) │    │   Port :8443     │    │   Port :8080    │- 🔄 **Real-time Policy Updates**: Central policy management với automatic distribution[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://docker.com)[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://docker.com)

└─────────────────┘    └──────────────────┘    └─────────────────┘

         │                       │                       │- 📊 **Multi-format Reporting**: JSON, HTML, Excel export với rich analytics

         │ mTLS Certificate      │ Certificate           │ Policy + Results

         │ Authentication        │ Validation            │ Processing- 🛡️ **Security-First**: Automatic mTLS authentication với bypass mode for testingVT-Audit là một hệ thống **enterprise-grade** để giám sát tuân thủ baseline security cho Windows workstations. Hệ thống cung cấp dashboard tập trung, agent tự động với mTLS authentication, và analytics real-time.

         ▼                       ▼                       ▼

┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐- 🚀 **Zero-Touch Deployment**: Agent tự cài đặt như Windows service

│ Step-CA Auto    │◀───│ Enroll Gateway   │───▶│   PostgreSQL    │

│ Enrollment      │    │ Port :8742       │    │   Database      │- 💾 **Intelligent Caching**: Offline operation với policy caching[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://microsoft.com)[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://microsoft.com)

│ (Zero-Config)   │    │ (Bootstrap)      │    │   Storage       │

└─────────────────┘    └──────────────────┘    └─────────────────┘- 📈 **Scalable Architecture**: Support hàng trăm agents simultaneous

```

## ✨ Key Features

## 📋 Prerequisites

## 🏗️ System Architecture

### Server Requirements

- **OS**: Linux (Ubuntu 20.04+ recommended) [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

- **Docker**: Docker Engine 20.10+ và Docker Compose v2

- **Memory**: 4GB RAM minimum, 8GB recommended```mermaid

- **Storage**: 20GB available disk space

- **Network**: Port 443, 8443, 8742 accessible từ agentsgraph TB- 🎯 **Server-Controlled Scheduling**: Dashboard điều khiển polling intervals của tất cả agents



### Agent Requirements      subgraph "VT-Server Environment"

- **OS**: Windows 10/11 (22H2+ recommended)

- **PowerShell**: Version 5.1+ (built-in)        Dashboard[Dashboard SPA]- 🔄 **Real-time Policy Updates**: Central policy management với automatic distribution

- **Network**: HTTPS outbound access đến server

- **Privileges**: Administrator rights cho service installation        Server[VT-Server Backend]



## 🚀 Quick Deployment        DB[(PostgreSQL)]- 📊 **Multi-format Reporting**: JSON, HTML, Excel export với rich analytics



### 1. Server Setup        Auth[Keycloak OIDC]



Clone repository và setup environment:        Proxy[Nginx Gateway]- 🛡️ **Security-First**: mTLS authentication với bypass mode for testingVT-Audit là hệ thống **enterprise-grade** giám sát tuân thủ baseline security cho Windows workstations với dashboard tập trung, agent tự động, và mTLS authentication.VT-Audit là một hệ thống **enterprise-grade** để giám sát tuân thủ baseline security cho Windows workstations. Hệ thống cung cấp dashboard tập trung, agent tự động, và analytics real-time.



```bash        StepCA[Step-CA Certificate Authority]

git clone https://github.com/vdnamliv/vt-audit.git

cd vt-audit        EnrollGW[Enroll Gateway]- 🚀 **Zero-Touch Deployment**: Agent tự cài đặt như Windows service



# Tạo environment configuration    end

cp env/.env.example env/.env

# Sửa env/.env với cấu hình của bạn:    - 💾 **Intelligent Caching**: Offline operation với policy caching

# - Database passwords

# - Domain names    subgraph "Agent Network"

# - OIDC settings

```        A1[Windows Agent 1]- 📈 **Scalable Architecture**: Support hàng trăm agents simultaneous



Start server stack:        A2[Windows Agent 2]



```bash        AN[Windows Agent N]## 🚀 Quick Start - Production Deployment## ✨ Key Features

cd env

docker compose up -d    end

```

    ## 🏗️ System Architecture

Verify deployment:

    Dashboard --> Server

```bash

# Check all services running    Server --> DB

docker compose ps

    Proxy --> Dashboard

# Test endpoints

curl -k https://localhost:443/health        # Dashboard    Proxy --> Auth```mermaid

curl -k https://localhost:8443/health       # Agent API  

curl -k https://localhost:8742/health       # Enrollment    EnrollGW --> StepCA

```

    A1 -.auto-enroll.-> EnrollGWgraph TB### Step 1: Server Environment Setup- 🎯 **Server-Controlled Scheduling**: Dashboard điều khiển polling intervals của tất cả agents

### 2. Agent Deployment

    A2 -.auto-enroll.-> EnrollGW

#### Quick Test (Development)

```powershell    AN -.auto-enroll.-> EnrollGW    subgraph "VT-Server Environment"

# Download agent binary

Invoke-WebRequest -Uri "https://your-server/agent.exe" -OutFile "agent.exe"    A1 -.mTLS.-> Proxy



# Test local audit (no server needed)    A2 -.mTLS.-> Proxy        Dashboard[Dashboard SPA]- 🔄 **Real-time Policy Updates**: Central policy management với automatic distribution

.\agent.exe --local --html

    AN -.mTLS.-> Proxy

# Test with server (bypass mTLS)  

.\agent.exe --server https://your-server:8443 --once --skip-mtls```        Server[VT-Server Backend]

```



#### Production Deployment

```powershell### Component Overview        DB[(PostgreSQL)]```bash- 📊 **Multi-format Reporting**: JSON, HTML, Excel export với rich analytics

# Run as Administrator

# Agent tự động enroll certificate và cài đặt service



# One-time enrollment và audit- **🌐 Dashboard**: Web UI với Alpine.js, real-time policy management        Auth[Keycloak OIDC]

.\agent.exe --server https://your-server:8443 --once

- **⚙️ VT-Server**: Go backend với REST API, multi-mode operation

# Install as Windows service

.\agent.exe --server https://your-server:8443 --install- **💽 PostgreSQL**: Centralized audit storage với advanced querying        Proxy[Nginx Gateway]# 1. Clone và setup environment- 🛡️ **Security-First**: mTLS authentication với bypass mode for testing

Start-Service VT-Agent

```- **🔐 Authentication**: Keycloak OIDC cho dashboard, mTLS cho agents



### 3. Access Dashboard- **🚪 Gateway**: Nginx reverse proxy với SSL termination và mTLS validation        StepCA[Step-CA Certificate Authority]



Mở browser tới: `https://your-server/`- **📜 Certificate Authority**: Step-CA cho automatic certificate enrollment



Default credentials (change immediately):- **🎫 Enroll Gateway**: Automatic certificate enrollment cho agents    endgit clone https://github.com/your-org/vt-audit.git- 🚀 **Zero-Touch Deployment**: Agent tự cài đặt như Windows service

- **Username**: `admin@vt-audit.local`  

- **Password**: `admin123`- **📱 Windows Agent**: Service mode với health checks và smart retry



## 🔧 Configuration    



### Server Configuration## 🚀 Quick Start



Main config trong `env/.env`:    subgraph "Agent Network"cd vt-audit- 💾 **Intelligent Caching**: Offline operation với policy caching



```bash### Prerequisites

# Database

POSTGRES_PASSWORD=YourSecurePassword123!        A1[Windows Agent 1]

POSTGRES_DB=vtaudit

POSTGRES_USER=audit- **Docker & Docker Compose** (for server environment)



# Authentication- **Go 1.21+** (for building agent)        A2[Windows Agent 2]- 📈 **Scalable Architecture**: Support hàng trăm agents simultaneous

OIDC_CLIENT_SECRET=your-keycloak-secret

ADMIN_KEY=your-admin-api-key- **Windows 10/11** (for agent deployment)



# Certificates- **PowerShell** (for automation scripts)        AN[Windows Agent N]

STEPCA_PASSWORD=your-step-ca-password



# Network

SERVER_DOMAIN=audit.company.com### Server Setup    end# 2. Tạo production environment config

```



### Agent Configuration

```bash    

Agent config file `agent.conf` (optional):

```ini# 1. Clone repository

[server]

url = https://audit.company.com:8443git clone https://github.com/your-org/vt-audit.git    Dashboard --> Servercp env/.env.example env/.env## 🏗️ System Architecture

polling_interval = 600

cd vt-audit

[security]  

mtls_enabled = true    Server --> DB

verify_server_cert = true

# 2. Start server environment

[logging]

level = infocd env    Proxy --> Dashboard# Edit env/.env với production values (xem bên dưới)

file_path = C:\ProgramData\VT-Agent\logs\agent.log

```docker compose up -d



## 📊 Usage Examples    Proxy --> Auth



### Agent Operations# 3. Access dashboard



```powershellopen https://localhost:8443    StepCA -.-> A1```mermaid

# Local audit with HTML report

.\agent.exe --local --html# Login: admin / admin123



# Single audit with server submission  ```    StepCA -.-> A2

.\agent.exe --server https://server:8443 --once



# Check certificate status

.\agent.exe --check-cert### Agent Deployment    StepCA -.-> AN# 3. Generate certificates và khởi động servicesgraph TB



# Service management

sc start VT-Agent

sc stop VT-Agent```bash    A1 -.mTLS.-> Proxy

sc query VT-Agent

```# 1. Build agent



### Dashboard Operationsgo build -o agent.exe ./agent/cmd/vt-agent    A2 -.mTLS.-> Proxycd env    subgraph "VT-Server Environment"



- **Policy Management**: Create/edit compliance rules

- **Fleet Overview**: Monitor all registered agents  

- **Compliance Reports**: View audit results và trends# 2. Install as Windows service với automatic mTLS    AN -.mTLS.-> Proxy

- **Agent Control**: Configure polling intervals

- **Analytics**: Compliance scoring và statisticssc.exe create VT-Agent binPath="C:\path\to\agent.exe --service" start=auto DisplayName="VT Compliance Agent"



## 📚 Documentationsc.exe start VT-Agent```./scripts/generate-mtls-assets.sh        Dashboard[Dashboard SPA]



- **[ARCHITECTURE.md](ARCHITECTURE.md)**: Detailed system design và API reference```

- **[env/README.md](env/README.md)**: Docker deployment guide

- **[rules/](rules/)**: Sample compliance policies

- **[scripts/](scripts/)**: Utility scripts và automation

### Quick Test

## 🛟 Support & Troubleshooting

### Component Overview./scripts/issue-nginx-cert.sh gateway.your-domain.com        Server[VT-Server Backend]

### Common Issues

```bash

**Agent không connect được server:**

```bash# Test agent locally (no mTLS)

# Check network connectivity  

curl -k https://server:8443/health.\agent.exe --once --skip-mtls --html



# Test with bypass mode- **🌐 Dashboard**: Web UI với Alpine.js, real-time policy managementdocker-compose up -d        DB[(PostgreSQL)]

.\agent.exe --server https://server:8443 --once --skip-mtls

```# Test agent với automatic mTLS enrollment



**Certificate enrollment fails:**.\agent.exe --local --json --server https://your-server:8443/agent- **⚙️ VT-Server**: Go backend với REST API, multi-mode operation

```bash  

# Check Step-CA logs```

docker logs stepca

- **💽 PostgreSQL**: Centralized audit storage với advanced querying        Auth[Keycloak OIDC]

# Manual certificate cleanup

Remove-Item -Recurse -Force data\certs\## 🤖 Agent Operation Modes

```

- **🔐 Authentication**: Keycloak OIDC cho dashboard, mTLS cho agents

**Service installation issues:**

```powershell### 1. Local Mode (Fetch Policy, Run Local, No Submit)

# Run as Administrator

# Check event logs- **🚪 Gateway**: Nginx reverse proxy với SSL termination và mTLS validation# 4. Verify deployment        Proxy[Nginx Gateway]

Get-EventLog -LogName Application -Source "VT-Agent" -Newest 10

```Fetch policy từ server, chạy audit local, không gửi results:



### Getting Help- **📜 Certificate Authority**: Step-CA cho automatic certificate enrollment



- 📧 **Email**: support@vt-audit.local```bash

- 📖 **Documentation**: [ARCHITECTURE.md](ARCHITECTURE.md)  

- 🐛 **Issues**: GitHub Issues.\agent.exe --local --html --skip-mtls- **📱 Windows Agent**: Service mode với health checks và smart retrydocker-compose ps    end

- 💬 **Community**: Internal collaboration channels

```

---



**VT-Audit** - Secure, scalable, zero-config Windows compliance monitoring cho enterprise environments.
- Kết nối server để lấy policy mới nhất

- Chạy audit trên máy local## 🚀 Quick Startcurl -k https://localhost:443/health    

- Tạo file HTML report để xem kết quả

- KHÔNG gửi results lên server



### 2. Once Mode (Fetch Policy, Run Once, Submit Results)### Prerequisites```    subgraph "Agent Network"



Fetch policy từ server, chạy audit, gửi results lên server:



```bash- **Docker & Docker Compose** (for server environment)        A1[Windows Agent 1]

.\agent.exe --once --skip-mtls

```- **Go 1.21+** (for building agent)



- Kết nối server để lấy policy mới nhất- **Windows 10/11** (for agent deployment)### Step 2: Agent Deployment (Windows)        A2[Windows Agent 2]

- Chạy audit một lần duy nhất

- Gửi kết quả audit lên server- **PowerShell** (for automation scripts)

- Thoát sau khi hoàn thành

        AN[Windows Agent N]

### 3. Service Mode (Continuous Periodic Audits)

### Server Setup

Chạy như Windows service với interval điều khiển từ server:

```powershell    end

```cmd

# Install Windows Service```bash

sc.exe create VT-Agent binPath="C:\Path\To\agent.exe --service" start=auto DisplayName="VT Compliance Agent"

sc.exe start VT-Agent# 1. Clone repository# 1. Build agent executable    



# Kiểm tra service statusgit clone https://github.com/your-org/vt-audit.git

sc.exe query VT-Agent

```cd vt-auditgo build -o agent.exe ./agent/cmd/vt-agent    Dashboard --> Server



**Service Features:**



- 🔍 **Health Check tự động**: Kiểm tra server connection, interval changes, policy version# 2. Start server environment    Server --> DB

- ⏱️ **Server-controlled interval**: Dashboard control polling frequency (5m, 10m, 1h, etc.)

- 📋 **Smart caching**: Chỉ fetch policy khi version thay đổicd env

- 🔄 **Dynamic updates**: Tự động update interval khi admin thay đổi từ dashboard

- 🛡️ **Graceful fallback**: Sử dụng cache khi server unreachabledocker compose up -d# 2. Production deployment với mTLS    Proxy --> Dashboard



### 4. Service Installation Commands



```bash# 3. Access dashboardcd distribute    Proxy --> Auth

# Cài đặt service

.\agent.exe --installopen https://localhost:8443



# Khởi động service # Login: admin / admin123.\Deploy-VTAgent.ps1 -Mode Production -ServerUrl "https://gateway.your-domain.com"    A1 -.-> Proxy

sc start VT-Agent

```

# Kiểm tra status

sc query VT-Agent    A2 -.-> Proxy



# Gỡ cài đặt service### Agent Deployment

.\agent.exe --uninstall

```# 3. Verify agent service    AN -.-> Proxy



## 🔐 Simplified mTLS Authentication```bash



### Automatic Certificate Enrollment (No Bootstrap Tokens Required)# 1. Build agentGet-Service VT-Agent```



Agent tự động enroll và nhận certificate từ enroll-gateway mà không cần pre-configured tokens:go build -o agent.exe ./agent/cmd/vt-agent



#### Simplified FlowGet-EventLog -LogName Application -Source "VT-Agent" -Newest 5



1. **Agent Request**: Agent gửi hostname tới `/api/enroll`# 2. Configure agent

2. **Auto-Generate OTT**: Enroll-gateway tự động tạo OTT từ Step-CA

3. **Certificate Issue**: Agent nhận certificate và lưu local# Edit distribute/agent.conf with your server IP```### Component Overview

4. **mTLS Ready**: Agent sử dụng certificate cho tất cả subsequent requests



```bash

# Agent tự động enroll khi cần certificate# 3. Install as Windows service- **🌐 Dashboard**: Web UI với Alpine.js, real-time policy management

.\agent.exe --once --server https://gateway.local:8443

sc.exe create VT-Agent binPath="C:\path\to\agent.exe --service --skip-mtls" start=auto DisplayName="VT Compliance Agent"

# Production service mode với auto-enrollment

.\agent.exe --service --server https://gateway.local:8443sc.exe start VT-Agent### Step 3: Access Dashboard- **⚙️ VT-Server**: Go backend với REST API, multi-mode operation



# Install service với automatic mTLS```

.\agent.exe --install --server https://gateway.local:8443

```- **💽 PostgreSQL**: Centralized audit storage với advanced querying



#### Enrollment API Flow### Quick Test



```json```- **🔐 Authentication**: Keycloak OIDC cho dashboard, mTLS/bypass cho agents

# Auto-generated enrollment request

POST /api/enroll```bash

{

  "subject": "hostname.domain.com",# Test agent locallyURL: https://gateway.your-domain.com- **🚪 Gateway**: Nginx reverse proxy với SSL termination

  "sans": ["hostname"]

}.\agent.exe --once --skip-mtls --html



# Auto-generated enrollment response  Login: admin / [from Keycloak setup]- **📱 Windows Agent**: Service mode với health checks và smart retry

{

  "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",# Test agent connectivity

  "expires_at": "2025-10-31T12:00:00Z",

  "stepca_url": "https://gateway.local:8443/step-ca".\agent.exe --local --json --server https://your-server:8443/agent```

}

``````



### Certificate Management## � Quick Start



#### Automatic Certificate Renewal## 🤖 Agent Operation Modes



Agent tự động renew certificate trước khi hết hạn:## ⚙️ Production Environment Configuration



- **Certificate TTL**: 24 giờ (configurable)### 1. Local Mode (Fetch Policy, Run Local, No Submit)

- **Renewal Window**: 1 giờ trước expiry

- **Fallback**: Re-enroll với enroll-gateway nếu renewal failed### Prerequisites



#### Certificate StorageFetch policy từ server, chạy audit local, không gửi results:



```bash### Required Environment Variables (env/.env)- **Docker & Docker Compose** (for server environment)

# Certificate locations (auto-created)

%PROGRAMDATA%\VT-Agent\certs\client.crt```bash

%PROGRAMDATA%\VT-Agent\certs\client.key

%PROGRAMDATA%\VT-Agent\certs\ca.crt.\agent.exe --local --html --skip-mtls- **Go 1.21+** (for building agent)

```

```

#### Certificate Validation

```bash- **Windows 10/11** (for agent deployment)

Server validates client certificates với các checks:

- Kết nối server để lấy policy mới nhất

- **Certificate Authority**: Signed by Step-CA intermediate

- **Subject**: Hostname match với agent identity- Chạy audit trên máy local# =============================================================================- **PowerShell** (for automation scripts)

- **Expiration**: Certificate còn valid

- **Revocation**: Check certificate không bị revoke- Tạo file HTML report để xem kết quả



### Manual Certificate Commands- KHÔNG gửi results lên server# VT-AUDIT PRODUCTION CONFIGURATION



```bash

# Kiểm tra certificate hiện tại

.\agent.exe --check-cert### 2. Once Mode (Fetch Policy, Run Once, Submit Results)# =============================================================================### Server Setup



# Force renewal certificate

.\agent.exe --renew-cert

Fetch policy từ server, chạy audit, gửi results lên server:

# Reset certificates và auto re-enroll

.\agent.exe --reset-cert

```

```bash# Certificate Authority Configuration```bash

### mTLS Configuration

.\agent.exe --once --skip-mtls

#### Server-side Configuration (nginx)

```STEPCA_PROVISIONER_PASSWORD=YourSecurePassword123!# 1. Clone repository

```nginx

# /env/conf/nginx/conf.d/20-agent-mtls-443.conf

server {

    listen 443 ssl;- Kết nối server để lấy policy mới nhấtSTEPCA_PROVISIONER_NAME=vt-audit-provisionergit clone https://github.com/your-org/vt-audit.git

    server_name gateway.local;

- Chạy audit một lần duy nhất

    # SSL Configuration

    ssl_certificate /certs/nginx/server.crt;- Gửi kết quả audit lên servercd vt-audit

    ssl_certificate_key /certs/nginx/server.key;

    - Thoát sau khi hoàn thành

    # mTLS Configuration

    ssl_client_certificate /certs/stepca/intermediate_ca.crt;# Database Configuration  

    ssl_verify_client on;

    ssl_verify_depth 2;### 3. Service Mode (Continuous Periodic Audits)



    # Agent API endpointsPOSTGRES_DB=vtaudit# 2. Start server environment

    location /agent {

        proxy_pass http://api-agent;Chạy như Windows service với interval điều khiển từ server:

        proxy_set_header X-SSL-Client-Cert $ssl_client_cert;

        proxy_set_header X-SSL-Client-S-DN $ssl_client_s_dn;POSTGRES_USER=vtauditcd env

        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;

    }**Manual Installation (Recommended):**



    # Enrollment gatewayPOSTGRES_PASSWORD=YourDBPassword456!docker compose up -d

    location /api/enroll {

        proxy_pass http://enroll-gateway;```cmd

    }

}# Chạy PowerShell as AdministratorPOSTGRES_HOST=postgres

```

sc.exe create VT-Agent binPath= "C:\Path\To\agent.exe --service --skip-mtls" start= auto DisplayName= "VT Compliance Agent"

#### Agent-side Configuration

sc.exe start VT-AgentPOSTGRES_PORT=5432# 3. Access dashboard

```ini

# distribute/agent.conf

[security]

mtls_enabled = true# Kiểm tra service statusopen https://localhost:8443

certificate_path = %PROGRAMDATA%\VT-Agent\certs\client.crt

private_key_path = %PROGRAMDATA%\VT-Agent\certs\client.keysc.exe query VT-Agent

ca_certificate_path = %PROGRAMDATA%\VT-Agent\certs\ca.crt

auto_enroll = true```# Keycloak Authentication# Login: admin / admin123



[enrollment]

enroll_gateway_url = https://gateway.local:8443/api/enroll

step_ca_url = https://gateway.local:8443/step-ca**Service Features:**KEYCLOAK_ADMIN=admin```

certificate_ttl = 24h

renewal_threshold = 1h

```

- 🔍 **Health Check tự động**: Kiểm tra server connection, interval changes, policy versionKEYCLOAK_ADMIN_PASSWORD=YourKeycloakPassword789!

### Testing mTLS Setup

- ⏱️ **Server-controlled interval**: Dashboard control polling frequency (5m, 10m, 1h, etc.)

#### 1. Test Automatic Enrollment

- 📋 **Smart caching**: Chỉ fetch policy khi version thay đổiKEYCLOAK_DB_PASSWORD=YourKeycloakDBPassword!### Agent Deployment

```bash

# Test enrollment process- 🔄 **Dynamic updates**: Tự động update interval khi admin thay đổi từ dashboard

.\agent.exe --once --server https://gateway.local:8443 --debug

- 🛡️ **Graceful fallback**: Sử dụng cache khi server unreachable

# Kiểm tra certificate được tạo

dir "%PROGRAMDATA%\VT-Agent\certs\"

```

### 4. Service Installation (Windows Service Deployment)# Network Configuration```bash

#### 2. Test mTLS Connection



```bash

# Test với automatic mTLSCài đặt và chạy agent như Windows service:NGINX_HOST=gateway.your-domain.com# 1. Build agent

.\agent.exe --once --debug



# Kiểm tra logs cho certificate validation

type "%PROGRAMDATA%\VT-Agent\logs\agent.log"```bashNGINX_SSL_CERT_PATH=/etc/nginx/certs/server.crtgo build -o agent.exe ./agent/cmd/vt-agent

```

# Cài đặt service

### Troubleshooting mTLS

.\agent.exe --installNGINX_SSL_KEY_PATH=/etc/nginx/certs/server.key

#### Common mTLS Issues



**Certificate Enrollment Failed:**

# Khởi động service # 2. Configure agent

```bash

# Test enroll-gateway connectivitysc start VT-Agent

curl -k https://gateway.local:8443/api/enroll -d '{"subject":"test"}'

# Security Settings# Edit distribute/agent.conf with your server IP

# Kiểm tra Step-CA connectivity

curl -k https://gateway.local:8443/step-ca/health# Kiểm tra status

```

sc query VT-AgentJWT_SECRET=YourJWTSecretKey_MinLength32Characters!

**mTLS Handshake Failed:**



```bash

# Test với bypass mode để isolate issue# Gỡ cài đặt serviceENCRYPTION_KEY=YourEncryptionKey_Exactly32Characters# 3. Install as Windows service

.\agent.exe --skip-mtls --once --debug

.\agent.exe --uninstall

# Kiểm tra nginx logs

docker logs vt-nginx | Select-String "SSL"```sc.exe create VT-Agent binPath="C:\path\to\agent.exe --service --skip-mtls" start=auto DisplayName="VT Compliance Agent"

```



**Certificate Expired:**

## 🔐 mTLS Authentication với Step-CA# Agent Configurationsc.exe start VT-Agent

```bash

# Auto re-enrollment

.\agent.exe --reset-cert

### Bootstrap Agent với CertificateDEFAULT_POLLING_INTERVAL=600```

# Manual cleanup

Remove-Item "%PROGRAMDATA%\VT-Agent\certs\*" -Force

```

Để sử dụng mTLS authentication trong production, agent cần được bootstrap với certificate từ Step-CA:BOOTSTRAP_TOKEN_EXPIRY=3600

### Security Considerations



- **No Pre-shared Secrets**: Không cần bootstrap tokens hoặc pre-shared keys

- **Automatic Enrollment**: Zero-configuration certificate enrollment#### Bước 1: Lấy Bootstrap TokenCERTIFICATE_VALIDITY_HOURS=24### Quick Test

- **Network Security**: Tất cả communications qua TLS 1.3

- **Certificate Rotation**: Automatic 24h rotation cho enhanced security

- **Revocation**: Support certificate revocation cho compromised agents

Từ dashboard hoặc admin API, tạo bootstrap token cho agent:

### Agent Parameters



| Tham số | Mô tả | Ví dụ |

|---------|-------|-------|```bash# Monitoring và Logging```bash

| `--local` | Fetch policy, run audit locally, no submit | `--local --html` |

| `--once` | Fetch policy, run once, submit results | `--once` |# Từ server hoặc admin interface

| `--service` | Run as Windows service (periodic) | `--service` |

| `--install` | Install as Windows service | `--install` |curl -X POST https://gateway.local:8443/api/enroll \LOG_LEVEL=info# Test agent locally

| `--uninstall` | Uninstall Windows service | `--uninstall` |

| `--html` | Create HTML report (with --local) | `--local --html` |  -H "Content-Type: application/json" \

| `--json` | Create JSON report (with --local) | `--local --json` |

| `--excel` | Create Excel report (with --local) | `--local --excel` |  -d '{"subject": "hostname.domain.com", "sans": ["hostname"]}'ENABLE_DEBUG=false.\agent.exe --once --skip-mtls --html

| `--skip-mtls` | Skip mTLS authentication (testing) | `--skip-mtls` |

| `--server URL` | Custom server endpoint | `--server https://server:8443/agent` |```

| `--check-cert` | Check current certificate status | `--check-cert` |

| `--renew-cert` | Force certificate renewal | `--renew-cert` |METRICS_ENABLED=true

| `--reset-cert` | Reset certificates và auto re-enroll | `--reset-cert` |

Response sẽ chứa OTT (One-Time Token):

## ⚙️ Production Environment Configuration

```# Test agent connectivity

### Required Environment Variables (env/.env)

```json

```bash

# ============================================================================={.\agent.exe --local --json --server https://your-server:8443/agent

# VT-AUDIT PRODUCTION CONFIGURATION

# =============================================================================  "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",



# Certificate Authority Configuration  "expires_at": "2025-10-31T12:00:00Z",## 🏗️ System Architecture Overview```

STEPCA_PROVISIONER_PASSWORD=YourSecurePassword123!

STEPCA_PROVISIONER=bootstrap@vt-audit  "issuer": "bootstrap@vt-audit",



# Database Configuration    "audience": "https://stepca:9000"

POSTGRES_DB=vtaudit

POSTGRES_USER=vtaudit}

POSTGRES_PASSWORD=YourDBPassword456!

POSTGRES_HOST=postgres``````## 📊 Dashboard Features

POSTGRES_PORT=5432



# Keycloak Authentication

KEYCLOAK_ADMIN=admin#### Bước 2: Bootstrap Agent với OTTProduction Network

KEYCLOAK_ADMIN_PASSWORD=YourKeycloakPassword789!

KEYCLOAK_DB_PASSWORD=YourKeycloakDBPassword!



# Network ConfigurationSử dụng OTT để enroll agent và nhận certificate:        │### Policy Management

NGINX_HOST=gateway.your-domain.com

NGINX_SSL_CERT_PATH=/etc/nginx/certs/server.crt

NGINX_SSL_KEY_PATH=/etc/nginx/certs/server.key

```bash        ▼- ⚙️ **Centralized Policies**: Manage Windows compliance rules từ web interface

# Security Settings

JWT_SECRET=YourJWTSecretKey_MinLength32Characters!# Bootstrap với OTT token

ENCRYPTION_KEY=YourEncryptionKey_Exactly32Characters

.\agent.exe --bootstrap-token "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..." --server https://gateway.local:8443┌─────────────────────────────────┐- 🕐 **Interval Control**: Set polling intervals per agent group (5min - 24h)

# Agent Configuration

DEFAULT_POLLING_INTERVAL=600

CERTIFICATE_VALIDITY_HOURS=24

# Sau khi bootstrap thành công, certificate sẽ được lưu tại:│     Nginx Gateway (443)         │ ← mTLS Certificate Validation- 📋 **Rule Templates**: Pre-built baseline templates cho different security levels

# Monitoring và Logging

LOG_LEVEL=info# %PROGRAMDATA%\VT-Agent\certs\client.crt

ENABLE_DEBUG=false

METRICS_ENABLED=true# %PROGRAMDATA%\VT-Agent\certs\client.key├─────────────────────────────────┤- 🔄 **Live Updates**: Policy changes propagate to agents automatically

```

```

## 🔧 Configuration

│  VT-Server Stack                │

### Agent Configuration

#### Bước 3: Chạy Agent với mTLS

- **Policy source**: Luôn fetch từ server (không có local policy files)

- **Policy cache**: `data/policy_cache.json` (tự động tạo)│  ├─ Dashboard UI                │### Results Analytics

- **Log file**: `agent.log` (hoặc Program Files cho service)

- **Default server**: `https://127.0.0.1:8443/agent`Sau khi có certificate, agent có thể chạy với full mTLS authentication:

- **Auto-enrollment**: Automatic certificate enrollment từ enroll-gateway

- **Service interval**: 1 giờ (server hardcoded)│  ├─ Agent API (8081)            │- 📈 **Real-time Dashboards**: Agent status và compliance metrics



### Server Configuration```bash



- Database: PostgreSQL với schema `audit`# Production mode với mTLS certificates│  ├─ Admin API (8080)            │- 🔍 **Advanced Filtering**: Search by hostname, time range, compliance status

- Tables: `agents`, `runs`, `check_results`, `results_flat`

- mTLS bypass mode với header `X-Test-Mode: true`.\agent.exe --once

- Enroll-gateway: Automatic certificate enrollment cho agents

│  └─ Bootstrap API (8082)        │- 📊 **Trend Analysis**: Historical compliance trends và improvement tracking

## 📊 Database Schema

# Hoặc production service mode

```sql

-- Bảng agents.\agent.exe --service├─────────────────────────────────┤- 📱 **Export Options**: JSON, HTML, Excel reports với custom formatting

CREATE TABLE audit.agents (

    id TEXT PRIMARY KEY,

    hostname TEXT,

    os TEXT,# Install service với mTLS│  ├─ PostgreSQL Database         │

    created_at TIMESTAMP DEFAULT NOW(),

    last_seen TIMESTAMP DEFAULT NOW().\agent.exe --install --server https://gateway.local:8443

);

```│  ├─ Keycloak OIDC              │### Agent Management

-- Bảng runs

CREATE TABLE audit.runs (

    id TEXT PRIMARY KEY,

    agent_id TEXT REFERENCES audit.agents(id),### Certificate Management│  └─ Step-CA Certificate Authority│- 🖥️ **Fleet Overview**: All connected agents với last-seen status

    created_at TIMESTAMP DEFAULT NOW()

);



-- Bảng check_results#### Automatic Certificate Renewal└─────────────────────────────────┘- 🔧 **Remote Control**: Start/stop audit cycles, update intervals

CREATE TABLE audit.check_results (

    id SERIAL PRIMARY KEY,

    run_id TEXT REFERENCES audit.runs(id),

    policy_id TEXT,Agent tự động renew certificate trước khi hết hạn:        ▲- 🏥 **Health Monitoring**: Agent connectivity, version tracking, error reporting

    rule_id TEXT,

    title TEXT,

    severity TEXT,

    status TEXT,- **Certificate TTL**: 24 giờ (configurable)        │ HTTPS + mTLS- 📍 **Group Management**: Organize agents by location, department, compliance level

    expected TEXT,

    reason TEXT,- **Renewal Window**: 1 giờ trước expiry

    fix TEXT

);- **Fallback**: Sử dụng bootstrap token để re-enroll nếu renewal failed        ▼```

```



## 🔍 Troubleshooting

#### Certificate Validation┌──────────────┐ ┌──────────────┐ ┌──────────────┐

### Agent Issues



#### Agent không kết nối được server

Server validates client certificates với các checks:│  Windows     │ │  Windows     │ │  Windows     │### Bước 4: Kiểm tra services

```bash

# Kiểm tra server có chạy không

docker ps | findstr nginx

- **Certificate Authority**: Signed by Step-CA intermediate│  Agent #1    │ │  Agent #2    │ │  Agent #N    │```bash

# Test connectivity

curl -k https://127.0.0.1:8443/agent/health- **Subject**: Hostname match với agent identity

```

- **Expiration**: Certificate còn valid│  (Service)   │ │  (Service)   │ │  (Service)   │# Kiểm tra tất cả containers đang chạy

#### Authentication failed

- **Revocation**: Check certificate không bị revoke

```bash

# Dùng skip-mtls mode để test└──────────────┘ └──────────────┘ └──────────────┘docker ps

.\agent.exe --skip-mtls --once --debug

#### Manual Certificate Management

# Kiểm tra logs

docker logs vt-api-agent```

```

```bash

#### Policy fetch failed

# Kiểm tra certificate hiện tại# Kiểm tra logs

```bash

# Kiểm tra api-agent service.\agent.exe --check-cert

docker logs vt-api-agent

## 📦 Component Detailsdocker logs vt-nginx

# Test policy endpoint

curl -k -H "X-Test-Mode: true" https://127.0.0.1:8443/agent/policies# Force renewal certificate

```

.\agent.exe --renew-certdocker logs vt-api-agent

### Server Issues



#### Database connection failed

# Reset certificates (xóa và bootstrap lại)### VT-Agent (Windows Service)docker logs vt-api-backend

```bash

# Kiểm tra PostgreSQL.\agent.exe --reset-cert --bootstrap-token "new-token"

docker logs postgres

```- **Compliance Monitoring**: Automated Windows baseline security checksdocker logs postgres

# Test database connection

docker exec -it postgres psql -U postgres -d vtaudit

```

### mTLS Configuration- **mTLS Authentication**: Certificate-based authentication với Step-CA```

#### Nginx routing issues



```bash

# Kiểm tra nginx config#### Server-side Configuration (nginx)- **Service Mode**: Runs as Windows service với configurable intervals

docker exec vt-nginx nginx -t



# Restart nginx

docker restart vt-nginx```nginx- **Multi-format Reports**: JSON, HTML, Excel export capabilities### Bước 5: Truy cập Dashboard

```

# /env/conf/nginx/conf.d/20-agent-mtls-443.conf

#### Certificate issues

server {- Mở browser: https://localhost:443

```bash

# Regenerate certificates    listen 443 ssl;

cd env

./scripts/generate-mtls-assets.sh    server_name gateway.local;### VT-Server (Docker Stack)- Login với Keycloak credentials (admin/admin)

./scripts/issue-nginx-cert.sh

docker restart vt-nginx

```

    # SSL Configuration- **Dashboard API**: Web interface cho policy management- Dashboard hiển thị policy editor và audit results

## 📝 Development

    ssl_certificate /certs/nginx/server.crt;

### Build từ source

    ssl_certificate_key /certs/nginx/server.key;- **Agent API**: Handles agent communication và result collection

```bash

# Build agent    

go build -o agent.exe ./agent/cmd/vt-agent

    # mTLS Configuration- **Certificate Management**: Integrated Step-CA cho automatic enrollment## 🤖 Sử dụng Agent

# Build server

cd env    ssl_client_certificate /certs/stepca/intermediate_ca.crt;

docker compose build

```    ssl_verify_client on;- **Data Storage**: PostgreSQL với optimized schema cho compliance data



### Logs và Debugging    ssl_verify_depth 2;



```bash### Build Agent

# Agent logs

tail -f agent.log    # Agent API endpoints



# Server logs    location /agent {## 🔐 Security Features```bash

docker logs -f vt-api-agent

docker logs -f vt-api-backend        proxy_pass http://api-agent;

docker logs -f vt-nginx

        proxy_set_header X-SSL-Client-Cert $ssl_client_cert;# Từ thư mục gốc

# Database logs

docker logs -f postgres        proxy_set_header X-SSL-Client-S-DN $ssl_client_s_dn;

```

        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;### Authentication & Authorizationgo build -o agent.exe ./agent/cmd/vt-agent

### Testing Flow

    }

1. Chạy `.\agent.exe --local --html --skip-mtls` để test local audit

2. Chạy `.\agent.exe --once --skip-mtls` để test với server submission}- **mTLS Certificates**: All production agents use client certificates```

3. Kiểm tra dashboard tại https://localhost:443

4. Xem results trong PostgreSQL```

5. Test auto-mTLS: `.\agent.exe --once` (no bootstrap token needed)

6. Cài đặt production: `.\agent.exe --install` và `sc start VT-Agent`- **OIDC Integration**: Keycloak authentication cho dashboard access



## 🔐 Security#### Agent-side Configuration



- **Server-Controlled Policy**: Agent luôn fetch policy từ server, không có local files- **Role-based Access**: Admin, operator, và viewer roles### Các mode chạy Agent

- **Automatic mTLS**: Zero-configuration certificate enrollment qua enroll-gateway

- **Certificate Rotation**: Automatic 24h certificate renewal```ini

- **Bypass Mode**: Test mode với header `X-Test-Mode: true` và `--skip-mtls`

- **OIDC Integration**: Keycloak authentication cho dashboard# distribute/agent.conf- **Certificate Rotation**: Automatic 24-hour certificate renewal

- **TLS Encryption**: Tất cả communications đều encrypted

- **Centralized Management**: Tất cả policy và configuration từ server[security]



## 📖 API Endpointsmtls_enabled = true#### 1. Local Mode (Fetch Policy, Run Local, No Submit)



### Agent API (port 8443)certificate_path = %PROGRAMDATA%\VT-Agent\certs\client.crt



- `GET /agent/policies` - Lấy policy hiện tạiprivate_key_path = %PROGRAMDATA%\VT-Agent\certs\client.key### Network SecurityFetch policy từ server, chạy audit local, không gửi results:

- `POST /agent/results` - Gửi audit results

- `GET /agent/health` - Health check endpointca_certificate_path = %PROGRAMDATA%\VT-Agent\certs\ca.crt



### Enrollment API (port 8443)verify_server_cert = true- **TLS 1.3**: Strong encryption cho all communications```bash



- `POST /api/enroll` - Automatic certificate enrollment (no pre-auth required)

- `GET /step-ca/*` - Step-CA proxy endpoints

[enrollment]- **Rate Limiting**: Protection against DoS attacks.\agent.exe --local --html --skip-mtls

### Dashboard API (port 443)

step_ca_url = https://gateway.local:8443/step-ca

- `GET /api/dashboard` - Dashboard data

- `GET /api/policy` - Policy managementbootstrap_audience = https://stepca:9000- **Security Headers**: HSTS, CSP, và other security headers```

- `POST /api/auth/login` - Authentication

certificate_ttl = 24h

## 🤝 Contributing

renewal_threshold = 1h- **Network Isolation**: Docker network segmentation- Kết nối server để lấy policy mới nhất

1. Fork repository

2. Tạo feature branch```

3. Commit changes

4. Push và tạo Pull Request- Chạy audit trên máy local



## 📚 Additional Resources### Testing mTLS Setup



- **ARCHITECTURE.md**: Detailed system architecture và API reference### Data Protection- Tạo file HTML report để xem kết quả

- **env/.env.example**: Production environment template

- **scripts/**: Automation scripts cho certificate management#### 1. Test Certificate Enrollment



## 📄 License- **Encrypted Storage**: Database encryption at rest- KHÔNG gửi results lên server



MIT License - see LICENSE file for details```bash



---# Test bootstrap process- **Secure Configuration**: No secrets in code, environment-based config



**Production Status**: ✅ Ready for enterprise deployment với simplified mTLS authentication và zero-configuration certificate enrollment..\agent.exe --bootstrap-token "test-token" --server https://gateway.local:8443 --debug

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
