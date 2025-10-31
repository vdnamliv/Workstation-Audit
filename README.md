# VT-Audit - Enterprise Windows Compliance Monitoring# VT-Audit - Enterprise Windows Compliance Platform



[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)

[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://docker.com)[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://docker.com)

[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://microsoft.com)[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://microsoft.com)

[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)



VT-Audit là hệ thống **enterprise-grade** giám sát tuân thủ baseline security cho Windows workstations với dashboard tập trung, agent tự động, và mTLS authentication.VT-Audit là một hệ thống **enterprise-grade** để giám sát tuân thủ baseline security cho Windows workstations. Hệ thống cung cấp dashboard tập trung, agent tự động, và analytics real-time.



## 🚀 Quick Start - Production Deployment## ✨ Key Features



### Step 1: Server Environment Setup- 🎯 **Server-Controlled Scheduling**: Dashboard điều khiển polling intervals của tất cả agents

- 🔄 **Real-time Policy Updates**: Central policy management với automatic distribution

```bash- 📊 **Multi-format Reporting**: JSON, HTML, Excel export với rich analytics

# 1. Clone và setup environment- 🛡️ **Security-First**: mTLS authentication với bypass mode for testing

git clone https://github.com/your-org/vt-audit.git- 🚀 **Zero-Touch Deployment**: Agent tự cài đặt như Windows service

cd vt-audit- 💾 **Intelligent Caching**: Offline operation với policy caching

- 📈 **Scalable Architecture**: Support hàng trăm agents simultaneous

# 2. Tạo production environment config

cp env/.env.example env/.env## 🏗️ System Architecture

# Edit env/.env với production values (xem bên dưới)

```mermaid

# 3. Generate certificates và khởi động servicesgraph TB

cd env    subgraph "VT-Server Environment"

./scripts/generate-mtls-assets.sh        Dashboard[Dashboard SPA]

./scripts/issue-nginx-cert.sh gateway.your-domain.com        Server[VT-Server Backend]

docker-compose up -d        DB[(PostgreSQL)]

        Auth[Keycloak OIDC]

# 4. Verify deployment        Proxy[Nginx Gateway]

docker-compose ps    end

curl -k https://localhost:443/health    

```    subgraph "Agent Network"

        A1[Windows Agent 1]

### Step 2: Agent Deployment (Windows)        A2[Windows Agent 2]

        AN[Windows Agent N]

```powershell    end

# 1. Build agent executable    

go build -o agent.exe ./agent/cmd/vt-agent    Dashboard --> Server

    Server --> DB

# 2. Production deployment với mTLS    Proxy --> Dashboard

cd distribute    Proxy --> Auth

.\Deploy-VTAgent.ps1 -Mode Production -ServerUrl "https://gateway.your-domain.com"    A1 -.-> Proxy

    A2 -.-> Proxy

# 3. Verify agent service    AN -.-> Proxy

Get-Service VT-Agent```

Get-EventLog -LogName Application -Source "VT-Agent" -Newest 5

```### Component Overview

- **🌐 Dashboard**: Web UI với Alpine.js, real-time policy management

### Step 3: Access Dashboard- **⚙️ VT-Server**: Go backend với REST API, multi-mode operation

- **💽 PostgreSQL**: Centralized audit storage với advanced querying

```- **🔐 Authentication**: Keycloak OIDC cho dashboard, mTLS/bypass cho agents

URL: https://gateway.your-domain.com- **🚪 Gateway**: Nginx reverse proxy với SSL termination

Login: admin / [from Keycloak setup]- **📱 Windows Agent**: Service mode với health checks và smart retry

```

## � Quick Start

## ⚙️ Production Environment Configuration

### Prerequisites

### Required Environment Variables (env/.env)- **Docker & Docker Compose** (for server environment)

- **Go 1.21+** (for building agent)

```bash- **Windows 10/11** (for agent deployment)

# =============================================================================- **PowerShell** (for automation scripts)

# VT-AUDIT PRODUCTION CONFIGURATION

# =============================================================================### Server Setup



# Certificate Authority Configuration```bash

STEPCA_PROVISIONER_PASSWORD=YourSecurePassword123!# 1. Clone repository

STEPCA_PROVISIONER_NAME=vt-audit-provisionergit clone https://github.com/your-org/vt-audit.git

cd vt-audit

# Database Configuration  

POSTGRES_DB=vtaudit# 2. Start server environment

POSTGRES_USER=vtauditcd env

POSTGRES_PASSWORD=YourDBPassword456!docker compose up -d

POSTGRES_HOST=postgres

POSTGRES_PORT=5432# 3. Access dashboard

open https://localhost:8443

# Keycloak Authentication# Login: admin / admin123

KEYCLOAK_ADMIN=admin```

KEYCLOAK_ADMIN_PASSWORD=YourKeycloakPassword789!

KEYCLOAK_DB_PASSWORD=YourKeycloakDBPassword!### Agent Deployment



# Network Configuration```bash

NGINX_HOST=gateway.your-domain.com# 1. Build agent

NGINX_SSL_CERT_PATH=/etc/nginx/certs/server.crtgo build -o agent.exe ./agent/cmd/vt-agent

NGINX_SSL_KEY_PATH=/etc/nginx/certs/server.key

# 2. Configure agent

# Security Settings# Edit distribute/agent.conf with your server IP

JWT_SECRET=YourJWTSecretKey_MinLength32Characters!

ENCRYPTION_KEY=YourEncryptionKey_Exactly32Characters# 3. Install as Windows service

sc.exe create VT-Agent binPath="C:\path\to\agent.exe --service --skip-mtls" start=auto DisplayName="VT Compliance Agent"

# Agent Configurationsc.exe start VT-Agent

DEFAULT_POLLING_INTERVAL=600```

BOOTSTRAP_TOKEN_EXPIRY=3600

CERTIFICATE_VALIDITY_HOURS=24### Quick Test



# Monitoring và Logging```bash

LOG_LEVEL=info# Test agent locally

ENABLE_DEBUG=false.\agent.exe --once --skip-mtls --html

METRICS_ENABLED=true

```# Test agent connectivity

.\agent.exe --local --json --server https://your-server:8443/agent

## 🏗️ System Architecture Overview```



```## 📊 Dashboard Features

Production Network

        │### Policy Management

        ▼- ⚙️ **Centralized Policies**: Manage Windows compliance rules từ web interface

┌─────────────────────────────────┐- 🕐 **Interval Control**: Set polling intervals per agent group (5min - 24h)

│     Nginx Gateway (443)         │ ← mTLS Certificate Validation- 📋 **Rule Templates**: Pre-built baseline templates cho different security levels

├─────────────────────────────────┤- 🔄 **Live Updates**: Policy changes propagate to agents automatically

│  VT-Server Stack                │

│  ├─ Dashboard UI                │### Results Analytics

│  ├─ Agent API (8081)            │- 📈 **Real-time Dashboards**: Agent status và compliance metrics

│  ├─ Admin API (8080)            │- 🔍 **Advanced Filtering**: Search by hostname, time range, compliance status

│  └─ Bootstrap API (8082)        │- 📊 **Trend Analysis**: Historical compliance trends và improvement tracking

├─────────────────────────────────┤- 📱 **Export Options**: JSON, HTML, Excel reports với custom formatting

│  ├─ PostgreSQL Database         │

│  ├─ Keycloak OIDC              │### Agent Management

│  └─ Step-CA Certificate Authority│- 🖥️ **Fleet Overview**: All connected agents với last-seen status

└─────────────────────────────────┘- 🔧 **Remote Control**: Start/stop audit cycles, update intervals

        ▲- 🏥 **Health Monitoring**: Agent connectivity, version tracking, error reporting

        │ HTTPS + mTLS- 📍 **Group Management**: Organize agents by location, department, compliance level

        ▼```

┌──────────────┐ ┌──────────────┐ ┌──────────────┐

│  Windows     │ │  Windows     │ │  Windows     │### Bước 4: Kiểm tra services

│  Agent #1    │ │  Agent #2    │ │  Agent #N    │```bash

│  (Service)   │ │  (Service)   │ │  (Service)   │# Kiểm tra tất cả containers đang chạy

└──────────────┘ └──────────────┘ └──────────────┘docker ps

```

# Kiểm tra logs

## 📦 Component Detailsdocker logs vt-nginx

docker logs vt-api-agent

### VT-Agent (Windows Service)docker logs vt-api-backend

- **Compliance Monitoring**: Automated Windows baseline security checksdocker logs postgres

- **mTLS Authentication**: Certificate-based authentication với Step-CA```

- **Service Mode**: Runs as Windows service với configurable intervals

- **Multi-format Reports**: JSON, HTML, Excel export capabilities### Bước 5: Truy cập Dashboard

- Mở browser: https://localhost:443

### VT-Server (Docker Stack)- Login với Keycloak credentials (admin/admin)

- **Dashboard API**: Web interface cho policy management- Dashboard hiển thị policy editor và audit results

- **Agent API**: Handles agent communication và result collection

- **Certificate Management**: Integrated Step-CA cho automatic enrollment## 🤖 Sử dụng Agent

- **Data Storage**: PostgreSQL với optimized schema cho compliance data

### Build Agent

## 🔐 Security Features```bash

# Từ thư mục gốc

### Authentication & Authorizationgo build -o agent.exe ./agent/cmd/vt-agent

- **mTLS Certificates**: All production agents use client certificates```

- **OIDC Integration**: Keycloak authentication cho dashboard access

- **Role-based Access**: Admin, operator, và viewer roles### Các mode chạy Agent

- **Certificate Rotation**: Automatic 24-hour certificate renewal

#### 1. Local Mode (Fetch Policy, Run Local, No Submit)

### Network SecurityFetch policy từ server, chạy audit local, không gửi results:

- **TLS 1.3**: Strong encryption cho all communications```bash

- **Rate Limiting**: Protection against DoS attacks.\agent.exe --local --html --skip-mtls

- **Security Headers**: HSTS, CSP, và other security headers```

- **Network Isolation**: Docker network segmentation- Kết nối server để lấy policy mới nhất

- Chạy audit trên máy local

### Data Protection- Tạo file HTML report để xem kết quả

- **Encrypted Storage**: Database encryption at rest- KHÔNG gửi results lên server

- **Secure Configuration**: No secrets in code, environment-based config

- **Audit Logging**: Complete audit trail cho all activities#### 2. Once Mode (Fetch Policy, Run Once, Submit Results)

- **Data Retention**: Configurable data lifecycle policiesFetch policy từ server, chạy audit, gửi results lên server:

```bash

## 🚀 Deployment Modes.\agent.exe --once --skip-mtls

```

### 1. Development Environment- Kết nối server để lấy policy mới nhất

```bash- Chạy audit một lần duy nhất

# Start with default test settings- Gửi kết quả audit lên server

cd env- Thoát sau khi hoàn thành

docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

#### 3. Service Mode (Continuous Periodic Audits)

# Test agent với bypass modeChạy như Windows service với interval điều khiển từ server:

.\agent.exe --once --skip-mtls --server http://localhost:8081

```**Manual Installation (Recommended):**

```cmd

### 2. Production Environment  # Chạy PowerShell as Administrator

```powershellsc.exe create VT-Agent binPath= "C:\Path\To\agent.exe --service --skip-mtls" start= auto DisplayName= "VT Compliance Agent"

# Deploy với full securitysc.exe start VT-Agent

.\Deploy-VTAgent.ps1 -Mode Production -ServerUrl "https://gateway.company.com"

# Kiểm tra service status

# Or manual production deploymentsc.exe query VT-Agent

.\agent.exe --install --server "https://gateway.company.com"```

Start-Service VT-Agent

```**Service Features:**

- 🔍 **Health Check tự động**: Kiểm tra server connection, interval changes, policy version

### 3. Testing Environment- ⏱️ **Server-controlled interval**: Dashboard control polling frequency (5m, 10m, 1h, etc.)

```powershell- 📋 **Smart caching**: Chỉ fetch policy khi version thay đổi

# Enable bypass cho testing environments- 🔄 **Dynamic updates**: Tự động update interval khi admin thay đổi từ dashboard

$env:VT_AGENT_FORCE_BYPASS="true"- 🛡️ **Graceful fallback**: Sử dụng cache khi server unreachable

.\agent.exe --skip-mtls --once --server http://test-server:8081Chạy agent như Windows service với audit định kỳ:

```bash

# Or run test data generation.\agent.exe --service --skip-mtls

.\generate_vtn_test_data.ps1```

```- Chạy liên tục với interval do server hardcode (1 giờ)

- Tự động fetch policy mới nhất từ server

## 📋 Agent Operation Modes- Gửi results lên server theo định kỳ

- Phù hợp cho production deployment

### Local Audit (No Server Submission)

```powershell#### 4. Service Installation (Windows Service Deployment)

# Fetch policy và run audit locally, no submissionCài đặt và chạy agent như Windows service:

.\agent.exe --local --html --server https://gateway.company.com```bash

```# Cài đặt service

.\agent.exe --install

### Single Audit (Submit Results)

```powershell# Khởi động service 

# Fetch policy, run once, submit resultssc start VT-Agent

.\agent.exe --once --server https://gateway.company.com

```# Kiểm tra status

sc query VT-Agent

### Service Mode (Continuous Monitoring)

```powershell  # Gỡ cài đặt service

# Install và run as Windows service.\agent.exe --uninstall

.\agent.exe --install --server https://gateway.company.com```

Start-Service VT-Agent

```#### 5. Production Mode (Full mTLS Authentication)

```bash

### Certificate Enrollment# Production với mTLS certificates

```powershell.\agent.exe --once

# Bootstrap với OTT token để get certificate

.\agent.exe --bootstrap-token "your-ott-token" --server https://gateway.company.com# Hoặc production service mode

```.\agent.exe --service

```

## 🔧 Configuration Management

#### 6. Custom Server Endpoint

### Agent Configuration (distribute/agent.conf)```bash

```ini.\agent.exe --server https://your-server:8443/agent --once --skip-mtls

# VT-Agent Configuration File```

server_url = https://gateway.company.com

bootstrap_token = <obtain-from-admin>### Tham số Agent

log_level = info

polling_interval = 600| Tham số | Mô tả | Ví dụ |

enable_html_reports = true|---------|-------|-------|

certificate_path = %PROGRAMDATA%\VT-Agent\certs| `--local` | Fetch policy, run audit locally, no submit | `--local --html` |

```| `--once` | Fetch policy, run once, submit results | `--once` |

| `--service` | Run as Windows service (periodic) | `--service` |

### Policy Management| `--install` | Install as Windows service | `--install` |

- **Centralized Policies**: All compliance rules managed from dashboard| `--uninstall` | Uninstall Windows service | `--uninstall` |

- **Version Control**: Policy versioning với rollback capabilities  | `--html` | Create HTML report (with --local) | `--local --html` |

- **Rule Categories**: Security, compliance, configuration checks| `--json` | Create JSON report (with --local) | `--local --json` |

- **Custom Rules**: Support cho organization-specific compliance requirements| `--excel` | Create Excel report (with --local) | `--local --excel` |

| `--skip-mtls` | Skip mTLS authentication (testing) | `--skip-mtls` |

## 📊 Monitoring & Analytics| `--server URL` | Custom server endpoint | `--server https://server:8443/agent` |

| `--bootstrap-token TOKEN` | Bootstrap OTT token | `--bootstrap-token 123456` |

### Dashboard Features

- **Fleet Management**: Overview của all registered agents## 🔧 Cấu hình

- **Compliance Trends**: Historical compliance scoring và improvement tracking

- **Real-time Status**: Live agent connectivity và health monitoring### Agent Configuration

- **Custom Reports**: Flexible reporting với multiple export formats- **Policy source**: Luôn fetch từ server (không có local policy files)

- **Policy cache**: `data/policy_cache.json` (tự động tạo)

### Performance Metrics- **Log file**: `agent.log` (hoặc Program Files cho service)

- **Agent Health**: Last seen, version, connectivity status- **Default server**: `https://127.0.0.1:8443/agent`

- **Compliance Scoring**: Overall và per-rule compliance percentages  - **Bootstrap token**: `123456` (mặc định)

- **System Performance**: Database performance, API response times- **Service interval**: 1 giờ (server hardcoded)

- **Certificate Status**: Expiration monitoring và renewal tracking

### Server Configuration

## 🛠️ Maintenance & Operations- Database: PostgreSQL với schema `audit`

- Tables: `agents`, `runs`, `check_results`, `results_flat`

### Regular Maintenance Tasks- mTLS bypass mode với header `X-Test-Mode: true`

```bash

# Database maintenance## 📊 Database Schema

docker exec postgres psql -U vtaudit -d vtaudit -c "VACUUM ANALYZE;"

```sql

# Certificate monitoring-- Bảng agents

docker exec stepca step certificate inspect /home/step/certs/intermediate_ca.crtCREATE TABLE audit.agents (

    id TEXT PRIMARY KEY,

# Log rotation    hostname TEXT,

docker-compose logs --tail=1000 vt-server > server-logs-$(date +%Y%m%d).log    os TEXT,

```    created_at TIMESTAMP DEFAULT NOW(),

    last_seen TIMESTAMP DEFAULT NOW()

### Backup Procedures);

```bash

# Database backup-- Bảng runs

docker exec postgres pg_dump -U vtaudit vtaudit > backup-$(date +%Y%m%d).sqlCREATE TABLE audit.runs (

    id TEXT PRIMARY KEY,

# Certificate backup    agent_id TEXT REFERENCES audit.agents(id),

cp -r env/certs/ backup/certs-$(date +%Y%m%d)/    created_at TIMESTAMP DEFAULT NOW()

);

# Configuration backup

cp env/.env backup/env-$(date +%Y%m%d).bak-- Bảng check_results

```CREATE TABLE audit.check_results (

    id SERIAL PRIMARY KEY,

## 🔍 Troubleshooting    run_id TEXT REFERENCES audit.runs(id),

    policy_id TEXT,

### Common Issues    rule_id TEXT,

    title TEXT,

#### Agent Connection Problems    severity TEXT,

```powershell    status TEXT,

# Check network connectivity    expected TEXT,

Test-NetConnection gateway.company.com -Port 443    reason TEXT,

    fix TEXT

# Verify certificate validity);

.\agent.exe --test-connection

-- View results_flat

# Check service logsCREATE VIEW audit.results_flat AS 

Get-EventLog -LogName Application -Source "VT-Agent" -Newest 10SELECT ...

``````



#### Server Issues## 🔍 Troubleshooting

```bash

# Check all services### Agent Issues

docker-compose ps

#### Agent không kết nối được server

# Review server logs```bash

docker-compose logs vt-server# Kiểm tra server có chạy không

docker ps | findstr nginx

# Database connectivity

docker exec postgres psql -U vtaudit -d vtaudit -c "SELECT version();"# Test connectivity

```curl -k https://127.0.0.1:8443/agent/health

```

#### Certificate Issues

```bash#### Authentication failed

# Regenerate certificates```bash

cd env/scripts# Dùng skip-mtls mode để test

./generate-mtls-assets.sh.\agent.exe --skip-mtls --once --debug

docker-compose restart nginx stepca

```# Kiểm tra logs

docker logs vt-api-agent

## 📚 Additional Resources```



- **ARCHITECTURE.md**: Detailed system architecture và design patterns#### Policy fetch failed

- **API.md**: Complete API reference documentation  ```bash

# Kiểm tra api-agent service

## 🤝 Supportdocker logs vt-api-agent



For technical support:# Test policy endpoint

1. Check troubleshooting section abovecurl -k -H "X-Test-Mode: true" https://127.0.0.1:8443/agent/policies

2. Review service logs cho error details```

3. Verify network connectivity và certificates

4. Contact system administrators với log details### Server Issues



---#### Database connection failed

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
