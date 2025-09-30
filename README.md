# VT-Audit - Windows Compliance Monitoring Platform

VT-Audit là hệ thống giám sát tuân thủ Windows với dashboard tập trung, hệ thống đăng ký agent và lưu trữ kết quả audit trong PostgreSQL.

## 🏗️ Kiến trúc hệ thống

- **Dashboard SPA**: Giao diện web tại port 443 với authentication OIDC
- **Agent System**: mTLS certificate-based authentication với bypass mode để test
- **Database**: PostgreSQL với schema audit hoàn chỉnh
- **Services**: 
  - nginx (443/8443) - reverse proxy và routing
  - PostgreSQL - lưu trữ audit results
  - Step-CA - certificate authority
  - Keycloak - OIDC authentication
  - Multiple vt-server modes (api-backend:8081, api-agent:8080, enroll-gateway:8082)

## 📋 Yêu cầu hệ thống

- Docker & Docker Compose
- Go 1.19+ (để build agent)
- Windows (cho agent)
- PowerShell

## 🚀 Cài đặt và khởi chạy Server

### Bước 1: Clone repository
```bash
git clone <repository-url>
cd vt-audit
```

### Bước 2: Tạo certificates và secrets
```bash
cd env
# Tạo certificates cho nginx và Step-CA
./scripts/generate-mtls-assets.sh
./scripts/issue-nginx-cert.sh
```

### Bước 3: Khởi động services
```bash
cd env
docker compose up -d
```

### Bước 4: Kiểm tra services
```bash
# Kiểm tra tất cả containers đang chạy
docker ps

# Kiểm tra logs
docker logs vt-nginx
docker logs vt-api-agent
docker logs vt-api-backend
docker logs postgres
```

### Bước 5: Truy cập Dashboard
- Mở browser: https://localhost:443
- Login với Keycloak credentials (admin/admin)
- Dashboard hiển thị policy editor và audit results

## 🤖 Sử dụng Agent

### Build Agent
```bash
# Từ thư mục gốc
go build -o agent.exe ./agent/cmd/vt-agent
```

### Các mode chạy Agent

#### 1. Local Mode (Offline Testing)
Chạy audit offline và tạo file HTML report:
```bash
.\agent.exe --local --html
```
- Tạo file `audit_report.html` để xem kết quả
- Không cần kết nối server
- Sử dụng policy từ file `rules/windows.yml`

#### 2. Skip mTLS Mode (Testing với Server)
Chạy agent kết nối server nhưng bỏ qua mTLS authentication:
```bash
.\agent.exe --skip-mtls --once
```
- Kết nối đến server qua nginx bypass mode
- Sử dụng test credentials (Bearer test:test)
- Chạy 1 lần và thoát

#### 3. Skip mTLS Service Mode
Chạy agent như Windows service với bypass mode:
```bash
.\agent.exe --skip-mtls --service
```
- Chạy liên tục với interval mặc định
- Bypass mTLS authentication
- Gửi results lên server theo định kỳ

#### 4. Production Mode (Full mTLS)
Bootstrap và enrollment với mTLS certificates:
```bash
# Bootstrap để lấy OTT token
.\agent.exe --bootstrap 123456

# Enroll để lấy client certificate
.\agent.exe --enroll

# Chạy production mode
.\agent.exe
```

#### 5. Custom Server Endpoint
```bash
.\agent.exe --server https://your-server:8443/agent --skip-mtls --once
```

#### 6. Debug Mode
```bash
.\agent.exe --skip-mtls --once --debug
```

### Tham số Agent

| Tham số | Mô tả | Ví dụ |
|---------|-------|-------|
| `--local` | Chạy offline, không kết nối server | `--local` |
| `--html` | Tạo HTML report (chỉ với --local) | `--local --html` |
| `--skip-mtls` | Bỏ qua mTLS authentication | `--skip-mtls` |
| `--once` | Chạy 1 lần rồi thoát | `--once` |
| `--service` | Chạy như Windows service | `--service` |
| `--server URL` | Custom server endpoint | `--server https://server:8443/agent` |
| `--bootstrap TOKEN` | Bootstrap với OTT token | `--bootstrap 123456` |
| `--enroll` | Enroll để lấy client certificate | `--enroll` |
| `--debug` | Enable debug logging | `--debug` |

## 🔧 Cấu hình

### Agent Configuration
- Policy cache: `policy_cache.json`
- Log file: `agent.log`
- Default server: `https://127.0.0.1:8443/agent`
- Bootstrap token: `123456`

### Server Configuration
- Database: PostgreSQL với schema `audit`
- Tables: `agents`, `runs`, `check_results`, `results_flat`
- mTLS bypass mode với header `X-Test-Mode: true`

## 📊 Database Schema

```sql
-- Bảng agents
CREATE TABLE audit.agents (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    os TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW()
);

-- Bảng runs
CREATE TABLE audit.runs (
    id TEXT PRIMARY KEY,
    agent_id TEXT REFERENCES audit.agents(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Bảng check_results
CREATE TABLE audit.check_results (
    id SERIAL PRIMARY KEY,
    run_id TEXT REFERENCES audit.runs(id),
    policy_id TEXT,
    rule_id TEXT,
    title TEXT,
    severity TEXT,
    status TEXT,
    expected TEXT,
    reason TEXT,
    fix TEXT
);

-- View results_flat
CREATE VIEW audit.results_flat AS 
SELECT ...
```

## 🔍 Troubleshooting

### Agent Issues

#### Agent không kết nối được server
```bash
# Kiểm tra server có chạy không
docker ps | findstr nginx

# Test connectivity
curl -k https://127.0.0.1:8443/agent/health
```

#### Authentication failed
```bash
# Dùng skip-mtls mode để test
.\agent.exe --skip-mtls --once --debug

# Kiểm tra logs
docker logs vt-api-agent
```

#### Policy fetch failed
```bash
# Kiểm tra api-agent service
docker logs vt-api-agent

# Test policy endpoint
curl -k -H "X-Test-Mode: true" https://127.0.0.1:8443/agent/policies
```

### Server Issues

#### Database connection failed
```bash
# Kiểm tra PostgreSQL
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
1. Chạy `.\agent.exe --local --html` để test offline
2. Chạy `.\agent.exe --skip-mtls --once` để test với server
3. Kiểm tra dashboard tại https://localhost:443
4. Xem results trong PostgreSQL

## 🔐 Security

- **mTLS Authentication**: Client certificates cho production
- **Bypass Mode**: Test mode với header `X-Test-Mode: true`
- **OIDC Integration**: Keycloak authentication cho dashboard
- **TLS Encryption**: Tất cả communications đều encrypted

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
