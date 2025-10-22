# VT-Audit Developer Guide

## 📋 Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Development Setup](#development-setup)
5. [Core Components](#core-components)
6. [API Reference](#api-reference)
7. [Agent Development](#agent-development)
8. [Server Development](#server-development)
9. [Deployment Guide](#deployment-guide)
10. [Contributing](#contributing)
11. [Troubleshooting](#troubleshooting)

## 🎯 Overview

**VT-Audit** là một hệ thống kiểm tra tuân thủ baseline security cho máy trạm Windows trong môi trường enterprise. Hệ thống bao gồm:

- **VT-Server**: Backend API server với dashboard quản lý
- **VT-Agent**: Windows agent để thu thập dữ liệu compliance
- **Policy Management**: Hệ thống quản lý chính sách baseline
- **Result Analytics**: Dashboard phân tích kết quả audit

### Key Features
- ✅ **Server-controlled polling intervals**: Dashboard điều khiển frequency của agent
- ✅ **Real-time policy management**: Cập nhật policies từ central server
- ✅ **Multi-format reporting**: JSON, HTML, Excel export
- ✅ **Windows Service integration**: Agent chạy như Windows service
- ✅ **mTLS security với bypass mode**: Flexible authentication
- ✅ **Policy caching**: Smart offline operation capabilities

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   VT-Dashboard  │    │   VT-Server     │    │   PostgreSQL    │
│   (Frontend)    │◄──►│   (Backend)     │◄──►│   (Database)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         ▲                       ▲
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│   Nginx Proxy   │    │   Keycloak      │
│   (Gateway)     │    │   (Auth)        │
└─────────────────┘    └─────────────────┘
         ▲
         │ HTTPS/mTLS
         ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   VT-Agent      │    │   VT-Agent      │    │   VT-Agent      │
│   (Windows 1)   │    │   (Windows 2)   │    │   (Windows N)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Component Communication
- **Dashboard ↔ Server**: REST API với OIDC authentication
- **Agent ↔ Server**: HTTPS với mTLS/bypass authentication  
- **Server ↔ Database**: PostgreSQL connection pooling
- **Gateway**: Nginx reverse proxy với SSL termination

## 📁 Project Structure

```
vt-audit/
├── agent/                    # VT-Agent (Windows client)
│   ├── cmd/vt-agent/
│   │   └── main.go          # Agent main entry point
│   └── pkg/
│       ├── audit/           # Compliance checking engine
│       ├── collector/       # System data collection
│       ├── policy/          # Policy fetching & caching
│       ├── report/          # Report generation
│       └── svcwin/          # Windows service integration
├── server/                   # VT-Server (Backend)
│   ├── cmd/vt-server/
│   │   └── main.go          # Server main entry point
│   ├── pkg/
│   │   ├── dashboard/       # Web dashboard handlers
│   │   ├── httpagent/       # Agent API endpoints
│   │   ├── model/           # Data models
│   │   ├── policy/          # Policy management
│   │   ├── server/          # Core server logic
│   │   ├── stepca/          # Certificate authority
│   │   └── storage/         # Database abstraction
│   └── ui/                  # Frontend assets
├── env/                      # Docker development environment
│   ├── docker-compose.yml
│   ├── conf/                # Service configurations
│   └── docker/              # Custom Dockerfiles
├── rules/                    # Compliance rule definitions
│   └── windows.yml          # Windows baseline rules
├── distribute/               # Agent distribution package
└── scripts/                  # Deployment scripts
```

## 🔧 Development Setup

### Prerequisites
- **Go 1.21+** (for agent & server development)
- **Docker & Docker Compose** (for server environment)
- **Windows 10/11** (for agent testing)
- **PostgreSQL knowledge** (for database schema)
- **Git** (for version control)

### Quick Start

```bash
# 1. Clone repository
git clone https://github.com/your-org/vt-audit.git
cd vt-audit

# 2. Start development environment
cd env
docker compose up -d

# 3. Build agent
go build -o agent.exe ./agent/cmd/vt-agent

# 4. Build server
go build -o vt-server ./server/cmd/vt-server

# 5. Access dashboard
# https://localhost:8443 (admin/admin123)
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_USER` | Database username | `audit` |
| `POSTGRES_PASSWORD` | Database password | `audit123` |
| `BOOTSTRAP_TOKEN` | Agent authentication | `123456` |
| `SERVER_URL` | Agent server endpoint | `https://localhost:8443/agent` |

## 🧱 Core Components

### 1. VT-Agent (`agent/cmd/vt-agent/main.go`)

```go
// Main agent modes
func main() {
    // Flag parsing & configuration
    config := loadConfig()
    
    // Execution modes
    if *tLocal {
        runAuditLocal()     // Local audit with file output
    } else if *tOnce {
        runOnce()           // Single audit cycle with server submission
    } else if *tService {
        runServiceMode()    // Windows service mode with periodic cycles
    } else {
        runContinuous()     // Continuous polling mode
    }
}
```

**Key Functions:**
- `agentSession()`: Establishes TLS connection với server
- `performHealthCheck()`: Checks server connectivity & policy version
- `runOnce()`: Single audit execution
- `runServiceMode()`: Windows service integration
- `getOrFetchPolicy()`: Policy retrieval với caching

### 2. VT-Server (`server/cmd/vt-server/main.go`)

```go
// Server modes
func main() {
    mode := flag.String("mode", "", "Server mode: dashboard|agent|enroll")
    
    switch *mode {
    case "dashboard":
        startDashboardServer()  // Web UI & management API
    case "agent":
        startAgentServer()      // Agent communication endpoint
    case "enroll":
        startEnrollServer()     // Certificate enrollment
    }
}
```

**Key Functions:**
- `startDashboardServer()`: Web dashboard với OIDC auth
- `startAgentServer()`: Agent API endpoints
- `handleAgentResults()`: Process audit results từ agents
- `handlePolicyFetch()`: Serve policies to agents

### 3. Policy Engine (`agent/pkg/audit/audit.go`)

```go
// Compliance checking core
func Execute(policy PolicyBundle, osType string) ([]Result, error) {
    var results []Result
    
    for _, pol := range policy.Policies {
        result := evaluatePolicy(pol, osType)
        results = append(results, result)
    }
    
    return results, nil
}

// Individual policy evaluation
func evaluatePolicy(policy map[string]interface{}, osType string) Result {
    // Extract policy details
    title := policy["title"].(string)
    check := policy["check"].(map[string]interface{})
    
    // Execute check based on type
    switch check["type"] {
    case "registry":
        return checkRegistry(check)
    case "file":
        return checkFile(check)
    case "service":
        return checkService(check)
    case "process":
        return checkProcess(check)
    }
}
```

### 4. Dashboard API (`server/pkg/dashboard/handler.go`)

```go
// REST API endpoints
func RegisterHandlers(mux *http.ServeMux, storage storage.Storage) {
    // Authentication required endpoints
    mux.HandleFunc("GET /api/agents", handleListAgents)
    mux.HandleFunc("GET /api/results", handleGetResults)
    mux.HandleFunc("PUT /api/policy", handleUpdatePolicy)
    mux.HandleFunc("GET /api/health", handleHealthCheck)
    
    // Static file serving
    mux.HandleFunc("/", handleStaticFiles)
}

// Agent results endpoint
func handleGetResults(w http.ResponseWriter, r *http.Request) {
    hostname := r.URL.Query().Get("hostname")
    
    results, err := storage.GetResults(hostname, filters...)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    
    json.NewEncoder(w).Encode(results)
}
```

## 🚀 API Reference

### Agent Endpoints (`/agent/*`)

| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/agent/policies` | GET | Fetch compliance policies | Bearer/mTLS |
| `/agent/results` | POST | Submit audit results | Bearer/mTLS |
| `/agent/health` | GET | Server health check | Bearer/mTLS |
| `/agent/interval` | GET | Get polling interval | Bearer/mTLS |

### Dashboard API (`/api/*`)

| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/api/agents` | GET | List connected agents | OIDC |
| `/api/results` | GET | Query audit results | OIDC |
| `/api/policy` | GET/PUT | Policy management | OIDC |
| `/api/health` | GET | System health | OIDC |

### Example API Usage

```bash
# Fetch policies (agent)
curl -H "Authorization: Bearer test:test" \
     https://server:8443/agent/policies?os=windows

# Submit results (agent)  
curl -X POST -H "Authorization: Bearer test:test" \
     -d @results.json \
     https://server:8443/agent/results

# Get agent list (dashboard)
curl -H "Authorization: Bearer oidc-token" \
     https://server:8443/api/agents

# Update policy (dashboard)
curl -X PUT -H "Authorization: Bearer oidc-token" \
     -d @policy.json \
     https://server:8443/api/policy
```

## 🔧 Agent Development

### Building Agent

```bash
# Standard build
go build -o agent.exe ./agent/cmd/vt-agent

# Cross-compilation (Linux -> Windows)
GOOS=windows GOARCH=amd64 go build -o agent.exe ./agent/cmd/vt-agent

# With version info
go build -ldflags "-X main.version=1.0.0" -o agent.exe ./agent/cmd/vt-agent
```

### Agent Configuration

```ini
# agent.conf
SERVER_URL=https://server:8443/agent
BOOTSTRAP_TOKEN=your-token-here
LOG_LEVEL=info
LOG_FILE=agent.log
CERT_DIR=data/certs
```

### Adding New Compliance Checks

1. **Define rule in `rules/windows.yml`:**

```yaml
- title: "Check Windows Firewall Status"
  description: "Ensure Windows Firewall is enabled"
  check:
    type: "service"
    name: "MpsSvc"
    state: "running"
  expected: true
  severity: "high"
```

2. **Implement check in `agent/pkg/audit/audit.go`:**

```go
func checkService(check map[string]interface{}) Result {
    serviceName := check["name"].(string)
    expectedState := check["state"].(string)
    
    // Query Windows service status
    status := getServiceStatus(serviceName)
    
    return Result{
        Title:  check["title"].(string),
        Status: status == expectedState,
        Value:  status,
        Expected: expectedState,
    }
}
```

### Agent Service Mode

```go
// Windows service integration
type svcRunner struct {
    httpClient  *tlsclient.Client
    serverURL   string
    hostname    string  
    intervalSec int
    authHeader  string
}

func (s *svcRunner) RunOnce(ctx context.Context) error {
    // Health check
    serverAlive, newInterval, _, _ := performHealthCheck(
        s.httpClient, s.serverURL, s.authHeader, s.intervalSec)
    
    if !serverAlive {
        log.Printf("Server unreachable, skipping cycle")
        return nil
    }
    
    // Update interval if changed
    if newInterval != s.intervalSec {
        s.intervalSec = newInterval
    }
    
    // Perform audit
    return runOnce(s.httpClient, s.serverURL, s.hostname, s.authHeader)
}
```

## 🏢 Server Development

### Building Server

```bash
# Build all server modes
go build -o vt-server ./server/cmd/vt-server

# Run specific mode
./vt-server --mode=dashboard --port=8081
./vt-server --mode=agent --port=8080  
./vt-server --mode=enroll --port=9000
```

### Database Schema

```sql
-- Core tables
CREATE TABLE agents (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) UNIQUE,
    last_seen TIMESTAMP,
    version VARCHAR(50),
    status VARCHAR(50)
);

CREATE TABLE audit_results (
    id SERIAL PRIMARY KEY,
    agent_id INTEGER REFERENCES agents(id),
    policy_version INTEGER,
    title VARCHAR(500),
    status VARCHAR(20),
    value TEXT,
    expected TEXT,
    severity VARCHAR(20),
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE TABLE policies (
    id SERIAL PRIMARY KEY,
    version INTEGER UNIQUE,
    content JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    active BOOLEAN DEFAULT FALSE
);
```

### Adding New API Endpoints

```go
// 1. Define handler function
func handleNewEndpoint(w http.ResponseWriter, r *http.Request) {
    // Validate request
    if r.Method != "GET" {
        http.Error(w, "Method not allowed", 405)
        return
    }
    
    // Business logic
    data, err := processRequest(r)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    
    // Return JSON response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(data)
}

// 2. Register in handler.go
func RegisterHandlers(mux *http.ServeMux, storage storage.Storage) {
    mux.HandleFunc("GET /api/new-endpoint", handleNewEndpoint)
}
```

### Frontend Integration

Dashboard sử dụng **Alpine.js** cho reactive UI:

```html
<!-- Policy management example -->
<div x-data="policyManager()">
    <button @click="fetchPolicies()">Refresh Policies</button>
    
    <template x-for="policy in policies">
        <div class="policy-card">
            <h3 x-text="policy.title"></h3>
            <p x-text="policy.description"></p>
            <span :class="policy.status" x-text="policy.status"></span>
        </div>
    </template>
</div>

<script>
function policyManager() {
    return {
        policies: [],
        async fetchPolicies() {
            const response = await fetch('/api/policies');
            this.policies = await response.json();
        }
    }
}
</script>
```

## 🚀 Deployment Guide

### Production Deployment

```bash
# 1. Prepare environment
mkdir -p /opt/vt-audit
cd /opt/vt-audit

# 2. Copy docker-compose.yml và config files
cp env/docker-compose.yml .
cp -r env/conf .

# 3. Set environment variables
export POSTGRES_PASSWORD=secure-password
export BOOTSTRAP_TOKEN=secure-token

# 4. Deploy services
docker compose up -d

# 5. Build và distribute agent
go build -o agent.exe ./agent/cmd/vt-agent
# Copy to agent distribution points
```

### Agent Distribution

```bash
# Create distribution package
mkdir distribute
cp agent.exe distribute/
cp agent.conf distribute/
cp windows.yml distribute/
cp README.md distribute/

# Install on target machines
sc.exe create VT-Agent \
    binPath="C:\path\to\agent.exe --service --skip-mtls" \
    start=auto \
    DisplayName="VT Compliance Agent"

sc.exe start VT-Agent
```

### Monitoring & Maintenance

```bash
# Check service health
docker compose ps
docker compose logs api-backend

# Database maintenance
docker compose exec postgres psql -U audit -d audit

# Agent status
sc.exe query VT-Agent
Get-Content "C:\path\to\agent.log" -Tail 20
```

## 🤝 Contributing

### Code Style Guidelines

1. **Go Code**: Follow `gofmt` và `go vet` standards
2. **Error Handling**: Always handle errors explicitly
3. **Logging**: Use structured logging với contextual information
4. **Testing**: Write unit tests cho core business logic
5. **Documentation**: Document public functions và complex logic

### Development Workflow

```bash
# 1. Create feature branch
git checkout -b feature/new-compliance-check

# 2. Make changes
# ... code changes ...

# 3. Test locally
go test ./...
docker compose up -d  # Test integration

# 4. Commit với descriptive message
git commit -m "feat: add Windows Defender status check"

# 5. Create pull request
git push origin feature/new-compliance-check
```

### Testing

```bash
# Unit tests
go test ./agent/pkg/audit/...
go test ./server/pkg/storage/...

# Integration tests
cd env && docker compose up -d
go test -tags=integration ./...

# Agent testing
.\agent.exe --once --skip-mtls  # Manual test
.\agent.exe --local --html      # Local test
```

## 🛠️ Troubleshooting

### Common Issues

#### Agent Issues

**Problem**: Agent không connect được tới server
```bash
# Check network connectivity
Test-NetConnection -ComputerName server-ip -Port 8443

# Verify TLS certificate
openssl s_client -connect server-ip:8443

# Check agent logs
Get-Content agent.log -Tail 20
```

**Problem**: Service mode không hoạt động
```bash
# Check service status
sc.exe query VT-Agent

# Check service logs
# Agent logs to same directory as executable

# Reinstall service
sc.exe stop VT-Agent
sc.exe delete VT-Agent  
sc.exe create VT-Agent binPath="..." start=auto
```

#### Server Issues

**Problem**: Dashboard login failed
```bash
# Check container status
docker compose ps

# Check keycloak logs
docker compose logs keycloak

# Restart services
docker compose restart
```

**Problem**: Agent 401 authentication errors
```bash
# Check server logs
docker compose logs api-agent

# Verify bypass mode enabled
# Check nginx configuration

# Test direct API call
curl -H "Authorization: Bearer test:test" \
     https://server:8443/agent/health
```

### Debug Mode

```bash
# Enable debug logging in agent
export LOG_LEVEL=debug
.\agent.exe --once --skip-mtls

# Server debug mode
docker compose -f docker-compose.debug.yml up

# Database debugging
docker compose exec postgres psql -U audit -c "SELECT * FROM agents;"
```

### Performance Optimization

1. **Agent Performance**:
   - Adjust polling intervals based on network capacity
   - Enable policy caching để reduce server load
   - Use compression cho large result payloads

2. **Server Performance**:
   - Configure PostgreSQL connection pooling
   - Enable nginx caching cho static assets
   - Monitor memory usage của containers

3. **Network Optimization**:
   - Use mTLS only khi necessary (bypass mode cho testing)
   - Implement result batching for multiple agents
   - Configure appropriate timeout values

## 📞 Support

- **Issues**: GitHub Issues tracker
- **Documentation**: Wiki pages
- **Code Review**: Pull Request process
- **Security**: security@your-domain.com

---

**Happy Coding! 🚀**

*This documentation covers the core architecture and development practices for VT-Audit. Cần updates thường xuyên khi system evolves.*