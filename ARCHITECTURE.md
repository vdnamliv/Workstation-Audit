# VT-Audit System Architecture & API Reference

## 🏗️ System Architecture

### Zero-Config mTLS Enrollment Flow

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Windows       │───▶│ Enroll-Gateway   │───▶│    Step-CA      │
│   Agent         │    │ (Bootstrap API)  │    │ (Certificate    │
│                 │    │ :8742            │    │  Authority)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │ 1. Request OTT         │ 2. Generate CSR       │ 3. Sign Certificate
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Certificate     │◀───│ Certificate +    │◀───│ Signed Cert +   │
│ Stored Locally  │    │ Private Key      │    │ CA Chain        │
│ (data/certs/)   │    │ Response         │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Production Operation Flow

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Windows       │───▶│   Nginx Gateway  │───▶│   API-Agent     │
│   Agent         │    │   (mTLS Proxy)   │    │  (Policy API)   │ 
│  (Service Mode) │    │   :8443          │    │   :8080         │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │ 1. mTLS Request        │ 2. Certificate        │ 3. Policy/Results
         │                       │    Validation         │    Processing
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Policy Cached   │◀───│ X-Client-Verify  │───▶│   PostgreSQL    │
│ Audit Executed  │    │ SUCCESS Headers  │    │   Database      │
│ Results Sent    │    │ Forwarded        │    │   Storage       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Authentication Fallback Flow

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Agent         │───▶│ Policy Request   │───▶│ 401 Unauthorized│
│ (No mTLS Cert)  │    │ (No Auth)        │    │ Response        │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                                             │
         │ Auto Retry with X-Test-Mode                 │
         ▼                                             ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ X-Test-Mode:    │───▶│ Bypass mTLS      │───▶│ 200 OK Success  │
│ true Header     │    │ Authentication   │    │ Policy Received │
│ Added           │    │ Check            │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Design Principles

VT-Audit được thiết kế theo các nguyên tắc enterprise-grade:

- **🔒 Security-First**: Defense-in-depth với mTLS authentication, certificate management
- **📊 Centralized Management**: Single dashboard điều khiển toàn bộ fleet  
- **⚡ Performance**: Efficient polling, smart caching, batch operations
- **🛡️ Resilient**: Graceful degradation và offline operation
- **🔄 Zero-Touch**: Minimal manual intervention cho deployment

### Component Overview

```mermaid
graph TB
    subgraph "Production Network"
        Internet[Internet/Corporate Network]
    end
    
    subgraph "VT-Server Stack"
        Nginx[Nginx Gateway :443]
        Dashboard[Dashboard UI :8081]  
        AgentAPI[Agent API :8080]
        BootstrapAPI[Bootstrap API :8082]
        Keycloak[Keycloak OIDC :8080]
        PostgreSQL[PostgreSQL :5432]
        StepCA[Step-CA Certificate Authority]
    end
    
    subgraph "Windows Agent Fleet" 
        Agent1[Windows Agent 1<br/>Service Mode]
        Agent2[Windows Agent 2<br/>Service Mode]
        AgentN[Windows Agent N<br/>Service Mode]
    end
    
    Internet --> Nginx
    Nginx --> Dashboard
    Nginx --> AgentAPI
    Nginx --> BootstrapAPI
    Dashboard --> Keycloak
    AgentAPI --> PostgreSQL
    BootstrapAPI --> StepCA
    
    Agent1 -.->|HTTPS + mTLS| Nginx
    Agent2 -.->|HTTPS + mTLS| Nginx
    AgentN -.->|HTTPS + mTLS| Nginx
```

### VT-Agent Architecture

**Core Functions**:
```go
// Agent execution modes
type AgentMode interface {
    Execute() error
}

// LocalMode: Fetch policy, audit local, no submit
// OnceMode: Fetch policy, audit once, submit results  
// ServiceMode: Continuous periodic auditing
```

**Key Components**:
- **🔄 Policy Engine**: Fetch và cache compliance policies
- **🔍 Compliance Checker**: Modular checker system
- **📊 Result Formatter**: JSON, HTML, Excel output
- **🛡️ Certificate Manager**: mTLS certificate handling
- **🏥 Health Monitor**: Server connectivity tracking

**Collector Architecture**:
```go
type Collector interface {
    Collect(policy Policy) ([]Result, error)
}

// Implemented collectors
- RegistryCollector: Windows Registry checks
- FileSystemCollector: File/folder permissions
- ServiceCollector: Windows Service status  
- ProcessCollector: Running process analysis
- SecurityPolicyCollector: Local security policies
```

### VT-Server Architecture

**Multi-mode Backend**:
```bash
# Specialized server instances
./vt-server --mode=dashboard --port=8081  # Web UI & management
./vt-server --mode=agent --port=8080      # Agent communication  
./vt-server --mode=bootstrap --port=8082  # Certificate enrollment
```

**Service Components**:

#### Dashboard Service (`pkg/dashboard/`)
- **Authentication**: OIDC integration với Keycloak
- **Policy CRUD**: Compliance rule management
- **Fleet Management**: Agent status và control
- **Analytics**: Compliance reporting và trends
- **Static Serving**: Alpine.js SPA hosting

#### Agent API Service (`pkg/httpagent/`)  
- **Policy Distribution**: Versioned policy với caching headers
- **Result Ingestion**: Bulk compliance result collection
- **Health Endpoints**: Agent connectivity monitoring
- **Interval Control**: Dynamic polling interval management

#### Bootstrap Service (`pkg/stepca/`)
- **Certificate Enrollment**: Step-CA integration
- **OTT Token Validation**: One-time token verification
- **mTLS Setup**: Client certificate provisioning

### Data Layer Design

**PostgreSQL Schema**:
```sql
-- Agent fleet management
CREATE TABLE agents (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) UNIQUE NOT NULL,
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    version VARCHAR(50),
    os_version VARCHAR(100),
    status VARCHAR(50) DEFAULT 'active',
    certificate_fingerprint VARCHAR(128),
    group_name VARCHAR(100),
    location VARCHAR(100)
);

-- Compliance audit storage
CREATE TABLE audit_results (
    id SERIAL PRIMARY KEY,
    agent_id INTEGER REFERENCES agents(id),
    run_id UUID NOT NULL,
    policy_version INTEGER NOT NULL,
    rule_id VARCHAR(100) NOT NULL,
    title VARCHAR(500) NOT NULL,
    status VARCHAR(20) NOT NULL, -- PASS/FAIL/ERROR
    actual_value TEXT,
    expected_value TEXT,
    severity VARCHAR(20), -- LOW/MEDIUM/HIGH/CRITICAL
    category VARCHAR(50), -- SECURITY/COMPLIANCE/CONFIG
    timestamp TIMESTAMP DEFAULT NOW(),
    
    INDEX idx_agent_timestamp (agent_id, timestamp),
    INDEX idx_status_severity (status, severity)
);

-- Policy version control
CREATE TABLE policies (
    version INTEGER PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    content JSONB NOT NULL,
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW(),
    active BOOLEAN DEFAULT FALSE
);

-- Agent-specific configuration
CREATE TABLE agent_configs (
    agent_id INTEGER PRIMARY KEY REFERENCES agents(id),
    polling_interval INTEGER DEFAULT 600,
    enabled_rules JSONB,
    custom_settings JSONB,
    updated_at TIMESTAMP DEFAULT NOW()
);
```

**Performance Optimizations**:
- **Table Partitioning**: audit_results partitioned by month
- **Composite Indexing**: Optimized for common query patterns
- **Connection Pooling**: pgbouncer for connection management
- **Query Optimization**: Materialized views cho analytics

### Security Architecture

#### mTLS Certificate Flow
```mermaid
sequenceDiagram
    participant A as Agent
    participant N as Nginx  
    participant B as Bootstrap API
    participant S as Step-CA
    
    Note over A,S: Certificate Enrollment Process
    A->>N: POST /agent/bootstrap/ott + token
    N->>B: Forward enrollment request
    B->>S: Generate certificate pair
    S-->>B: Return client certificate
    B-->>N: Certificate response
    N-->>A: Client certificate + key
    
    Note over A,N: Subsequent API Calls  
    A->>N: API request + client cert
    N->>N: Validate certificate
    N->>AgentAPI: Forward authenticated request
```

#### Authentication Layers
```yaml
Dashboard Authentication:
  - Primary: Keycloak OIDC với JWT tokens
  - Session: HTTP-only cookies với CSRF protection
  - Authorization: Role-based access control

Agent Authentication:
  - Production: mTLS client certificates  
  - Development: Bearer token bypass mode
  - Certificate Lifecycle: 24-hour validity với auto-renewal
```

#### Network Security
```yaml
Nginx Configuration:
  - TLS 1.3 preferred
  - Strong cipher suites only
  - HSTS với preload
  - Rate limiting: 10 req/s API, 2 req/s bootstrap
  - Request size limits
  - Security headers (CSP, X-Frame-Options, etc.)
```

## 🔌 API Reference

### Agent API Endpoints

**Base URL**: `https://gateway.company.com/agent`

#### GET /agent/policies
Fetch current compliance policies for agent execution.

**Request:**
```http
GET /agent/policies?os=windows HTTP/1.1
Host: gateway.company.com
Authorization: Bearer test:test  # Development only
# Or mTLS certificate in production
```

**Response:**
```json
{
  "version": 2,
  "name": "Windows Baseline Security v2.0",
  "updated": "2025-10-31T10:00:00Z",
  "policies": [
    {
      "id": "WIN-SEC-001",
      "title": "Windows Firewall Status",
      "description": "Ensure Windows Firewall is enabled on all profiles",
      "category": "security", 
      "severity": "high",
      "enabled": true,
      "check": {
        "type": "registry",
        "path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        "value": "EnableFirewall",
        "expected": 1
      }
    },
    {
      "id": "WIN-UPD-001", 
      "title": "Windows Update Configuration",
      "description": "Verify Windows Update is configured for automatic updates",
      "category": "compliance",
      "severity": "medium",
      "enabled": true,
      "check": {
        "type": "service",
        "name": "wuauserv",
        "state": "running"
      }
    }
  ]
}
```

#### POST /agent/results
Submit compliance audit results to server.

**Request:**
```http
POST /agent/results HTTP/1.1
Host: gateway.company.com  
Content-Type: application/json
Authorization: Bearer test:test  # Development only

{
  "agent_id": "DESKTOP-ABC123",
  "hostname": "DESKTOP-ABC123",
  "run_id": "550e8400-e29b-41d4-a716-446655440000",
  "policy_version": 2,
  "timestamp": "2025-10-31T09:30:00Z",
  "results": [
    {
      "rule_id": "WIN-SEC-001",
      "title": "Windows Firewall Status", 
      "status": "PASS",
      "actual_value": "1",
      "expected_value": "1",
      "severity": "high",
      "category": "security"
    },
    {
      "rule_id": "WIN-UPD-001",
      "title": "Windows Update Configuration",
      "status": "FAIL", 
      "actual_value": "stopped",
      "expected_value": "running",
      "severity": "medium",
      "category": "compliance",
      "reason": "Windows Update service is not running"
    }
  ]
}
```

**Response:**
```json
{
  "status": "success",
  "processed": 2,
  "agent_id": "DESKTOP-ABC123",
  "run_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-10-31T09:30:15Z"
}
```

#### GET /agent/config
Get agent-specific configuration settings.

**Request:**
```http
GET /agent/config?agent_id=DESKTOP-ABC123 HTTP/1.1
```

**Response:**
```json
{
  "agent_id": "DESKTOP-ABC123",
  "polling_interval": 600,
  "enabled_rules": ["WIN-SEC-001", "WIN-UPD-001"],
  "custom_settings": {
    "max_retries": 3,
    "timeout": 30,
    "enable_html_reports": true
  },
  "updated": "2025-10-31T08:00:00Z"
}
```

#### POST /agent/bootstrap/ott
Bootstrap agent enrollment với one-time token.

**Request:**
```http
POST /agent/bootstrap/ott HTTP/1.1
Content-Type: application/json

{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "hostname": "DESKTOP-ABC123", 
  "csr": "-----BEGIN CERTIFICATE REQUEST-----..."
}
```

**Response:**
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----...",
  "private_key": "-----BEGIN PRIVATE KEY-----...",
  "ca_certificate": "-----BEGIN CERTIFICATE-----...",
  "validity": "24h",
  "renewal_endpoint": "/agent/renew"
}
```

### Dashboard API Endpoints  

**Base URL**: `https://gateway.company.com/api`

#### GET /api/agents
List registered agents với filtering options.

**Request:**
```http
GET /api/agents?status=active&group=production&limit=50 HTTP/1.1
Authorization: Bearer [oidc-jwt-token]
```

**Response:**
```json
{
  "agents": [
    {
      "id": 1,
      "hostname": "DESKTOP-ABC123",
      "first_seen": "2025-10-01T10:00:00Z",
      "last_seen": "2025-10-31T09:30:00Z",
      "version": "1.0.0", 
      "os_version": "Windows 11 Pro 22H2",
      "status": "active",
      "group_name": "production",
      "location": "office-hcm",
      "polling_interval": 600,
      "last_audit": "2025-10-31T09:25:00Z",
      "compliance_score": 95.8,
      "certificate_expires": "2025-11-01T09:30:00Z"
    }
  ],
  "total": 157,
  "pagination": {
    "limit": 50,
    "offset": 0,
    "has_more": true
  }
}
```

#### GET /api/compliance/results
Query compliance results với advanced filtering.

**Request:**
```http  
GET /api/compliance/results?hostname=DESKTOP-ABC123&status=FAIL&severity=high&from=2025-10-30&to=2025-10-31 HTTP/1.1
```

**Response:**
```json
{
  "results": [
    {
      "id": 12345,
      "agent_id": 1,
      "hostname": "DESKTOP-ABC123", 
      "run_id": "550e8400-e29b-41d4-a716-446655440000",
      "rule_id": "WIN-SEC-003",
      "title": "User Account Control Settings",
      "status": "FAIL",
      "actual_value": "disabled",
      "expected_value": "enabled", 
      "severity": "high",
      "category": "security",
      "timestamp": "2025-10-31T09:25:00Z",
      "reason": "UAC is disabled in registry"
    }
  ],
  "summary": {
    "total": 1247,
    "pass": 1198, 
    "fail": 45,
    "error": 4,
    "compliance_rate": 96.1
  }
}
```

#### PUT /api/policies
Update compliance policies.

**Request:**
```http
PUT /api/policies HTTP/1.1
Content-Type: application/json
Authorization: Bearer [oidc-jwt-token]

{
  "name": "Windows Baseline Security v2.1", 
  "description": "Enhanced security baseline with UAC enforcement",
  "policies": [
    {
      "id": "WIN-SEC-001",
      "title": "Windows Firewall Status",
      "enabled": true,
      "severity": "high",
      "check": {
        "type": "registry",
        "path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        "value": "EnableFirewall", 
        "expected": 1
      }
    }
  ]
}
```

**Response:**
```json
{
  "status": "success",
  "version": 3,
  "message": "Policy updated successfully",
  "created_at": "2025-10-31T10:00:00Z",
  "affected_agents": 157
}
```

### Error Handling

**Standard Error Format**:
```json
{
  "error": "authentication_required",
  "message": "Valid authentication credentials required",
  "code": "AUTH_001",
  "timestamp": "2025-10-31T10:00:00Z",
  "request_id": "req_123456789"
}
```

**Common HTTP Status Codes**:
- `200 OK`: Successful request
- `201 Created`: Resource created successfully  
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

### Rate Limiting

**Agent Endpoints**:
- Policy requests: 10/minute per agent
- Result submissions: 5/minute per agent
- Bootstrap requests: 2/minute per IP

**Dashboard Endpoints**:
- General API: 100/minute per user
- Bulk operations: 10/minute per user
- Analytics queries: 20/minute per user

---

**Documentation Version**: 2.0 - Updated for production deployment với comprehensive security implementation.