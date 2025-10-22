# VT-Audit API Documentation

## 📋 Overview

VT-Audit cung cấp 2 main API categories:

1. **Agent API** (`/agent/*`) - Communication giữa Windows agents và server
2. **Dashboard API** (`/api/*`) - Web dashboard và management functions

## 🔑 Authentication

### Agent Authentication
```http
# mTLS Certificate (Production)
GET /agent/policies
Client-Certificate: [agent-cert.pem]

# Bearer Token (Development/Testing)
GET /agent/policies
Authorization: Bearer test:test
```

### Dashboard Authentication
```http
# OIDC Token (từ Keycloak)
GET /api/agents
Authorization: Bearer [oidc-jwt-token]
```

## 🤖 Agent API Endpoints

Base URL: `https://server:8443/agent`

### GET /agent/policies

Fetch compliance policies cho agent execution.

**Request:**
```http
GET /agent/policies?os=windows
Authorization: Bearer test:test
```

**Response:**
```json
{
  "version": 1,
  "policies": [
    {
      "id": "WIN-001",
      "title": "Windows Firewall Status",
      "description": "Ensure Windows Firewall is enabled",
      "category": "security",
      "severity": "high",
      "check": {
        "type": "service",
        "name": "MpsSvc",
        "state": "running"
      },
      "expected": true
    }
  ]
}
```

**Query Parameters:**
- `os` (required): Operating system type (`windows`)
- `version` (optional): Request specific policy version

**Error Responses:**
```json
// 404 - No policies found
{
  "error": "no policies available for os=windows"
}

// 401 - Authentication failed  
{
  "error": "authentication required"
}
```

### POST /agent/results

Submit audit results từ agent execution.

**Request:**
```http
POST /agent/results
Authorization: Bearer test:test
Content-Type: application/json

{
  "agent_id": "agent-DESKTOP-ABC123",
  "hostname": "DESKTOP-ABC123", 
  "policy_version": 1,
  "timestamp": "2025-10-08T09:30:00Z",
  "results": [
    {
      "rule_id": "WIN-001",
      "title": "Windows Firewall Status",
      "status": "PASS",
      "actual_value": "running",
      "expected_value": "running",
      "severity": "high",
      "category": "security"
    }
  ]
}
```

**Response:**
```json
{
  "status": "success",
  "processed": 24,
  "agent_id": "agent-DESKTOP-ABC123",
  "timestamp": "2025-10-08T09:30:15Z"
}
```

**Validation Rules:**
- `agent_id`: Must be unique identifier
- `hostname`: Windows hostname
- `policy_version`: Must match current policy version
- `status`: Must be one of `PASS`, `FAIL`, `ERROR`
- `severity`: Must be one of `low`, `medium`, `high`, `critical`

### GET /agent/health

Server health check và policy version verification.

**Request:**
```http
GET /agent/health
Authorization: Bearer test:test
```

**Response:**
```json
{
  "status": "healthy",
  "active_version": 1,
  "server_time": "2025-10-08T09:30:00Z",
  "uptime": "72h15m30s"
}
```

### GET /agent/interval

Get current polling interval setting for agent.

**Request:**
```http
GET /agent/interval?agent_id=agent-DESKTOP-ABC123
Authorization: Bearer test:test
```

**Response:**
```json
{
  "interval": 600,
  "unit": "seconds", 
  "updated": "2025-10-08T09:00:00Z"
}
```

**Default Intervals:**
- `300` seconds (5 minutes) - High frequency
- `600` seconds (10 minutes) - Default
- `1800` seconds (30 minutes) - Medium frequency  
- `3600` seconds (1 hour) - Low frequency

## 🖥️ Dashboard API Endpoints

Base URL: `https://server:8443/api`

### GET /api/agents

List all registered agents với status information.

**Request:**
```http
GET /api/agents?status=active&limit=50&offset=0
Authorization: Bearer [oidc-token]
```

**Response:**
```json
{
  "agents": [
    {
      "id": 1,
      "hostname": "DESKTOP-ABC123",
      "first_seen": "2025-10-01T10:00:00Z",
      "last_seen": "2025-10-08T09:30:00Z", 
      "version": "1.0.0",
      "os_version": "Windows 11 Pro",
      "status": "active",
      "group_name": "production",
      "location": "office-hcm",
      "polling_interval": 600,
      "last_audit": "2025-10-08T09:25:00Z",
      "compliance_score": 95.8
    }
  ],
  "total": 157,
  "limit": 50,
  "offset": 0
}
```

**Query Parameters:**
- `status`: Filter by agent status (`active`, `inactive`, `error`)
- `group`: Filter by group name
- `location`: Filter by location
- `limit`: Number of results (max 100)
- `offset`: Pagination offset

### GET /api/results

Query audit results với advanced filtering.

**Request:**
```http
GET /api/results?hostname=DESKTOP-ABC123&status=FAIL&from=2025-10-07&to=2025-10-08&limit=100
Authorization: Bearer [oidc-token]
```

**Response:**
```json
{
  "results": [
    {
      "id": 12345,
      "agent_id": 1,
      "hostname": "DESKTOP-ABC123",
      "policy_version": 1,
      "rule_id": "WIN-002", 
      "title": "Windows Update Status",
      "description": "Ensure Windows updates are current",
      "status": "FAIL",
      "actual_value": "updates pending",
      "expected_value": "up to date",
      "severity": "medium",
      "category": "security",
      "timestamp": "2025-10-08T09:25:00Z"
    }
  ],
  "total": 1247,
  "summary": {
    "pass": 1198,
    "fail": 45, 
    "error": 4,
    "compliance_rate": 96.1
  }
}
```

**Query Parameters:**
- `hostname`: Filter by specific agent hostname
- `status`: Filter by result status (`PASS`, `FAIL`, `ERROR`)
- `severity`: Filter by severity level
- `category`: Filter by compliance category
- `from`: Start date (ISO format)
- `to`: End date (ISO format)
- `rule_id`: Filter by specific rule
- `limit`: Number of results (max 1000)
- `offset`: Pagination offset

### GET /api/policies

Get current active policies với management info.

**Request:**
```http
GET /api/policies?version=latest
Authorization: Bearer [oidc-token]
```

**Response:**
```json
{
  "policies": {
    "version": 1,
    "name": "Windows Baseline v1.0",
    "description": "Standard Windows compliance baseline",
    "created_by": "admin",
    "created_at": "2025-10-01T10:00:00Z",
    "active": true,
    "rules_count": 24,
    "rules": [
      {
        "id": "WIN-001",
        "title": "Windows Firewall Status", 
        "description": "Ensure Windows Firewall is enabled",
        "category": "security",
        "severity": "high",
        "enabled": true,
        "check": {
          "type": "service",
          "name": "MpsSvc",
          "state": "running"
        }
      }
    ]
  }
}
```

### PUT /api/policies

Update hoặc create new policy version.

**Request:**
```http
PUT /api/policies
Authorization: Bearer [oidc-token]
Content-Type: application/json

{
  "name": "Windows Baseline v1.1",
  "description": "Updated baseline with new security checks",
  "rules": [
    {
      "id": "WIN-001",
      "title": "Windows Firewall Status",
      "description": "Ensure Windows Firewall is enabled",
      "category": "security", 
      "severity": "high",
      "enabled": true,
      "check": {
        "type": "service",
        "name": "MpsSvc",
        "state": "running"
      }
    }
  ]
}
```

**Response:**
```json
{
  "status": "success",
  "version": 2,
  "message": "Policy updated successfully",
  "created_at": "2025-10-08T10:00:00Z"
}
```

### PUT /api/agents/{id}/config

Update agent configuration (polling interval, enabled rules).

**Request:**
```http
PUT /api/agents/1/config
Authorization: Bearer [oidc-token]
Content-Type: application/json

{
  "polling_interval": 300,
  "enabled_rules": ["WIN-001", "WIN-002", "WIN-003"],
  "custom_settings": {
    "max_retries": 3,
    "timeout": 30
  }
}
```

**Response:**
```json
{
  "status": "success",
  "agent_id": 1,
  "updated_at": "2025-10-08T10:05:00Z"
}
```

### GET /api/dashboard/stats

Get dashboard statistics và metrics.

**Request:**
```http
GET /api/dashboard/stats?period=7d
Authorization: Bearer [oidc-token]
```

**Response:**
```json
{
  "period": "7d",
  "agents": {
    "total": 157,
    "active": 152, 
    "inactive": 5,
    "new_this_period": 3
  },
  "compliance": {
    "overall_rate": 96.1,
    "trend": "+2.3%",
    "critical_failures": 12,
    "improvement_areas": ["Windows Update", "User Account Control"]
  },
  "audit_activity": {
    "total_audits": 3245,
    "audits_today": 152,
    "avg_compliance_score": 96.1,
    "trend_data": [
      {"date": "2025-10-01", "score": 94.2},
      {"date": "2025-10-02", "score": 95.1},
      {"date": "2025-10-08", "score": 96.1}
    ]
  }
}
```

## 📊 Data Models

### Agent Model
```json
{
  "id": "number",
  "hostname": "string",
  "first_seen": "datetime",
  "last_seen": "datetime", 
  "version": "string",
  "os_version": "string",
  "status": "enum[active,inactive,error]",
  "group_name": "string",
  "location": "string",
  "polling_interval": "number",
  "last_audit": "datetime",
  "compliance_score": "number"
}
```

### Audit Result Model
```json
{
  "id": "number",
  "agent_id": "number",
  "hostname": "string",
  "policy_version": "number",
  "rule_id": "string",
  "title": "string",
  "description": "string", 
  "status": "enum[PASS,FAIL,ERROR]",
  "actual_value": "string",
  "expected_value": "string",
  "severity": "enum[low,medium,high,critical]",
  "category": "string",
  "timestamp": "datetime"
}
```

### Policy Model
```json
{
  "version": "number",
  "name": "string",
  "description": "string",
  "created_by": "string",
  "created_at": "datetime",
  "active": "boolean",
  "rules": [
    {
      "id": "string",
      "title": "string", 
      "description": "string",
      "category": "string",
      "severity": "enum[low,medium,high,critical]",
      "enabled": "boolean",
      "check": "object"
    }
  ]
}
```

## 🚨 Error Handling

### Standard Error Response
```json
{
  "error": "error message",
  "code": "ERROR_CODE",
  "details": "additional details if available",
  "timestamp": "2025-10-08T10:00:00Z"
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `AUTH_REQUIRED` | 401 | Authentication required |
| `AUTH_INVALID` | 401 | Invalid authentication credentials |
| `ACCESS_DENIED` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `RATE_LIMITED` | 429 | Too many requests |
| `SERVER_ERROR` | 500 | Internal server error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

### Retry Logic

**Agent Requests**: 
- Exponential backoff: 1s, 2s, 4s, 8s
- Max retries: 3
- Timeout: 30 seconds

**Dashboard Requests**:
- Immediate retry for 5xx errors
- Max retries: 1  
- Timeout: 10 seconds

## 🔧 Rate Limiting

### Agent Endpoints
- **Policy requests**: 10 requests/minute per agent
- **Result submissions**: 5 requests/minute per agent  
- **Health checks**: 60 requests/minute per agent

### Dashboard Endpoints
- **General API**: 100 requests/minute per user
- **Bulk operations**: 10 requests/minute per user
- **Statistics**: 20 requests/minute per user

## 📝 API Versioning

Current API version: `v1`

**Version Header**:
```http
API-Version: v1
```

**Deprecation Policy**:
- New versions announced 3 months in advance
- Old versions supported for 6 months after deprecation
- Breaking changes increment major version

## 🧪 Testing

### Development Testing
```bash
# Agent API testing
curl -H "Authorization: Bearer test:test" \
     https://localhost:8443/agent/policies?os=windows

# Dashboard API testing (requires OIDC token)
curl -H "Authorization: Bearer [oidc-token]" \
     https://localhost:8443/api/agents
```

### Integration Tests
```bash
# Run full API test suite
go test -tags=integration ./server/pkg/...

# Test specific endpoints
go test ./server/pkg/httpagent/...
go test ./server/pkg/dashboard/...
```

---

*API documentation nên được sync với code changes và version updates.*