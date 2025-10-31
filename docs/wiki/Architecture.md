# Architecture

Detailed system architecture và technical design của VT-Audit platform.

## 🏗️ System Overview

VT-Audit là enterprise-grade compliance monitoring system với zero-config mTLS authentication, centralized policy management, và scalable agent deployment.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            VT-Audit Enterprise Platform                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
│  │    Dashboard    │◀──▶│   API Gateway   │◀──▶│   Agent Fleet   │        │
│  │   (Web UI)      │    │     (Nginx)     │    │   (Windows)     │        │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘        │
│           │                       │                       │                │
│           ▼                       ▼                       ▼                │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
│  │   Authentication│    │   mTLS Proxy    │    │  Certificate    │        │
│  │   (Keycloak)    │    │   Validation    │    │  Management     │        │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘        │
│           │                       │                       │                │
│           └───────────────────────┼───────────────────────┘                │
│                                   ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                        Core Services                                │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │  │
│  │  │ VT-Server   │ │ Step-CA     │ │ PostgreSQL  │ │ Enroll      │  │  │
│  │  │ Backend     │ │ Authority   │ │ Database    │ │ Gateway     │  │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 🔧 Component Architecture

### Frontend Layer

#### Dashboard (Alpine.js SPA)
```javascript
// Dashboard architecture
┌─────────────────────────────────────┐
│           Dashboard SPA             │
├─────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────────┐ │
│ │   Policy    │ │    Agent        │ │
│ │ Management  │ │   Monitoring    │ │
│ └─────────────┘ └─────────────────┘ │
│ ┌─────────────┐ ┌─────────────────┐ │
│ │ Compliance  │ │   Reporting     │ │
│ │ Analytics   │ │   Dashboard     │ │
│ └─────────────┘ └─────────────────┘ │
├─────────────────────────────────────┤
│        Alpine.js + Tailwind CSS    │
└─────────────────────────────────────┘
```

**Features:**
- Real-time policy editing với syntax highlighting
- Live agent status monitoring
- Interactive compliance dashboards
- Multi-format report generation

### API Gateway Layer

#### Nginx Reverse Proxy
```nginx
# Architecture flow
┌─────────────────────────────────────────┐
│              Nginx Gateway               │
├─────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Dashboard   │  │    mTLS Proxy       │ │
│  │ Routes      │  │   Validation        │ │
│  │ :443        │  │    :8443            │ │
│  └─────────────┘  └─────────────────────┘ │
│  ┌─────────────────────────────────────┐   │
│  │         SSL Termination             │   │
│  │      Certificate Validation         │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

**Configuration:**
```nginx
# /env/conf/nginx/nginx.conf
upstream api-backend {
    server vt-server-backend:8080;
}

upstream api-agent {
    server vt-server-agent:8081;
}

upstream enroll-gateway {
    server vt-server-enroll:8082;
}

server {
    listen 443 ssl http2;
    server_name gateway.local;
    
    # Dashboard routes
    location / {
        root /usr/share/nginx/html;
        try_files $uri $uri/ /index.html;
    }
    
    # API routes
    location /api/ {
        proxy_pass http://api-backend;
    }
}

server {
    listen 8443 ssl http2;
    
    # mTLS configuration
    ssl_client_certificate /certs/stepca/intermediate_ca.crt;
    ssl_verify_client on;
    
    # Agent API
    location /agent {
        proxy_pass http://api-agent;
        proxy_set_header X-SSL-Client-Cert $ssl_client_cert;
    }
    
    # Enrollment gateway
    location /api/enroll {
        proxy_pass http://enroll-gateway;
    }
}
```

### Backend Services

#### VT-Server Backend Architecture
```go
// Go service architecture
┌─────────────────────────────────────────────────────────────┐
│                    VT-Server Backend                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Dashboard   │  │   Agent     │  │     Enrollment      │  │
│  │ Handler     │  │  Handler    │  │     Gateway         │  │
│  │ :8080       │  │   :8081     │  │      :8082          │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Business Logic Layer                       │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐  │ │
│  │  │   Policy    │ │  Audit      │ │   Certificate   │  │ │
│  │  │ Management  │ │ Processing  │ │   Management    │  │ │
│  │  └─────────────┘ └─────────────┘ └─────────────────┘  │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                Data Access Layer                        │ │
│  │              PostgreSQL Driver                          │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Package Structure:**
```
server/
├── cmd/vt-server/
│   └── main.go                 # Entry point
├── pkg/
│   ├── dashboard/
│   │   ├── auth.go            # OIDC authentication
│   │   └── handler.go         # Dashboard API handlers
│   ├── httpagent/
│   │   └── handler.go         # Agent API handlers
│   ├── model/
│   │   └── types.go           # Data structures
│   ├── policy/
│   │   └── policy.go          # Policy management
│   ├── server/
│   │   └── run.go             # Server orchestration
│   ├── stepca/
│   │   ├── enroll_gateway.go  # Certificate enrollment
│   │   ├── provisioner.go     # Step-CA integration
│   │   └── server.go          # Certificate authority
│   └── storage/
│       ├── storage.go         # Storage interface
│       └── postgres/
│           └── postgres.go    # PostgreSQL implementation
└── ui/                        # Frontend assets
```

### Certificate Authority

#### Step-CA Integration
```
┌─────────────────────────────────────────────────────────────┐
│                     Step-CA Authority                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐    ┌─────────────────────────────┐ │
│  │    Root CA          │───▶│      Intermediate CA        │ │
│  │   (Offline)         │    │       (Online)              │ │
│  └─────────────────────┘    └─────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                JWK Provisioner                          │ │
│  │       "bootstrap@vt-audit"                              │ │
│  │    Audience: https://stepca:9000/1.0/sign              │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Certificate Management                     │ │
│  │  • Automatic enrollment                                │ │
│  │  • 24-hour certificate lifetime                        │ │
│  │  • Automatic renewal                                   │ │
│  │  • Revocation support                                  │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Data Layer

#### PostgreSQL Schema
```sql
-- Database architecture
┌─────────────────────────────────────────────────────────────┐
│                   PostgreSQL Database                       │
├─────────────────────────────────────────────────────────────┤
│                        audit schema                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   agents    │  │    runs     │  │   check_results     │  │
│  │             │  │             │  │                     │  │
│  │ • id (PK)   │  │ • id (PK)   │  │ • id (PK)           │  │
│  │ • hostname  │  │ • agent_id  │  │ • run_id (FK)       │  │
│  │ • os        │  │ • created_at│  │ • policy_id         │  │
│  │ • created_at│  │             │  │ • rule_id           │  │
│  │ • last_seen │  │             │  │ • status            │  │
│  └─────────────┘  └─────────────┘  │ • severity          │  │
│                                    │ • title             │  │
│                                    │ • expected          │  │
│                                    │ • reason            │  │
│                                    │ • fix               │  │
│                                    └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                  results_flat view                      │ │
│  │           (Denormalized for analytics)                  │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘

-- Table relationships
CREATE TABLE audit.agents (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    os TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW()
);

CREATE TABLE audit.runs (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES audit.agents(id),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE audit.check_results (
    id SERIAL PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES audit.runs(id),
    policy_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    expected TEXT,
    reason TEXT,
    fix TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_agents_hostname ON audit.agents(hostname);
CREATE INDEX idx_agents_last_seen ON audit.agents(last_seen);
CREATE INDEX idx_runs_agent_id ON audit.runs(agent_id);
CREATE INDEX idx_runs_created_at ON audit.runs(created_at);
CREATE INDEX idx_check_results_run_id ON audit.check_results(run_id);
CREATE INDEX idx_check_results_status ON audit.check_results(status);
CREATE INDEX idx_check_results_severity ON audit.check_results(severity);
```

## 🔄 Data Flow Architecture

### Agent Registration & Enrollment Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Windows   │    │   Enroll    │    │   Step-CA   │    │ PostgreSQL  │
│   Agent     │    │   Gateway   │    │ Authority   │    │ Database    │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │                  │
       │ 1. POST /api/enroll                 │                  │
       │ {"subject":"hostname"}              │                  │
       ├─────────────────▶│                  │                  │
       │                  │ 2. Generate OTT  │                  │
       │                  ├─────────────────▶│                  │
       │                  │ 3. Return OTT    │                  │
       │                  │◀─────────────────┤                  │
       │ 4. Return token  │                  │                  │
       │◀─────────────────┤                  │                  │
       │                  │                  │                  │
       │ 5. Certificate Request               │                  │
       │ (using OTT token)                   │                  │
       ├────────────────────────────────────▶│                  │
       │ 6. Issue Certificate                │                  │
       │◀────────────────────────────────────┤                  │
       │                  │                  │                  │
       │ 7. Register Agent                   │                  │
       │ (with client cert)                  │                  │
       ├─────────────────────────────────────────────────────────▶│
       │ 8. Agent registered                 │                  │
       │◀─────────────────────────────────────────────────────────┤
```

### Policy & Audit Execution Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Windows   │    │    Nginx    │    │ VT-Server   │    │ PostgreSQL  │
│   Agent     │    │   Gateway   │    │ Backend     │    │ Database    │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │                  │
       │ 1. GET /agent/policies               │                  │
       │ (mTLS authenticated)                 │                  │
       ├─────────────────▶├─────────────────▶│                  │
       │                  │ 2. Fetch latest  │                  │
       │                  │    policies      │                  │
       │                  │                  ├─────────────────▶│
       │                  │ 3. Return policy │                  │
       │                  │                  │◀─────────────────┤
       │ 4. Policy YAML   │                  │                  │
       │◀─────────────────┤◀─────────────────┤                  │
       │                  │                  │                  │
       │ 5. Execute Audit │                  │                  │
       │    Locally       │                  │                  │
       │ ┌──────────────┐ │                  │                  │
       │ │ Registry     │ │                  │                  │
       │ │ Files        │ │                  │                  │
       │ │ Services     │ │                  │                  │
       │ │ Security     │ │                  │                  │
       │ └──────────────┘ │                  │                  │
       │                  │                  │                  │
       │ 6. POST /agent/results               │                  │
       │ (JSON audit results)                 │                  │
       ├─────────────────▶├─────────────────▶│                  │
       │                  │ 7. Process &     │                  │
       │                  │    Store results │                  │
       │                  │                  ├─────────────────▶│
       │ 8. Acknowledge   │                  │                  │
       │◀─────────────────┤◀─────────────────┤                  │
```

## 🔐 Security Architecture

### Authentication & Authorization Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Dashboard  │    │   Nginx     │    │  Keycloak   │    │ VT-Server   │
│   User      │    │  Gateway    │    │   OIDC      │    │ Backend     │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │                  │
       │ 1. Access Dashboard                 │                  │
       ├─────────────────▶│                  │                  │
       │ 2. Redirect to   │                  │                  │
       │    OIDC login    │                  │                  │
       │◀─────────────────┤                  │                  │
       │                  │                  │                  │
       │ 3. Login (credentials)              │                  │
       ├────────────────────────────────────▶│                  │
       │ 4. Return JWT token                 │                  │
       │◀────────────────────────────────────┤                  │
       │                  │                  │                  │
       │ 5. API Request with JWT             │                  │
       ├─────────────────▶├─────────────────────────────────────▶│
       │                  │ 6. Validate JWT │                  │
       │                  │    with Keycloak │                  │
       │                  ├─────────────────▶│                  │
       │                  │ 7. JWT valid     │                  │
       │                  │◀─────────────────┤                  │
       │ 8. API Response  │                  │                  │
       │◀─────────────────┤◀─────────────────────────────────────┤
```

### mTLS Certificate Validation

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Agent     │    │    Nginx    │    │ VT-Server   │
│ (Client)    │    │   (Proxy)   │    │ (Backend)   │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │
       │ 1. TLS Handshake │                  │
       │    + Client Cert │                  │
       ├─────────────────▶│                  │
       │                  │                  │
       │ 2. Verify Client │                  │
       │    Certificate:  │                  │
       │    • CA signed   │                  │
       │    • Not expired │                  │
       │    • Not revoked │                  │
       │                  │                  │
       │ 3. Forward with  │                  │
       │    cert headers  │                  │
       │                  ├─────────────────▶│
       │                  │ X-SSL-Client-Cert│
       │                  │ X-SSL-Client-S-DN │
       │                  │                  │
       │                  │ 4. Authenticate  │
       │                  │    agent via     │
       │                  │    certificate   │
       │                  │                  │
       │ 5. Response      │                  │
       │◀─────────────────┤◀─────────────────┤
```

## 📊 Monitoring & Observability

### Metrics Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Monitoring Stack                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Prometheus  │  │   Grafana   │  │     Alertmanager    │  │
│  │ (Metrics)   │  │ (Dashboard) │  │   (Notifications)   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                        Exporters                            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Node      │  │ PostgreSQL  │  │      Nginx          │  │
│  │ Exporter    │  │  Exporter   │  │    Exporter         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Logging Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Logging Stack                           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Fluentd/    │  │Elasticsearch│  │      Kibana         │  │
│  │ Filebeat    │  │   Cluster   │  │   (Visualization)   │  │
│  │(Log Ship)   │  │ (Storage)   │  │                     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                      Log Sources                            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ VT-Server   │  │   Nginx     │  │   PostgreSQL        │  │
│  │   Logs      │  │   Logs      │  │     Logs            │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Agent     │  │  Step-CA    │  │    Keycloak         │  │
│  │   Logs      │  │   Logs      │  │     Logs            │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Deployment Architecture

### Development Environment
```
┌─────────────────────────────────────┐
│         Developer Workstation       │
├─────────────────────────────────────┤
│  Docker Compose Stack               │
│  ┌─────────────┐ ┌─────────────────┐│
│  │ VT-Server   │ │   PostgreSQL    ││
│  │ (Hot reload)│ │   (Dev data)    ││
│  └─────────────┘ └─────────────────┘│
│  ┌─────────────┐ ┌─────────────────┐│
│  │   Nginx     │ │    Step-CA      ││
│  │ (Dev certs) │ │ (Test certs)    ││
│  └─────────────┘ └─────────────────┘│
└─────────────────────────────────────┘
```

### Production Environment
```
┌─────────────────────────────────────────────────────────────┐
│                  Production Cluster                         │
├─────────────────────────────────────────────────────────────┤
│  Load Balancer (HAProxy/AWS ALB)                           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ VT-Server   │  │ VT-Server   │  │     VT-Server       │  │
│  │ Instance 1  │  │ Instance 2  │  │    Instance 3       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            PostgreSQL Cluster                           │ │
│  │  ┌─────────┐  ┌─────────────┐  ┌─────────────────────┐ │ │
│  │  │ Primary │  │ Replica 1   │  │     Replica 2       │ │ │
│  │  └─────────┘  └─────────────┘  └─────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐ │
│  │               Shared Services                           │ │
│  │  ┌─────────┐  ┌─────────────┐  ┌─────────────────────┐ │ │
│  │  │Step-CA  │  │  Keycloak   │  │      Redis          │ │ │
│  │  │Cluster  │  │   Cluster   │  │    (Session)        │ │ │
│  │  └─────────┘  └─────────────┘  └─────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Agent Fleet Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    Enterprise Network                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                  Site A (HQ)                            │ │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────────────────┐ │ │
│  │  │Windows PC │ │Windows PC │ │    Windows Server     │ │ │
│  │  │Agent      │ │Agent      │ │      Agent            │ │ │
│  │  └───────────┘ └───────────┘ └───────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                Site B (Remote)                          │ │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────────────────┐ │ │
│  │  │Windows PC │ │Windows PC │ │    Windows Laptop     │ │ │
│  │  │Agent      │ │Agent      │ │      Agent            │ │ │
│  │  └───────────┘ └───────────┘ └───────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                │                             │
│                                ▼                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                VT-Audit Server                          │ │
│  │           (Cloud or On-premise)                         │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 📞 Support

For architecture questions:
- Review [API Reference](API-Reference.md)
- Check [Deployment Guide](Deployment-Guide.md)  
- Create GitHub Issue với "architecture" label