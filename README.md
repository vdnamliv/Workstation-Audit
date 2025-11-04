# VT-Audit - Enterprise Windows Compliance Platform

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://docker.com)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://microsoft.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

VT-Audit là hệ thống **enterprise-grade** giám sát tuân thủ baseline security cho Windows workstations với dashboard tập trung, zero-config mTLS authentication, và policy management tự động.

## ✨ Key Features

- 🔒 **Zero-Config mTLS**: Automatic certificate enrollment với Step-CA
- 📊 **Centralized Dashboard**: Web-based policy management và compliance analytics
- 🚀 **Auto-deployment**: Agent tự cài đặt như Windows service
- ⚡ **Smart Caching**: Offline operation với intelligent policy caching
- 🛡️ **Fallback Authentication**: X-Test-Mode cho development và testing
- 📈 **Scalable**: Support hàng trăm agents đồng thời

## 🏗️ System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Windows       │───▶│   Nginx Gateway  │───▶│   API Server    │
│   Agents        │    │   (mTLS Proxy)   │    │   + Database    │
│  (Service Mode) │    │   Port :8443     │    │   Port :8080    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │ mTLS Certificate      │ Certificate           │ Policy + Results
         │ Authentication        │ Validation            │ Processing
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Step-CA Auto    │◀───│ Enroll Gateway   │───▶│   PostgreSQL    │
│ Enrollment      │    │ Port :8742       │    │   Database      │
│ (Zero-Config)   │    │ (Bootstrap)      │    │   Storage       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- **Server**: Linux với Docker & Docker Compose
- **Agent**: Windows 10/11 với PowerShell 5.1+
- **Network**: HTTPS access giữa agents và server

### 1. Server Deployment

**Quick Setup (Recommended):**
```bash
git clone https://github.com/vdnamliv/Workstation-Audit.git
cd Workstation-Audit/env

# Automated setup - generates secure .env file
./setup-env.sh

# Or manual setup
cp .env.template .env
# Edit .env with your configuration

# Deploy
sudo docker compose up -d
```

📖 **[Full Deployment Guide](DEPLOYMENT.md)** - Detailed configuration and troubleshooting

### 2. Agent Deployment
```powershell
# Download và test
.\agent.exe --local --html

# Production installation
.\agent.exe --server https://your-server:8443 --install
Start-Service VT-Agent
```

### 3. Access Dashboard
Open: `https://your-server/`
- Username: `admin@vt-audit.local`
- Password: `admin123`

## 📚 Documentation

📖 **[Complete Documentation Site](https://vdnamliv.github.io/Workstation-Audit/)**

### Essential Guides
- **[🚀 Deployment Guide](DEPLOYMENT.md)** - **START HERE** - Complete production setup with troubleshooting
- **[Environment Setup](env/README.md)** - Configuration file reference
- **[Architecture](https://vdnamliv.github.io/Workstation-Audit/architecture)** - System design
- **[Agent Management](https://vdnamliv.github.io/Workstation-Audit/agents)** - Windows deployment
- **[Certificate Management](https://vdnamliv.github.io/Workstation-Audit/certificates)** - mTLS setup
- **[Troubleshooting](https://vdnamliv.github.io/Workstation-Audit/troubleshooting)** - Issue resolution

## 🔧 Agent Commands

| Command | Description |
|---------|-------------|
| `--local --html` | Local audit với HTML report |
| `--once` | Single audit với server submission |
| `--install` | Install as Windows service |
| `--skip-mtls` | Bypass mTLS (testing) |

## 🛟 Support

- 📖 [Documentation](https://vdnamliv.github.io/Workstation-Audit/)
- 🐛 [Issues](https://github.com/vdnamliv/Workstation-Audit/issues)
- 💬 [Discussions](https://github.com/vdnamliv/Workstation-Audit/discussions)

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.
