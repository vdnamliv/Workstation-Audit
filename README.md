# VT-Audit 

> ?? **Port mapping update**: Agents now use HTTPS 443 (mTLS gateway) while the admin dashboard listens on 8443.

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

└─────────────────┘    └──────────────────┘    └─────────────────┘- 📈 **Scalable Architecture**: 
