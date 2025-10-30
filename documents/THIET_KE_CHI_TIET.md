# 4. Thiết kế chi tiết

Tài liệu này trình bày "Thiết kế chi tiết" cho hệ thống VT-Audit, nhằm giúp đội vận hành/triển khai và developer có cái nhìn rõ ràng để xin hạ tầng, bảo trì và mở rộng.

## 4.1 Thiết kế hạ tầng VM

Mục này mô tả số lượng và cấu hình VM đề xuất (tách thành Server và DB Server). Các thông số là gợi ý cho môi trường production vừa (thường ~500–2,000 agent). Điều chỉnh theo tải thực tế.

### 4.1.1 Danh sách & cấu hình VM cần xin

Lưu ý: "vCPU" = logical CPU, "GB" = RAM, "IOPS" và "Disk" tuỳ thuộc vào nhà cung cấp.

A) VM cho thành phần Server (ứng dụng, gateway, proxy, keycloak)

- Option nhỏ (≤ 500 agent, test/staging):
  - 1 x Nginx + Nginx-certs (proxy) : 1 vCPU, 2 GB RAM, 20 GB disk
  - 1 x VT-Server (all-in-one: dashboard + api + enroll) : 2 vCPU, 4 GB RAM, 40 GB disk
  - 1 x Keycloak (auth) : 1 vCPU, 2 GB RAM, 20 GB disk
  - 1 x Step-CA (CA) : 1 vCPU, 2 GB RAM, 20 GB disk

- Option trung bình (500–2,000 agent):
  - 2 x Nginx (LB / HA) : 2 vCPU, 4 GB RAM, 40 GB disk (behind LB)
  - 2 x VT-Server (backend replicas) : 4 vCPU, 8 GB RAM, 80 GB disk (stateless, behind LB)
  - 2 x Keycloak (cluster) : 2 vCPU, 4 GB RAM, 40 GB disk (for HA)
  - 1 x Step-CA (primary) + 1 x Step-CA (standby) : 2 vCPU, 4 GB RAM, 40 GB disk
  - 1 x Monitoring/Logging node (Prometheus/ELK) : 4 vCPU, 8 GB RAM, 100 GB disk

- Option lớn (2,000+ agent / enterprise):
  - 3+ VT-Server replicas (4–8 vCPU, 16 GB RAM each)
  - 3+ Keycloak nodes
  - 2+ Nginx nodes in different AZs
  - Dedicated workers (for heavy report generation / batch import) : 4 vCPU, 8 GB RAM
  - Separate analytics / BI nodes as needed

B) VM cho thành phần Database

- Option nhỏ (≤ 500 agents):
  - 1 x PostgreSQL primary: 4 vCPU, 16 GB RAM, 200 GB SSD (provisioned IOPS)
  - (Optional) nightly backup server or cloud snapshot

- Option trung bình (500–2,000 agents) – khuyến nghị production:
  - 1 x PostgreSQL primary: 8 vCPU, 32 GB RAM, 500 GB SSD (high IOPS)
  - 1 x PostgreSQL standby replica (hot standby): 8 vCPU, 32 GB RAM, 500 GB SSD
  - WAL archive storage (object storage / NFS) for PITR
  - Backup orchestration node (cron + pg_basebackup)

- Option lớn (enterprise, 2,000+ agents):
  - PostgreSQL cluster with replication (primary + 2 replicas), 16 vCPU, 64 GB RAM each
  - Dedicated storage layer (SAN/NAS/Cloud DB managed service)
  - Use read-replicas for analytics queries

### Ghi chú về mạng & bảo mật VM
- Mạng: riêng private subnet cho DB; chỉ mở port 5432 giữa app servers và DB.
- Firewall: chỉ cho phép 443/8443 từ corporate/agents tới proxy, SSH từ jump-host.
- Certificates: sử dụng Step-CA cho mTLS giữa agent ↔ proxy/server.

---

## 4.2 Thiết kế ứng dụng

### 4.2.1 Thiết kế tổng quan

Hệ thống bao gồm:
- Dashboard (web SPA) – quản trị và policy management
- VT-Server backend – REST API cho agents & dashboard
- Keycloak – OIDC cho dashboard
- Nginx – reverse proxy, TLS termination, routing
- Step-CA – Certificate Authority cho mTLS (agent enrollment)
- PostgreSQL – storage kết quả audit và cấu hình

#### 4.2.1.1 Các thành phần điều phối và quản trị tập trung (Dashboard)

- Authentication / Authorization flow:
  - Dashboard users authenticate via Keycloak (OIDC).
  - Keycloak trả về JWT/OIDC token; dashboard dùng token để call backend API.
  - Backend verify token (JWKS from Keycloak) và áp role-based access control: admin/operator/viewer.

- Luồng enroll, cấp cert và xác thực cho agent:
  1. Agent lúc bootstrap (hoặc khi admin trigger) gọi endpoint enroll gateway qua HTTPS: `/agent/enroll`.
  2. Enroll-Gateway xác thực bootstrap token (được cấp sẵn trong `agent.conf`) và forward request tới Step-CA.
  3. Step-CA issue short-lived cert (X.509) cho agent, trả về private key & cert hoặc PKCS12 container.
  4. Agent lưu cert vào `CERT_DIR` và sử dụng cert này cho mTLS khi gọi server endpoints.
  5. Server side (Nginx + API) validate client cert CN / SAN hoặc sử dụng mTLS mutual verification.

- Luồng lưu dữ liệu kết quả audit vào DB:
  1. Agent thực hiện audit theo policy (local cache hoặc fetch mới).
  2. Agent gửi POST `/agent/results` (JSON) tới server với Authorization (mTLS or Bearer).
  3. Backend API validate payload, map agent -> agent record, insert vào `audit_results`.
  4. Nếu payload lớn, backend lưu tạm, ack agent, và xử lý ingest (async worker) để tránh blocking.

- Luồng thêm sửa xóa dữ liệu policy trên Policy Management:
  1. Admin gọi UI để tạo/update/delete policy.
  2. Dashboard calls Backend API `/api/policies` (OIDC auth).
  3. Backend validate policy JSON/schema, persist to `policies` table with version++.
  4. Backend đặt `active=true` cho version mới, và agents sẽ fetch active version on next poll (or next health check).
  5. Optional: Backend push notification (webhook/message queue) to notify other services or monitoring.

#### 4.2.1.2 Các thành phần tính năng của agent

Agent có 2 tính năng chính (được yêu cầu):

1) "Local Compliance Audit" – thực thi policies và xuất báo cáo
   - Mô tả: Agent tải policy (hoặc dùng cache) và thực thi các checks (registry, service, file, process, config).
   - Output: JSON results; optional HTML/Excel via `--local --html/--excel`.
   - Tính năng offline: nếu server unreachable, agent dùng cached policy và queue kết quả để gửi khi có kết nối.

2) "Periodic Server-Controlled Scheduling & Reporting" – chạy định kỳ theo lịch do server chỉ định
   - Mô tả: Agent gọi `/agent/interval` hoặc `health` endpoint để lấy polling interval; server có thể set interval per-agent or per-group.
   - Agent thực hiện audit theo interval, gửi kết quả, nhận interval mới nếu server update.

- Luồng API agent/enroll/mTLS (chi tiết):
  1. Agent (bootstrap) POST `/agent/enroll/start` với bootstrap token (Bearer or header) và thông tin hostname.
  2. Enroll-Gateway validate token → call Step-CA REST API to create cert request.
  3. Step-CA issue cert; Enroll-Gateway returns cert package to agent.
  4. Agent install cert in `CERT_DIR` and switches to mTLS mode for subsequent requests.
  5. Agent calls `/agent/health` (mTLS) or `/agent/policies` (mTLS) using client cert; Nginx enforces mTLS (or API verifies cert subject).

---

### 4.2.2 Mô hình logic và luồng hoạt động

#### 4.2.2.1 Agent kết nối tới server
- Kết nối mặc định: HTTPS trên port 8443 qua Nginx.
- Agent có 2 chế độ auth:
  - mTLS (production) — mutual TLS with client cert
  - Bearer bypass (development/test) — `Authorization: Bearer test:test`
- Agent chọn server URL từ `agent.conf` hoặc CLI flag `--server`.

Flow:
1. Agent tạo HTTP client (mTLS or fallback) và gọi `/agent/health`.
2. Nếu server trả về `active_version` và `interval`, agent cập nhật state.
3. Agent tải policy nếu local cache missing hoặc version mismatch.
4. Agent thực hiện audit và gửi `/agent/results`.

#### 4.2.2.2 Agent healthcheck với server
- Endpoint: `GET /agent/health`
- Response: `{ status, active_version, server_time, uptime }`.

Healthcheck logic:
- Nếu health ok: serverAlive=true, agent proceeds.
- Nếu health lỗi (network/401/etc): agent increment retry with exponential backoff, continue using cached policy and queue results.
- Agent heartbeat: update `agents.last_seen` khi gửi results; a separate heartbeat endpoint may be available.

#### 4.2.2.3 Server lập lịch cho agent chạy tự động
- Server lưu `agent_configs.polling_interval` (seconds) lên DB.
- Agent gọi `GET /agent/interval?agent_id=` hoặc `GET /agent/health` để nhận interval.
- Khi backend update interval (UI), change được persist và sẽ có hiệu lực ở lần request tiếp theo của agent.
- (Optional) Push model: server emit notification (MQ/webhook) nếu muốn thông báo real-time; agent phải subscribe nếu muốn push.

#### 4.2.2.4 Server thu thập và lưu trữ kết quả rà soát agent vào DB
- Ingest pipeline:
  1. Agent POST `/agent/results` → API validation
  2. Insert metadata (agent_id, timestamp) vào `agents`/`audit_results`
  3. For heavy payloads: store raw payload into object store and persist pointer in DB, process in background worker
  4. Update aggregates: compliance score, counters per agent/policy
  5. Emit events for alerting if critical failures

- Retention & archive:
  - Hot data: last 6 months in DB
  - Cold archive: older records to object storage (S3) and metadata retained in DB
  - Periodic vacuum and partitioning (monthly) recommended

#### 4.2.2.5 Quản trị tập trung trên Dashboard (log, search, policy management)
- Features:
  - Agent Fleet view (last seen, last audit, compliance score)
  - Result search (hostname/rule/time range/severity)
  - Policy CRUD with versioning and activation
  - Logs: centralized logging from backend (ELK/EFK)
  - Audit trail: who changed policy & when (user, timestamp)
- Security: dashboard access only via HTTPS (port 443), OIDC-authenticated, RBAC enforced server-side.

---

## 4.3 Thiết kế quản trị vận hành

- Dashboard truy cập qua port **443 (HTTPS)**; internal admin connections có thể sử dụng 8443.
- Đăng nhập sử dụng Keycloak (OIDC). Admin role có quyền tạo/activate policy, operator role chỉ có thể view và trigger audits.
- Backup và restore:
  - Daily DB logical backups (`pg_dump`) và WAL shipping for PITR.
  - Weekly snapshot của storage và Step-CA keys (secure vault required).
- Patch & upgrade:
  - Rolling update cho VT-Server replicas, cập nhật Keycloak cluster tuần tự.
  - Agent update: publish new `agent.exe` và update `distribute` package; admin có thể push via MDM hoặc script.
- Logs & troubleshooting:
  - Central logs in ELK/EFK; dashboards for error/agent health.
  - Escalation flow: alert when >X agents failed to connect in Y minutes.

## 4.4 Thiết kế giám sát tác động (tích hợp lên GNOC)

Mục tiêu: khi có sự kiện quan trọng (mass failure, critical rule fail, DB down), tự động tạo ticket vào GNOC và thông báo theo SLA.

- Event types to forward:
  - Agent offline > 30 minutes for > N agents
  - Critical policy failure (severity=critical)
  - DB unreachable / replication lag > threshold
  - Keycloak or Step-CA down
  - High error rates on `/agent/results` (5xx spike)

- Integration patterns:
  1. **Webhook**: Backend posts event JSON to GNOC webhook endpoint.
     - Payload example: `{"event":"agent_offline","count":25,"hosts":["..."],"time":"..."}`.
  2. **Ticketing API**: call GNOC ticket creation API (CURL / REST) with structured details.
  3. **SNMP Trap** (if GNOC uses SNMP): send SNMPv3 trap to GNOC collector.
  4. **Email/SMS fallback**: for critical incidents.

- Implementation details:
  - Events aggregated and rate-limited to avoid ticket storms
  - Include contextual data (agent list, last error logs, recent config changes)
  - Correlation id for follow-up investigations

## 4.5 Thiết kế dự phòng

### 4.5.1 Khả năng dự phòng của database

Khuyến nghị production-level HA & DR cho PostgreSQL:

- **Primary + Standby Replica**: synchronous or asynchronous replication depending on RPO.
  - Synchronous: minimal data loss, higher latency.
  - Asynchronous: better write throughput, potential small data loss.
- **Failover**:
  - Use repmgr or Patroni for automated failover & leader election.
  - Health checks: monitor replication lag, node responsiveness.
- **Backups & PITR**:
  - Continuous WAL archiving to object storage (S3) + base backups every 24h.
  - Test restore procedures quarterly.
- **Read replicas for analytics**:
  - Offload heavy read queries to replicas to keep primary write performance.
- **Disk & Storage**:
  - Use high IOPS SSD for data directories; separate volume for WAL.
- **Regular maintenance**:
  - VACUUM/ANALYZE, partition management, index maintenance.

### Database DR scenario (summary)
- RTO target: e.g., < 15 minutes for app failover (with automated failover)  
- RPO target: depends on business (synchronous replication => near 0s; async => minutes)
- Steps in DR test:
  1. Promote replica to primary (test via repmgr/Patroni)
  2. Reconfigure VT-Server to point to new primary or use DNS failover
  3. Validate agent ingestion and dashboard read/write

---

## Kết luận

Tài liệu này cung cấp thiết kế chi tiết hạ tầng VM, mô hình ứng dụng, các luồng nghiệp vụ chính, vận hành và dự phòng để triển khai VT-Audit ở môi trường production. Các con số (vCPU/RAM/Disk) là khuyến nghị ban đầu. Trước triển khai thực tế, cần thực hiện load test và điều chỉnh thông số theo kết quả thực tế.


> File gốc: `DEVELOPER_GUIDE.md`, `ARCHITECTURE.md`, `API_REFERENCE.md` — nội dung trên tóm tắt và mở rộng thành phần cần thiết cho phần Thiết kế chi tiết.
