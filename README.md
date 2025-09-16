# Workstation Audit Tool

## 1. Build agent.exe và server.exe
```
go build -o server.exe .\server\cmd\vt-server\main.go
go build -o agent.exe .\agent\cmd\vt-agent\main.go
```

## 2. Sử dụng chạy local
```
PS C:\Users\admin\Desktop\vt-audit> .\agent.exe -h
Usage of C:\Users\admin\Desktop\vt-audit\agent.exe:
  -ca-file string
        CA PEM file
  -enroll-key string
        Enrollment key
  -excel
        With --local: export XLSX report
  -html
        With --local: render HTML report
  -json
        With --local: print JSON report to stdout
  -local
        Run local audit: fetch policies but DO NOT submit to server      
  -log-file string
        Log file path (defaults to Program Files when running as service)
  -once
        Run one cycle then exit
  -server string
        Server URL
  -tls-skip-verify
        INSECURE: skip TLS verify
```

Ví dụ audit trả kết quả dạng html:
```
.\server.exe --mode all --agent-addr :443 --dashboard-addr :8443 
.\agent.exe --local -- html
```

## 3. Sử dụng chạy Agent - Server
### 3.1 Chạy trên command line
Dựng server HTTP/HTTPS:
```
.\server.exe --mode all --agent-addr :443 --dashboard-addr :8443 
.\server.exe --addr:8443 -rules rules -cert .\server.pem -key .\server.key (tạm bỏ qua)
```
Chạy agent gửi kết quả audit về server:
```
./agent.exe -once -server http://192.168.124.1:443 -enroll-key ORG_KEY_DEMO
```
##### NOTE: Với chức năng chạy định kỳ, thời gian định kỳ sẽ do server quyết định, nên agent không có flag liên quan đến tự đặt thời gian chạy

### 3.2 Chạy dạng service trên Windows
Tạo service VTAgent từ agent.exe
```
sc.exe create VTAgent binPath= "C:\Users\admin\Desktop\vt-audit\agent.exe service --action run --server http://192.168.124.1:443 --enroll-key ORG_KEY_DEMO" start= auto
```
Khởi động service VTAgent:
```
sc.exe start VTAgent
```
Dừng service VTAgent:
```
sc.exe stop VTAgent 
```
Xem process của service:
```
sc.exe query VTAgent
```

## 4. Build msi với Wix
```
wix build -arch x64 -o VTAgent.msi .\Package.wxs .\Folders.wxs .\Components.wxs
```
## 5. Giải thích các module server
![image](image/workflow.png)
- Mục tiêu: chia nhỏ server thành các phần có thể scale và đóng gói Docker độc lập theo so d?: API agent, Dashboard, DB.
- Thư mục nguồn:
  - `server/pkg/httpagent`: API cho agent (`/enroll`, `/policy/*`, `/results`).
  - `server/pkg/dashboard`: Dashboard + JSON API (`/api/*`), static ? `/app/`.
  - `server/pkg/storage`: interface; SQLite impl ? `server/pkg/storage/sqlite`.
  - `server/pkg/policy`: helper dọc YAML, normalize, hash.
  - `server/pkg/model`: các struct dùng chung.

### Cách chạy

- Tương thích cũ (1 cổng):
```
server.exe --addr :8443
```

- Tách tiến trình/cổng (phù hợp Docker):
```
# Chạy Dashboard
server.exe --mode dashboard --dashboard-addr :8443

# Chạy API agent
server.exe --mode agent --agent-addr :443

# Cùng 1 process, 2 cổng
server.exe --mode all --agent-addr :443 --dashboard-addr :8443
```

- Dùng TLS: thêm --cert và --key.

## 5. Chuyển sang PostgreSQL và chạy với Docker

### Tổng quan
- Tất cả dữ liệu policy baseline (yaml) và audit kết quả được lưu trong một DB PostgreSQL, tách thành 2 schema để dễ quản lý:
      - Schema policy: bảng policy_versions, policy_heads (versioning và active head)
      - Schema audit: bảng agents, results_flat (enroll, kết quả latest)
- Server đã tách module: httpagent (API agent) và dashboard (UI + API). Cả hai đều sử dụng cùng Store (SQLite hoặc PostgreSQL).

### Chạy local với PostgreSQL
1) Cài đặt PostgreSQL 15+ và tạo DB:
```
createdb vtadb
```
2) Chạy server dùng Postgres (backward compat, một cổng):
```
server.exe --addr :8443 --pg_dsn "postgres://user:pass@localhost:5432/vtadb?sslmode=disable"
```
3) Hoặc tách 2 tiến trình:
```
# Dashboard
server.exe --mode dashboard --dashboard-addr :8443 --pg_dsn "postgres://user:pass@localhost:5432/vtadb?sslmode=disable"
# API agent
server.exe --mode agent --agent-addr :443 --pg_dsn "postgres://user:pass@localhost:5432/vtadb?sslmode=disable"
```

### Chạy bằng Docker Compose
```
cd docker
docker compose up --build
```
- Services:
  - `db`: PostgreSQL (user/pass `vta`/`vta`, db `vtadb`)
  - `api`: vt-server mode `agent` (port 443)
  - `dashboard`: vt-server mode `dashboard` (port 8443)

### Biến môi trường chính
- --pg_dsn: DSN Postgres, ví dụ postgres://user:pass@host:5432/db?sslmode=disable
- --mode: all|agent|dashboard
- --agent-addr, --dashboard-addr: cổng nghe
- --cert, --key: bật TLS nếu cần
- --rules: thư mục chứa windows.yml seed ban đầu

### Phụ thuộc
- Go 1.22+ (nếu build local)
- PostgreSQL 15+ (server hoặc container)
- Docker/Docker Compose (nếu chạy bằng container)

### Ghi chú triển khai
- Khi dùng PostgreSQL, hệ thống tự động tạo schema audit và policy, tạo bảng và view tương thích ở public.* để giữ nguyên một số truy vấn cũ.
- Có thể chạy API agent và Dashboard trên các container riêng, cùng kết nối 1 DB. Thêm auth Keycloak/JWT vào Dashboard sau này không ảnh hưởng Store.
