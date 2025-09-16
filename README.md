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

- Mục tiêu: chia nhỏ server thành các phần có thể scale và đóng gói Docker độc lập theo so d?: API agent, Dashboard, DB.
- Thư mục nguồn:
  - `server/pkg/httpagent`: API cho agent (`/enroll`, `/policy/*`, `/results`).
  - `server/pkg/dashboard`: Dashboard + JSON API (`/api/*`), static ? `/app/`.
  - `server/pkg/storage`: interface; SQLite impl ? `server/pkg/storage/sqlite`.
  - `server/pkg/policy`: helper dọc YAML, normalize, hash.
  - `server/pkg/model`: các struct dùng chung.

### Cách chạy

- Tuong th�ch cu (1 c?ng):
```
server.exe --addr :8443
```

- T�ch ti?n tr�nh/c?ng (ph� h?p Docker):
```
# Ch? Dashboard
server.exe --mode dashboard --dashboard-addr :8443

# Ch? API agent
server.exe --mode agent --agent-addr :443

# C�ng 1 process, 2 c?ng
server.exe --mode all --agent-addr :443 --dashboard-addr :8443
```

- D�ng TLS: th�m `--cert` v� `--key`.

## 5. Chuyen sang PostgreSQL va chay voi Docker

### Tong quan
- Tat ca du lieu policy baseline (yaml) va audit ket qua duoc luu trong mot DB PostgreSQL, tach thanh 2 schema de de quan ly:
  - Schema `policy`: bang `policy_versions`, `policy_heads` (versioning va active head)
  - Schema `audit`: bang `agents`, `results_flat` (enroll, ket qua latest)
- Server da tach module: `httpagent` (API agent) va `dashboard` (UI + API). Ca hai deu su dung cung Store (SQLite hoac PostgreSQL).

### Chay local voi PostgreSQL
1) Cai dat PostgreSQL 15+ va tao DB:
```
createdb vtadb
```
2) Chay server dung Postgres (backward compat, mot cong):
```
server.exe --addr :8443 --pg_dsn "postgres://user:pass@localhost:5432/vtadb?sslmode=disable"
```
3) Hoac tach 2 tien trinh:
```
# Dashboard
server.exe --mode dashboard --dashboard-addr :8443 --pg_dsn "postgres://user:pass@localhost:5432/vtadb?sslmode=disable"
# API agent
server.exe --mode agent --agent-addr :443 --pg_dsn "postgres://user:pass@localhost:5432/vtadb?sslmode=disable"
```

### Chay bang Docker Compose
```
cd docker
docker compose up --build
```
- Services:
  - `db`: PostgreSQL (user/pass `vta`/`vta`, db `vtadb`)
  - `api`: vt-server mode `agent` (port 443)
  - `dashboard`: vt-server mode `dashboard` (port 8443)

### Bien moi truong chinh
- `--pg_dsn`: DSN Postgres, vi du `postgres://user:pass@host:5432/db?sslmode=disable`
- `--mode`: `all|agent|dashboard`
- `--agent-addr`, `--dashboard-addr`: cong nghe
- `--cert`, `--key`: bat TLS neu can
- `--rules`: thu muc chua `windows.yml` seed ban dau

### Phu thuoc
- Go 1.22+ (neu build local)
- PostgreSQL 15+ (server hoac container)
- Docker/Docker Compose (neu chay bang container)

### Ghi chu trien khai
- Khi dung PostgreSQL, he thong tu dong tao schema `audit` va `policy`, tao bang va view tuong thich o `public.*` de giu nguyen mot so truy van cu.
- Co the chay API agent va Dashboard tren cac container rieng, cung ket noi 1 DB. Them auth Keycloak/JWT vao Dashboard sau nay khong anh huong Store.
