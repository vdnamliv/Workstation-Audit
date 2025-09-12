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
        With --local: export XLSX report to --out
  -html
        With --local: render HTML report to --out
  -json
        With --local: print JSON report to stdout or --out
  -local
        Run local audit: fetch policies but DO NOT submit to server
  -log-file string
        Log file path (defaults to Program Files when running as service)
  -once
        Run local audit: fetch policies but DO NOT submit to server
  -log-file string
        Log file path (defaults to Program Files when running as service)
        Run local audit: fetch policies but DO NOT submit to server
  -log-file string
        Run local audit: fetch policies but DO NOT submit to server
        Run local audit: fetch policies but DO NOT submit to server
  -log-file string
        Log file path (defaults to Program Files when running as service)
  -once
        Run one cycle then exit
  -out string
        Output file path for --local
  -server string
        Server URL
  -tls-skip-verify
        INSECURE: skip TLS verify
```

Ví dụ audit trả kết quả dạng html:
```
.\agent.exe --local -- html
```

## 3. Sử dụng chạy Agent - Server
### 3.1 Chạy trên command line
Dựng server HTTP/HTTPS:
```
.\server.exe --addr:8000
.\server.exe --addr:8443 -rules rules -cert .\server.pem -key .\server.key
```
Chạy agent gửi kết quả audit về server:
```
./agent.exe -once -server http://192.168.124.1:8000 -enroll-key ORG_KEY_DEMO
```
##### NOTE: Với chức năng chạy định kỳ, thời gian định kỳ sẽ do server quyết định, nên agent không có flag liên quan đến tự đặt thời gian chạy

### 3.2 Chạy dạng service trên Windows
Tạo service VTAgent từ agent.exe
```
sc.exe create VTAgent binPath= "C:\Users\admin\Desktop\vt-audit\agent.exe service --action run --server http://192.168.124.1:8000 --enroll-key ORG_KEY_DEMO" start= auto
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