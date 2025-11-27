## Công dụng của từng loại cert:
### env/certs/nginx (server-side cert)
#### 1. server.crt + server.key:
- Công dụng: SSL/TLS certificate cho nginx (HTTPS)
- SAN bao gồm: DNS:gateway.local, DNS:localhost, DNS:stepca, DNS:agent-gateway.local, IP:192.168.1.226
- Sử dụng cho: Agent kết nối HTTPS đến server
- Tự động tạo: Bởi container nginx-certs trong docker-compose

#### 2. stepca_chain.crt
- Công dụng: Step-CA root + intermediate CA chain
- Sử dụng cho: Nginx verify client certificates từ agent (mTLS)
- Cấu hình nginx: ssl_client_certificate /etc/nginx/certs/stepca_chain.crt
- Tạo bằng: docker cp từ Step-CA container

#### 3. stepca_root_ca.crt
- Công dụng: Step-CA root certificate riêng
- Sử dụng cho: Thành phần của chain
- Copy từ: Step-CA container /home/step/certs/root_ca.crt

#### 4. stepca_intermediate_ca.crt
- Công dụng: Step-CA intermediate certificate
- Sử dụng cho: Thành phần của chain
- Copy từ: Step-CA container /home/step/certs/intermediate_ca.crt

### agent/pkg/enroll (agent-side embedded cert)
#### 1. ca_cert.pem:
- Công dụng: Embedded CA certificate trong agent binary
- Sử dụng cho: Agent trust server's HTTPS certificate (không cần cài thủ công)
- Nội dung: Copy từ root_ca.crt (self-signed nginx CA)
- Embedded vào code: //go:embed ca_cert.pem

### data/certs (agent runtime cert)
#### 1. agent.crt + agent.key:
- Công dụng: mTLS client certificate của agent
- Issued by: Step-CA (qua enrollment flow)
- Sử dụng cho: Agent authentication với server
- Tự động tạo: Khi agent chạy lần đầu (enrollment)

#### 2. ca.pem
- Step-CA certificate được server trả về
- Cached để verify server certificate

## Cert flow :
#### 1. Agent -> Server (HTTPS)
Agent trust server.crt vì:
├─ embedded ca_cert.pem (nginx self-signed CA) được compile vào binary
└─ Không cần cài CA thủ công trên Windows

#### 2. Agent → Server (mTLS Client Auth)
Server trust agent.crt vì:
├─ Nginx sử dụng stepca_chain.crt để verify
├─ agent.crt được Step-CA issue
└─ Chain trust: stepca_root_ca → stepca_intermediate_ca → agent.crt

## Fix nếu không đủ số cert được tạo ra như bên trên:
#### Bước 1: Setup
``` docker compose up -d ```

#### Bước 2: Copy Step-CA cert vào nginx:
```
# Tự động sau khi Step-CA khởi động
docker cp vt-stepca:/home/step/certs/root_ca.crt env/certs/nginx/stepca_root_ca.crt
docker cp vt-stepca:/home/step/certs/intermediate_ca.crt env/certs/nginx/stepca_intermediate_ca.crt

# Tạo chain
cat env/certs/nginx/stepca_root_ca.crt env/certs/nginx/stepca_intermediate_ca.crt > env/certs/nginx/stepca_chain.crt

# Restart nginx
docker compose restart nginx
```

#### Bước 3: Update nginx server certificate với production IP/domain
Sửa docker-compose.yml:
```
nginx-certs:
  command: >
    sh -c "
    if [ ! -f /certs/server.crt ]; then
      apk add --no-cache openssl &&
      openssl req -x509 -newkey rsa:2048 -keyout /certs/server.key -out /certs/server.crt \
        -days 365 -nodes -subj '/CN=your-domain.com' \
        -addext 'subjectAltName=DNS:your-domain.com,DNS:*.your-domain.com,IP:YOUR_PUBLIC_IP' &&
      # ... rest of script
    fi
    "
```

#### Bước 4: Build agent để phân phối:
```
# Sửa IP/domain trong BuildServerURL
cd agent/cmd/vt-agent

# Build với production server URL
go build -ldflags "-X 'main.BuildServerURL=https://your-domain.com:443/agent'" -o vt-agent.exe
```