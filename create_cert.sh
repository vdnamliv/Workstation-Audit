#!/bin/bash

# Dừng script ngay lập tức nếu có bất kỳ lệnh nào bị lỗi
set -e

echo "--- Bắt đầu quy trình tạo Cert và Build Agent ---"

# 1. Copy Root CA từ docker container vt-stepca
echo "[1/6] Copying Root CA..."
docker cp vt-stepca:/home/step/certs/root_ca.crt env/certs/nginx/stepca_root_ca.crt

# 2. Copy Intermediate CA từ docker container vt-stepca
echo "[2/6] Copying Intermediate CA..."
docker cp vt-stepca:/home/step/certs/intermediate_ca.crt env/certs/nginx/stepca_intermediate_ca.crt

# 3. Gộp Root CA và Intermediate CA thành chain
echo "[3/6] Creating Certificate Chain..."
cat env/certs/nginx/stepca_root_ca.crt env/certs/nginx/stepca_intermediate_ca.crt > env/certs/nginx/stepca_chain.crt

# 4. Khởi động lại Nginx service trong Docker Compose
echo "[4/6] Restarting Nginx..."
docker compose restart nginx

# 5. Copy server cert sang thư mục enroll của agent
echo "[5/6] Copying cert to agent enrollment path..."
cp env/certs/nginx/server.crt agent/pkg/enroll/ca_cert.pem

# 6. Build Go agent
echo "[6/6] Building vt-agent..."
# Lưu thư mục hiện tại và chuyển vào thư mục code
pushd agent/cmd/vt-agent > /dev/null
go build -o ../../../vt-agent.exe
# Quay trở lại thư mục gốc (nếu cần thiết cho các lệnh sau này)
popd > /dev/null

echo "--- Hoàn tất! File output: vt-agent.exe ---"