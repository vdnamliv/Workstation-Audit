Kế hoạch Triển khai Chi tiết (Runbook)
0. 🎯 Tóm tắt Kiến trúc & Mục tiêu
Mục tiêu: Triển khai ứng dụng (từ file docker-compose) lên 8 VM trên OpenStack, chia thành 4 nhóm dịch vụ.

Điểm mấu chốt (HA):

Proxy (Lớp 1): 2 VM Nginx/OIDC (.45, .46) sẽ chạy ở chế độ Active/Passive, chia sẻ một IP ảo (VIP) 10.221.130.44.

Database (Lớp 4): 2 VM DB (.52, .53) sẽ chạy ở chế độ Primary/Standby, chia sẻ một IP ảo (VIP) 10.221.130.51.

Công cụ chính: Docker, Docker Compose, Keepalived (để quản lý VIP), và PostgreSQL Streaming Replication (cho HA Database).

Giai đoạn 1: Chuẩn bị Hạ tầng & Mạng (SysAdmin)
Đây là bước nền tảng, thực hiện trên cả 8 VM trước khi chạy bất kỳ container nào.

1.1. Cài đặt Gói cơ bản (Thực hiện trên tất cả 8 VM)
Cập nhật hệ thống:

Bash

dnf update -y
Cài đặt các công cụ cần thiết (Docker, Docker Compose, Keepalived):

Bash

# Cài đặt Docker
dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io
systemctl enable --now docker

# Cài đặt Docker Compose (plugin)
dnf install -y docker-compose-plugin

# Cài đặt Keepalived (quan trọng cho VIP)
dnf install -y keepalived
1.2. Cấu hình Tường lửa (FirewallD)
Bạn phải mở port chính xác trên từng nhóm VM.

Trên 2 VM DB Server (.52, .53):

Bash

# Mở port 5432 (Postgres) cho các VM Admin/Agent
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.49/32" port protocol="tcp" port="5432" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.50/32" port protocol="tcp" port="5432" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.47/32" port protocol="tcp" port="5432" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.48/32" port protocol="tcp" port="5432" accept'

# Cho phép giao thức VRRP (cho Keepalived)
firewall-cmd --permanent --add-rich-rule='rule protocol value="vrrp" accept'
firewall-cmd --reload
Trên 2 VM Admin API (.49, .50):

Bash

# Mở port 8080 (Keycloak) và 8081 (api-backend) cho 2 VM Proxy
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.45/32" port protocol="tcp" port="8080" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.45/32" port protocol="tcp" port="8081" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.46/32" port protocol="tcp" port="8080" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.46/32" port protocol="tcp" port="8081" accept'
firewall-cmd --reload
Trên 2 VM Agent API (.47, .48):

Bash

# Mở port 9000 (StepCA), 8080 (api-agent), 8082 (enroll) cho 2 VM Proxy
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.45/32" port protocol="tcp" port="9000" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.45/32" port protocol="tcp" port="8080" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.45/32" port protocol="tcp" port="8082" accept'
# ... lặp lại cho IP .46
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.211.130.46/32" port protocol="tcp" port="9000" accept'
# ... (tương tự cho các port 8080, 8082 từ .46)
firewall-cmd --reload
Trên 2 VM Reverse Proxy (.45, .46):

Bash

# Mở port 80, 443, 8443 cho truy cập bên ngoài
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --permanent --add-port=8443/tcp

# Cho phép giao thức VRRP (cho Keepalived)
firewall-cmd --permanent --add-rich-rule='rule protocol value="vrrp" accept'
firewall-cmd --reload
Giai đoạn 2: Cấu hình HA cho Database (Cực kỳ quan trọng)
Bạn không nên chạy HA cho PostgreSQL bằng Docker Compose. Hãy cài đặt native (trực tiếp lên OS) và dùng Streaming Replication. VIP 10.221.130.51 sẽ trỏ về máy Primary.

2.1. Cài đặt & Cấu hình PostgreSQL (trên .52 và .53)
Cài đặt PostgreSQL 16 (giống image của bạn):

Bash

dnf install -y postgresql16-server postgresql16
/usr/pgsql-16/bin/postgresql-16-setup initdb
systemctl enable --now postgresql-16
Trên Primary (chọn .52):

Sửa postgresql.conf (/var/lib/pgsql/16/data/postgresql.conf):

Ini, TOML

listen_addresses = '*'
wal_level = replica
max_wal_senders = 10
wal_keep_size = 512MB
Sửa pg_hba.conf (/var/lib/pgsql/16/data/pg_hba.conf):

# Cho phép Standby (.53) kết nối để replication
host    replication     replicator      10.221.130.53/32        scram-sha-256

# Cho phép ứng dụng kết nối
host    all             all             10.211.130.49/32        scram-sha-256
host    all             all             10.211.130.50/32        scram-sha-256
host    all             all             10.211.130.47/32        scram-sha-256
host    all             all             10.211.130.48/32        scram-sha-256
Tạo user replication và database:

Bash

sudo -u postgres psql -c "CREATE USER replicator WITH REPLICATION PASSWORD 'MyReplicationPass';"
sudo -u postgres psql -c "CREATE USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';"
sudo -u postgres psql -c "CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER};"
# ... (tạo các DB/User khác như KEYCLOAK_DB_USER)
Restart Postgres: systemctl restart postgresql-16

Trên Standby (chọn .53):

Xóa data cũ: systemctl stop postgresql-16 và rm -rf /var/lib/pgsql/16/data/*

Backup từ Primary:

Bash

sudo -u postgres PGPASSWORD='MyReplicationPass' pg_basebackup -h 10.221.130.52 -U replicator -p 5432 -D /var/lib/pgsql/16/data/ -Fp -Xs -R
(Lệnh trên tự tạo file standby.signal và postgresql.auto.conf cho bạn).

Start Postgres: systemctl start postgresql-16

2.2. Cấu hình DB VIP 10.221.130.51 (Keepalived)
Tạo file script check Postgres (trên cả .52 và .53):

Tạo file /etc/keepalived/check_postgres.sh:

Bash

#!/bin/bash
# Script kiểm tra xem Postgres có phải là Primary hay không
/usr/pgsql-16/bin/pg_isready -q
if [ $? -eq 0 ] && [ $(sudo -u postgres /usr/pgsql-16/bin/psql -t -c "SELECT pg_is_in_recovery();") = "f" ]; then
    exit 0 # Là Primary và sẵn sàng
else
    exit 1 # Là Standby hoặc Lỗi
fi
chmod +x /etc/keepalived/check_postgres.sh

Cấu hình Keepalived (trên cả .52 và .53):

Sửa /etc/keepalived/keepalived.conf:

vrrp_script chk_postgres {
    script "/etc/keepalived/check_postgres.sh"
    interval 2
    weight 50
}

vrrp_instance VI_DB {
    state MASTER          # Sửa thành BACKUP trên máy .53
    interface ens192      # (Tên interface mạng của bạn, vd: eth0)
    virtual_router_id 51
    priority 150          # Sửa thành 100 trên máy .53
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
        10.221.130.51/24  # (Thêm /prefix, vd /24)
    }
    track_script {
        chk_postgres
    }
}
Quan trọng: Sửa state và priority trên 2 máy như chú thích.

Khởi động Keepalived: systemctl enable --now keepalived

Kiểm tra: Gõ ip a trên cả 2 máy. Bạn sẽ thấy VIP 10.221.130.51 chỉ xuất hiện trên máy Primary (.52).

Giai đoạn 3: Cấu hình HA cho Reverse Proxy
Phần này đơn giản hơn vì Nginx là stateless.

Cấu hình Keepalived (trên .45 và .46):

Sửa /etc/keepalived/keepalived.conf:

vrrp_instance VI_PROXY {
    state MASTER          # Sửa thành BACKUP trên máy .46
    interface ens192      # (Tên interface mạng)
    virtual_router_id 50
    priority 150          # Sửa thành 100 trên máy .46
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
        10.221.130.44/24  # (Thêm /prefix)
    }
    # Có thể thêm script check nginx nếu muốn
}
Khởi động Keepalived: systemctl enable --now keepalived

Kiểm tra: Gõ ip a. Bạn sẽ thấy VIP 10.221.130.44 trên máy .45.

Giai đoạn 4: Triển khai Docker Compose (Tách file)
Bây giờ bạn có 3 nhóm VM. Bạn sẽ chạy Docker Compose trên cả hai VM trong mỗi nhóm (tổng cộng 6 VM).

4.1. Vấn đề Đồng bộ Dữ liệu (Stateful Services)
stepca (stepca_data): Cần đồng bộ chứng chỉ.

nginx (./certs/nginx): Cần đồng bộ chứng chỉ.

Giải pháp (Khuyến nghị): Dùng NFS hoặc GlusterFS được cung cấp bởi OpenStack (nếu có) hoặc tự cài đặt.

Cách đơn giản (NFS):

Chọn 1 máy (ví dụ .47) làm NFS Server: dnf install -y nfs-utils, systemctl enable --now nfs-server.

Tạo thư mục: mkdir -p /shared/stepca và /shared/nginx_certs

Sửa /etc/exports:

/shared/stepca    10.211.130.48(rw,sync,no_root_squash)
/shared/nginx_certs 10.211.130.45(rw,sync,no_root_squash) 10.211.130.46(rw,sync,no_root_squash)
exportfs -a

Trên client (.48): mount 10.211.130.47:/shared/stepca /mnt/stepca

Trên client (.45, .46): mount <IP_NFS_SERVER>:/shared/nginx_certs /mnt/nginx_certs

4.2. File Compose và Biến Môi trường (.env)
Tạo 3 bộ thư mục dự án trên các VM tương ứng.

1. Nhóm Admin API (trên .49 và .50):

docker-compose.admin.yml (Chỉ chứa keycloak và api-backend)

File .env (quan trọng nhất):

Đoạn mã

# Database
POSTGRES_DSN=...host=10.221.130.51... # <--- SỬ DỤNG DB VIP
KC_DB_URL=jdbc:postgresql://10.221.130.51:5432/${KEYCLOAK_DB} # <--- SỬ DỤNG DB VIP

# OIDC/URLs (Trỏ về VIP của PROXY)
OIDC_ISSUER=https://10.221.130.44/auth/realms/vt-audit # <--- SỬ DỤNG PROXY VIP
STEPCA_EXTERNAL_URL=https://10.221.130.44:8443/step-ca # <--- SỬ DỤNG PROXY VIP

# Kết nối nội bộ (vẫn dùng IP thật)
STEPCA_URL=https://10.211.130.47:9000 # Hoặc 48
Chạy docker compose up -d trên cả hai máy .49 và .50.

2. Nhóm Agent API (trên .47 và .48):

docker-compose.agent.yml (Chứa stepca, api-agent, enroll-gateway)

Sửa volumes cho stepca:

YAML

volumes:
  - /mnt/stepca:/home/step # Sử dụng NFS đã mount
File .env:

Đoạn mã

POSTGRES_DSN=...host=10.221.130.51... # <--- SỬ DỤNG DB VIP
STEPCA_DNS_NAMES=10.211.130.47,10.211.130.48,10.221.130.44 # (Thêm các IP/VIP)
Chạy docker compose up -d trên cả hai máy .47 và .48.

3. Nhóm Reverse Proxy (trên .45 và .46):

docker-compose.proxy.yml (Chứa nginx, oidc-proxy, nginx-certs)

Sửa volumes cho nginx và nginx-certs:

YAML

volumes:
  - /mnt/nginx_certs:/certs # (nginx-certs)
  - /mnt/nginx_certs:/etc/nginx/certs:ro # (nginx)
Chạy docker compose run --rm nginx-certs 1 lần trên máy .45 để tạo cert.

File .env:

Đoạn mã

OAUTH2_PROXY_OIDC_ISSUER_URL=http://10.211.130.49:8080/realms/vt-audit # <--- Trỏ về 1 IP thật
Cập nhật nginx.conf (QUAN TRỌNG): Bạn phải cấu hình Nginx để Load Balance (cân bằng tải) giữa 2 VM backend.

Nginx

# Thêm vào đầu file nginx.conf (phần http)
upstream admin_api_backend {
    server 10.211.130.49:8081; # VM Admin 1
    server 10.211.130.50:8081; # VM Admin 2
}
upstream agent_api_backend {
    server 10.211.130.47:8080; # VM Agent 1
    server 10.211.130.48:8080; # VM Agent 2
}
upstream keycloak_backend {
    server 10.211.130.49:8080; # VM Admin 1
    server 10.211.130.50:8080; # VM Admin 2
}
# ... (tương tự cho các service khác)

# Sửa các lệnh proxy_pass của bạn
# Ví dụ:
location / {
  # proxy_pass http://oidc-proxy:4180;
  # Cấu hình oidc-proxy:
  proxy_pass http://127.0.0.1:4180; # (oidc-proxy vẫn chạy local trên VM này)
}

# Sửa file cấu hình oidc-proxy.cfg
# --upstream=http://api-backend:8081
# Đổi thành:
--upstream=http://admin_api_backend # (Trỏ về upstream Nginx, Nginx sẽ pass tiếp)
# HOẶC cấu hình oauth2-proxy để trỏ về 2 máy:
# --upstream=http://10.211.130.49:8081 --upstream=http://10.211.130.50:8081
Chạy docker compose up -d trên cả hai máy .45 và .46.

Giai đoạn 5: Kiểm tra (Verification)
Kiểm tra VIP:

ip a | grep 10.221.130.44 (Chỉ thấy trên .45)

ip a | grep 10.221.130.51 (Chỉ thấy trên .52)

Kiểm tra HA (Failover):

Trên .45, chạy systemctl stop keepalived.

Kiểm tra lại: ip a | grep 10.221.130.44 (Bây giờ phải thấy trên .46).

Start lại keepalived, VIP sẽ trả về .45.

Kiểm tra Ứng dụng:

Truy cập https://10.221.130.44 (Proxy VIP) từ trình duyệt. Đây là điểm truy cập duy nhất của người dùng. Hệ thống phải hoạt động.

Kiểm tra DB:

Từ một VM Admin (.49), kết nối Postgres đến DB VIP: psql -h 10.221.130.51 -U ${POSTGRES_USER} -d ${POSTGRES_DB}

Kết nối phải thành công.