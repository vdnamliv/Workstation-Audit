## 1. Gitclone
```
git clone https://github.com/vdnamliv/Workstation-Audit
cd Workstation-Audit
```
## 2. Đổi tên env/.env.example thành .env và sửa các nội dung:
```
# --- MÔI TRƯỜNG & DOMAIN (Sửa mục này khi đổi server) ---
DOMAIN_NAME=gateway.local       # Đổi thành domain thật (VD: audit.company.com)
PUBLIC_PORT=8443                # Đổi thành 443 nếu chạy Production chuẩn
PROTOCOL=https                  

# --- KEYCLOAK ADMIN (Lưu lại để đăng nhập quản trị) ---
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=CHANGE_THIS_SECURE_PASSWORD

# --- OIDC SECRETS ---
OIDC_CLIENT_SECRET=change-me-please
OIDC_COOKIE_SECRET=generate-random-16-chars
```
## 3. Khởi động hệ thống:
- Tại thư mục gốc, chạy lệnh khởi tạo container:
```
# Pull images và khởi chạy
docker compose -f env/docker-compose.yml up -d

# Kiểm tra trạng thái (Đợi khoảng 60s để Keycloak khởi động xong)
docker compose -f env/docker-compose.yml ps
```
- Đảm bảo tất cả container đều ở trạng thái Healthy hoặc Running. Đặc biệt lưu ý vt-keycloak cần thời gian khởi động lâu hơn các service khác.

## 4. Thiết lập Keycloak (Initial Setup)
- Do Keycloak được giấu sau Nginx (/auth), quy trình thiết lập ban đầu cần làm chính xác như sau:
#### Bước 1: Truy cập Admin console:
- URL: https://<DOMAIN_NAME>:<PORT>/auth/admin/
- Ví dụ: https://gateway.local:8443/auth/admin/
- Tài khoản: Dùng KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD trong file .env.
#### Bước 2: Cấu hình Redirect URI (bắt buộc)
- Nếu Realm vt-audit đã được import tự động, bạn cần cập nhật lại đường dẫn redirect để khớp với Domain/Port hiện tại: 
1. Chọn Realm vt-audit (góc trên bên trái).
2. Vào menu Clients > Chọn client dashboard-proxy (hoặc tên client OIDC bạn dùng).
3. Tìm mục Valid Redirect URIs.
4. Thêm/Sửa đường dẫn chính xác (Lưu ý phải có port nếu không dùng 443):
    - Cú pháp: https://<DOMAIN_NAME>:<PORT>/oauth2/callback
    - Ví dụ: https://gateway.local:8443/oauth2/callback
5. Nhấn Save.

#### Bước 3: Tạo tài khoản người dùng:
- Tài khoản Admin không dùng để đăng nhập vào Dashboard nghiệp vụ. Bạn cần tạo User thường.
1. Vào menu Users > Add user.
2. Điền Username (VD: nhanvien1) > Create.
3. Sang tab Credentials > Set password.
4. Điền mật khẩu và Tắt tùy chọn "Temporary" > Save.

## 5. Kiểm tra vận hành
1. Mở trình duyệt, truy cập https://gateway.local:8443
2. Hệ thống tự redirect sang trang login của Keycloak (URL gốc, không lộk port 8080)
3. Đăng nhập bằng tài khoản User vừa tạo ở bước 4.3
4. Đăng nhập thành công --> redirect về dashboard
