## Dựng docker:
1. Gitclone
```
git clone https://github.com/vdnamliv/Workstation-Audit
cd Workstation-Audit
```
2. Đổi tên env/.env.example thành .env và sửa các nội dung
3. Dựng docker:
```
cd env
docker compose up -d
docker ps
```
## Set up môi trường
1. Set up trên Keycloak:
- Truy cập http://<IP Server>:8080 
- Đăng nhập tài khoản keycloak theo trong .env
- Chọn mục vt-audit
- Chọn phần **User** --> add User --> điền Username --> Credential --> Set password --> Cài đặt password và Save