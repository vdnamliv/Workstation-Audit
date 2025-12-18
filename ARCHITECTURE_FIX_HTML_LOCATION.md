# Architecture Fix: HTML nên nằm ở đâu?

## ❌ Cách SAI (ban đầu):

```
deploy/02-nginx-gateway/
└── conf/html/
    ├── index.html          # ❌ Duplicate!
    └── assets/             # ❌ Sai vị trí

Nginx: Vừa reverse proxy, vừa serve static files
```

**Vấn đề:**
- HTML tách biệt với Backend API → khó quản lý version
- Duplicate code: `server/ui/` và `deploy/02-nginx-gateway/conf/html/`
- Nginx làm 2 việc: Reverse proxy + Static file server
- Deploy phức tạp, dễ version mismatch

## ✅ Cách ĐÚNG (đã sửa):

```
server/ui/                  # ✅ Single source of truth
├── index.html
├── policy.html
└── assets/
    ├── css/
    │   └── flowbite.min.css
    └── js/
        ├── alpine.min.js
        ├── flowbite.min.js
        └── tailwindcss.js

Admin API: Serve cả HTML và API
Nginx: Chỉ làm reverse proxy thuần
```

**Ưu điểm:**
- ✅ Frontend và Backend đi chùm → dễ quản lý version
- ✅ Single source of truth → không duplicate
- ✅ Deploy đơn giản: Rebuild admin-api là xong
- ✅ Nginx chỉ làm reverse proxy → Single Responsibility
- ✅ Theo convention: Dashboard frontend/backend cùng service

## 🔄 Luồng Request:

### Trước (SAI):
```
Browser
  → Nginx:9444/ (serve HTML từ /usr/share/nginx/html)
  → Nginx:9444/api/ (proxy sang admin-api:8081)
```

### Sau (ĐÚNG):
```
Browser
  → Nginx:9444/ (proxy pass)
  → Admin-API:8081/app/ (serve HTML + assets)
  → Admin-API:8081/api/ (serve API)
```

## 📝 Các thay đổi đã thực hiện:

### 1. Di chuyển assets về đúng vị trí:
```bash
server/ui/assets/      # ✅ Nơi đúng
  ├── css/
  │   └── flowbite.min.css
  └── js/
      ├── alpine.min.js
      ├── flowbite.min.js
      └── tailwindcss.js
```

### 2. Cập nhật HTML references:
```html
<!-- Cũ (CDN) -->
<script src="https://cdn.tailwindcss.com"></script>

<!-- Mới (Local) -->
<script src="/app/assets/js/tailwindcss.js"></script>
```

### 3. Cập nhật docker-compose của admin-api:
```yaml
volumes:
  - ../../rules:/rules:ro
  - ../../server/ui:/app/ui:ro  # ✅ Mount UI directory
```

### 4. Đơn giản hóa nginx config:
```nginx
# Xóa bỏ
location /assets/ { ... }  # ❌ Không cần nữa

# Giữ lại
location / {
  proxy_pass http://api_backend;  # ✅ Admin API tự serve tất cả
}
```

### 5. Xóa duplicate trong nginx:
```bash
# ❌ Không cần nữa
deploy/02-nginx-gateway/conf/html/
```

## 🚀 Deployment:

### Server .49 (Admin API):
```bash
cd /root/vt-audit/deploy/03-admin-api
docker compose down
docker compose build  # Rebuild để include UI changes
docker compose up -d

# Test
curl http://localhost:8081/app/
curl http://localhost:8081/api/health
```

### Server .45/.46 (Nginx Gateway):
```bash
cd /root/vt-audit/deploy/02-nginx-gateway
docker compose restart

# Nginx giờ chỉ proxy, không serve HTML
```

## 📋 URL Structure:

```
https://10.211.130.44:9444/
  ├── /                    → admin-api:8081/app/     (HTML)
  ├── /app/                → admin-api:8081/app/     (HTML + assets)
  ├── /app/assets/         → admin-api:8081/app/assets/ (CSS/JS)
  ├── /api/                → admin-api:8081/api/     (JSON API)
  ├── /auth/               → keycloak:8080/auth/     (OIDC)
  └── /oauth2/             → oauth2-proxy (future)
```

## ✅ Checklist:

- [x] Assets copied từ nginx về server/ui
- [x] HTML updated với local paths (/app/assets/)
- [x] docker-compose.yml mount ../../server/ui
- [x] nginx config simplified (xóa location /assets/)
- [x] docker-compose.yml nginx (xóa html mount)
- [ ] Rebuild admin-api container
- [ ] Test trên server production

## 🎯 Kết quả:

**Kiến trúc sạch hơn:**
- Nginx: Reverse proxy only
- Admin API: Serve frontend + backend
- Single source of truth: server/ui/
- Dễ maintain và deploy

**Performance:**
- Go's http.FileServer rất nhanh cho static files
- Có thể thêm caching layer sau nếu cần
- Không ảnh hưởng đến performance

## 📞 Notes:

Đây là **Best Practice** cho monolithic web app:
- Frontend và Backend cùng codebase
- Build và deploy cùng nhau
- Version sync tự động
- Đơn giản, dễ maintain

Chỉ tách riêng khi:
- Có dedicated CDN
- Frontend là SPA hoàn toàn độc lập
- Team frontend/backend riêng biệt
