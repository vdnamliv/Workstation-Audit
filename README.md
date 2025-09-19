# VT Audit Platform

This repository contains two deliverables:

1. **VT Agent (Windows)** – distributed as an MSI that installs a background service and the CLI for local audits. The agent authenticates exclusively with mutual TLS.
2. **VT Server** – a set of containerised services (Nginx mTLS gateway, Keycloak, oauth2-proxy, vt-server API processes, PostgreSQL, Step-CA, and a dashboard placeholder) intended to run on Rocky Linux 8.

---

## 1. Agent packaging & behaviour

### 1.1 MSI contents

The WiX project under `packaging/wix/` produces `VTAgent.msi`. The MSI must include:

| File | Purpose | Location after install |
|------|---------|------------------------|
| `agent.exe` | Windows agent binary | `%ProgramFiles%\VT Agent\agent.exe` |
| `config.json` | Agent configuration (see below) | `%ProgramFiles%\VT Agent\config.json` |
| `ca.pem` | CA that signs both the Nginx gateway and the agent client certificates | `%ProgramFiles%\VT Agent\ca.pem` |

The WiX fragments `Folders.wxs`, `Components.wxs`, and `product.wxs` already contain the directory layout and shortcuts – just ensure you add the PEM to the components list. A sample `config.json` that ships with the MSI:

```json
{
  "server": "https://agent-gateway.local",
  "ca_file": "ca.pem",
  "insecure_skip_verify": false
}
```

`agent.exe` now resolves CA paths in this order:

1. Absolute path (`ca_file` already points to a fully qualified location).
2. `agent.exe` directory.
3. `%ProgramFiles%\VT Agent`.

This allows you to ship the PEM alongside the executable without worrying about working directories.

### 1.2 Service mode

During installation the MSI should register the service. The agent can also do it manually:

```powershell
sc.exe create VTAgent binPath= "\"%ProgramFiles%\VT Agent\agent.exe\" service --action run --server https://agent-gateway.local --ca-file ca.pem" start= auto
sc.exe start VTAgent
```

`service --action run` performs the following:

1. Ensures `config.json` is valid and the CA exists.
2. Provisions a non-exportable RSA key in the Windows Software KSP (with automatic fallback to the current user profile if machine scope is forbidden) and requests a certificate from vt-server.
3. Stores the issued certificate in the Windows certificate store.
4. Enrols with vt-server over mTLS (no shared keys).
5. Runs the audit loop. The polling interval is dictated by the server (`/enroll` response, default 30s).

### 1.3 Local CLI mode

Local runs fetch live policy from the server (still over mTLS) and write the report to disk:

```powershell
cd "%ProgramFiles%\VT Agent"
./agent.exe --local --html
# Other formats
./agent.exe --local --json
./agent.exe --local --excel
```

The agent reuses the same certificate as the service. If none is present it will auto-enrol before running the audit.

### 1.4 Building the MSI

```powershell
cd packaging\wix
./build.ps1    # Produces VTAgent.msi in the same folder
```

Ensure `agent.exe`, `config.json`, and `ca.pem` have been copied to `packaging/wix/bin/` (or whichever directory your WiX fragments reference) before invoking the build.

---

## 2. Server architecture

![](image/workflow.png)

Component summary:

| Service | Container | Port | Responsibility |
|---------|-----------|------|----------------|
| **mtls-gateway** | `nginx` | 443 | Terminates mTLS, validates agent certificates, forwards to api-agent, injects identity headers |
| **api-agent** | `vt-server --mode agent` | 8080 (internal) | Handles `/agent/*` endpoints (enrolment, policy fetch, results), talks to PostgreSQL |
| **api-user** | `vt-server --mode dashboard` | 8081 (internal) | Admin/API surface for dashboards and policy management |
| **oidc-proxy** | `oauth2-proxy` | 8443 | Presents the admin portal, performs OIDC auth against Keycloak, forwards to dashboard + api-user |
| **dashboard** | `nginx` serving static assets | 3000 (internal) | Placeholder front-end, replace with your build |
| **keycloak** | `keycloak` | 8080 | Identity provider, federated with LDAP/AD |
| **postgres** | `postgres` | 5432 | Stores audit + policy schemas |
| **step-ca** | `smallstep/step-ca` | 9000 | Issues and revokes agent certificates |

All services communicate on the `backend` Docker network. `mtls-gateway` and `oidc-proxy` also join `frontend` to expose 443/8443 externally.

---

## 3. Deployment on Rocky Linux 8

### 3.1 Prerequisites

```bash
sudo dnf install -y yum-utils
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
```

### 3.2 Environment variables

Edit `env/.env` and provide safe values:

```env
# PostgreSQL
POSTGRES_USER=audit
POSTGRES_PASSWORD=ChangeMe123!
POSTGRES_DB=audit
POSTGRES_DSN=postgres://audit:ChangeMe123!@postgres:5432/audit?sslmode=disable

# Keycloak
KEYCLOAK_DB=keycloak
KEYCLOAK_DB_USER=keycloak
KEYCLOAK_DB_PASSWORD=ChangeMe123!
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=ChangeMe123!
KEYCLOAK_REALM=vt-audit

# oauth2-proxy
OIDC_CLIENT_ID=dashboard-proxy
OIDC_CLIENT_SECRET=<replace with Keycloak client secret>
OIDC_COOKIE_SECRET=<32-byte base64>

# Step-CA (used if you want to bootstrap a new authority)
STEPCA_NAME=VT-Audit CA
STEPCA_DNS_NAMES=agent-gateway.local,stepca
STEPCA_PROVISIONER=bootstrap@vt-audit
STEPCA_PASSWORD=ChangeMe123!

# Agent certificate lifetime
MTLS_CERT_TTL=24h
```

Clone the repository to `/opt/vt-audit` (or similar) and copy your TLS assets:

```bash
cd /opt/vt-audit
cp /secure/path/ca.pem env/conf/mtls/issuer/
cp /secure/path/ca.key env/conf/mtls/issuer/
cp /secure/path/server.pem env/conf/mtls/issuer/
cp /secure/path/server.key env/conf/mtls/issuer/
```

> **Tip:** `server.pem` should contain the full chain presented to agents (gateway leaf + any intermediates). `ca.pem` is the issuing CA used to sign agent certificates.

### 3.3 Creating TLS assets from scratch

If you do not already have certificates, you can create a full mTLS toolchain using either OpenSSL or `step-cli`. Pick one of the following approaches and copy the resulting files into `env/conf/mtls/issuer/` as described above.

### 3.4 Local smoke-test with Docker Desktop / WSL2

You can verify the stack end-to-end on your workstation before shipping to a server. The demo Keycloak realm already contains an `admin/admin` user with the `admin` role.

1. **Prerequisites**
   * Docker Desktop on Windows/macOS or Docker Engine inside WSL2.
   * Update your hosts file so `agent-gateway.local` and `dashboard.local` resolve to `127.0.0.1` (these names are baked into the sample certificates). On Windows run PowerShell as Administrator:

     ```powershell
     Add-Content -Path C:\Windows\System32\drivers\etc\hosts "127.0.0.1 agent-gateway.local"
     Add-Content -Path C:\Windows\System32\drivers\etc\hosts "127.0.0.1 dashboard.local"
     ```

     (Reverse the change after testing.)

2. **Prepare environment variables**

   ```powershell
   cd env
   copy .env .env.local        # adjust secrets if needed
   $Env:COMPOSE_FILE="docker-compose.yml"
   $Env:COMPOSE_PROJECT_NAME="vt-audit-local"
   docker compose --env-file .env.local build
   docker compose --env-file .env.local pull      # optional refresh of official images
   docker compose --env-file .env.local up -d
   ```

3. **Validate services**
   * Visit https://dashboard.local:8443/ (accept the self-signed cert if prompted) and authenticate through Keycloak (`http://localhost:8080/`).
   * Run the Windows agent:

     ```powershell
     cd "%ProgramFiles%\VT Agent"
     .gent.exe -once -server https://agent-gateway.local/agent -ca-file ca.pem
     ```

     Audit results should appear in the `audit.results` table (`docker compose exec postgres psql -U audit -d audit -c "select * from audit.results"`).

4. **Tear down**

   ```powershell
   docker compose --env-file .env.local down -v
   ```

The same `docker compose build/up` commands are used on the production server, ensuring image parity between local smoke-tests and deployment.


#### Option A: OpenSSL

```bash
# 1. Create a private CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -out ca.pem -days 3650   -subj "/C=VN/ST=Hanoi/L=Hanoi/O=VT Audit/CN=VT Audit Root CA"

# 2. Issue a certificate for the mTLS gateway
openssl genrsa -out server.key 2048
cat > server.cnf <<'EOF'
[req]
distinguished_name=req
req_extensions=v3_req
prompt=no
[req_distinguished_name]
C=VN
ST=Hanoi
L=Hanoi
O=VT Audit
CN=agent-gateway.local
[v3_req]
subjectAltName=DNS:agent-gateway.local,DNS:dashboard.local,IP:127.0.0.1
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
openssl req -new -key server.key -out server.csr -config server.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial   -out server.pem -days 825 -extensions v3_req -extfile server.cnf
```

#### Option B: step-cli

```bash
# Install step-cli on Rocky 8
dnf install -y https://github.com/smallstep/cli/releases/download/v0.25.2/step-cli_0.25.2_linux_amd64.rpm

# 1. Bootstrap a CA
step ca init --name "VT Audit" --dns agent-gateway.local --address :9000 --provisioner admin@vt-audit   --root ca.pem --key ca.key --password-file password.txt
# (see https://github.com/smallstep/certificates for more options)

# 2. Create an nginx/server certificate signed by the CA
step ca certificate agent-gateway.local server.pem server.key   --san dashboard.local --san 127.0.0.1 --root ca.pem --key ca.key --offline   --password-file password.txt
```

After generating the files, place them in `env/conf/mtls/issuer/` and restart the stack:

```bash
cp ca.pem ca.key server.pem server.key env/conf/mtls/issuer/
cd env
docker compose restart mtls-gateway api-agent
```



### 3.5 Container images & configuration

* `env/docker/Dockerfile.vt-server` builds the Go server once and reuses it for both api services.
* `env/conf/mtls/nginx.conf` defines the gateway. Adjust upstream hostnames if you rename services.
* `env/conf/oidc/oauth2-proxy.cfg` holds the oauth2-proxy runtime settings (callback URL, domains, etc.).
* `env/conf/postgres/init/00_init.sql` seeds the audit & policy schemas.
* `env/dashboard/` contains a placeholder static dashboard – replace `www/` with your built SPA or adjust the Dockerfile.

### 3.6 Bring-up

On both your test machine and the production server use the same commands:

```bash
cd env
docker compose build        # builds vt-server + dashboard images
docker compose pull         # optional: refresh official images (postgres, nginx, keycloak, ...)
docker compose up -d        # start the full stack
```

Containers:

```bash
docker compose ps
```

Logs (tailing the gateway and agent API):

```bash
docker compose logs -f mtls-gateway api-agent
```

### 3.7 Reverse proxy certificates

`env/conf/mtls/issuer/` must contain:

| File | Purpose |
|------|---------|
| `ca.pem` | Issuing CA for agents (used by vt-server & shipped to agents) |
| `ca.key` | Private key for the CA (vt-server accesses it to sign CSRs) |
| `server.pem` | Nginx certificate presented on 443 |
| `server.key` | Matching private key |

### 3.8 PostgreSQL hardening

* Create a dedicated `audit` user and restrict host-based auth (`pg_hba.conf`).
* Consider enabling `pgcrypto` and `uuid-ossp` extensions if you store sensitive data.
* Add PgBouncer in front of PostgreSQL for large fleets.

### 3.9 Keycloak setup

The compose file loads `env/conf/keycloak/vt-audit-realm.json` on first start. It provisions:

* Realm `vt-audit`
* Roles `admin`, `auditor`, `viewer`
* Confidential client `dashboard-proxy` (secret `dashboard-secret`)
* Demo user `admin/admin` with the `admin` role

To customise the realm, edit the JSON or replace it with your own export. After the initial import you can manage everything via the Keycloak admin console (`http://<host>:8080/`). For production, change the default password and configure LDAP/AD federation as needed.

### 3.10 oauth2-proxy

The container reads `/etc/oauth2-proxy.cfg`. Adjust:

* `redirect_url` to match your public dashboard hostname.
* `whitelist_domains` to the cookie domain (e.g., `.example.com`).

Restart the service after changes:

```bash
cd env
docker compose restart oidc-proxy
```

### 3.11 Dashboard/static assets

Replace `env/dashboard/www` with the compiled assets of your real UI. If you prefer a different runtime (Next.js, etc.), modify `env/dashboard/Dockerfile` accordingly.

---

## 4. Agent → server flow

1. **CSR** – agent generates a key in the Software KSP. If machine scope is unavailable it falls back to a user profile automatically.
2. **Issuance** – `vt-server --mode agent` signs the CSR using the CA from `/certs/ca.{pem,key}`.
3. **mTLS gateway** – agents reach `https://agent-gateway.your-domain:443/agent/...`. Nginx validates the certificate and injects identity headers.
4. **Authorisation** – the Go API maps the certificate subject/serial to an `agent_id` (persisted in PostgreSQL).
5. **Policy + results** – policy is fetched from PostgreSQL; audit results are written back.
6. **Dashboard/API** – oauth2-proxy protects `/api/*` and `/` with Keycloak. `api-user` reads the same PostgreSQL datasets.

---

## 5. Troubleshooting

| Issue | Remedy |
|-------|--------|
| Agent CLI says `ca file not found` | Ensure `ca.pem` exists next to `agent.exe` or update `config.json` with an absolute path. |
| Agent logs `stepca: open key: create key: Invalid flags specified` | Run once as administrator or allow the fallback (current user) produced by the new build; confirm the cert exists in the user store. |
| Nginx rejects agents with 403 | Verify the agent certificate chain against `ca.pem` and confirm `ssl_verify_client on` uses the correct CA. |
| Dashboard loops back to login | Check oauth2-proxy client secret, redirect URI, and Keycloak realm configuration. |
| `api-agent` complains about missing CA key | Mount `ca.key` into `env/conf/mtls/issuer/` and restart the stack. |

---

## 6. Useful commands

```bash
# Tear down
cd env
docker compose down

# Rotate gateway certificate
cd env/conf/mtls/issuer
mv server.pem server.pem.old
mv server.key server.key.old
# copy new files, then restart
cd ../../..
docker compose restart mtls-gateway

# View issued agent certificates via step-ca
curl -s http://localhost:9000/crl
```

With these changes the codebase and deployment assets follow the requested architecture while keeping the agent MSI story aligned with the new mTLS-only workflow.
