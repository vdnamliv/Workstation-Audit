# VT Audit Platform

This repository ships two deliverables:

1. **VT Agent (Windows)** – distributed as an MSI that installs the background service and a CLI for one-off audits. The agent now bootstraps against a Step-CA authority using short-lived JWTs and authenticates to the platform exclusively with mutual TLS.
2. **VT Server stack** – a docker-compose deployment that contains the gateway, Step-CA, vt-server API processes, oauth2-proxy, Keycloak, PostgreSQL, and a static dashboard shell.

---

## 1. Agent packaging & behaviour

### 1.1 MSI contents

The WiX project under `packaging/wix/` produces `VTAgent.msi`. Ensure the following artefacts are bundled:

| File | Purpose | Location after install |
|------|---------|------------------------|
| `agent.exe` | Windows agent binary | `%ProgramFiles%\VT Agent\agent.exe` |
| `config.json` | Agent configuration (see sample below) | `%ProgramFiles%\VT Agent\config.json` |
| `ca.pem` | Public cert for the external gateway TLS certificate | `%ProgramFiles%\VT Agent\ca.pem` |

Sample configuration shipped with the MSI:

```json
{
  "server": "https://gateway.local/agent",
  "ca_file": "ca.pem",
  "bootstrap_token": "change-me-bootstrap",
  "insecure_skip_verify": false
}
```

`agent.exe` resolves the CA file in this order:

1. Absolute path supplied in the config.
2. Next to the executable.
3. `%ProgramFiles%\VT Agent` (installed location).

### 1.2 Service mode

During installation the MSI should register the service. Manual installation remains possible:

```powershell
sc.exe create VTAgent binPath= "\"%ProgramFiles%\VT Agent\agent.exe\" service --action run --server https://gateway.local/agent --ca-file ca.pem --bootstrap-token change-me-bootstrap" start= auto
sc.exe start VTAgent
```

`service --action run` performs the following:

1. Validates `config.json` and the CA file.
2. Ensures a non-exportable RSA key exists in the Windows machine store.
3. Calls `/agent/bootstrap/ott` with the `bootstrap_token` to obtain a short-lived JWT signed with the Step-CA JWK provisioner.
4. Submits the CSR directly to Step-CA (proxied via the gateway) and stores the issued certificate in the Windows cert store.
5. Enrols with the vt-server agent API over mTLS and enters the policy/result loop (the poll interval is dictated by the server and defaults to 30s).

### 1.3 Local CLI mode

The CLI reuses the same certificate as the service. If none exists it will execute the bootstrap flow before running the audit.

```powershell
cd "%ProgramFiles%\VT Agent"
./agent.exe --local --html
```

### 1.4 Building the MSI

```powershell
cd packaging\wix
./build.ps1    # Produces VTAgent.msi in the same folder
```

Copy `agent.exe`, `config.json`, and `ca.pem` into `packaging/wix/bin/` (or whichever directory your WiX fragments reference) before invoking the build.

---

## 2. Server architecture

The refreshed compose stack contains the services below. Only the consolidated gateway exposes port 443 to the outside world; everything else stays on the internal `backend` network.

| Service | Container | Ports | Responsibility |
|---------|-----------|-------|----------------|
| **gateway** | `nginx:alpine` | `443/tcp` (external) | Terminates TLS, verifies client certs, proxies `/agent/*` to api-agent, `/dashboard/*` to oauth2-proxy/static assets, and `/step-ca/*` to the Step-CA instance |
| **stepca** | `smallstep/step-ca` | `9000/tcp` (backend only) | Issues agent certificates using a JWK provisioner |
| **api-agent** | `vt-server --mode agent` | `8080/tcp` (internal) | Agent enrolment, policy distribution, result ingestion |
| **api-user** | `vt-server --mode dashboard` | `8081/tcp` (internal) | Dashboard & policy APIs secured by oauth2-proxy |
| **oidc-proxy** | `quay.io/oauth2-proxy/oauth2-proxy` | `4180/tcp` (internal) | Handles `/dashboard/api/*` requests after authenticating via Keycloak |
| **dashboard** | `nginx` serving static files | `80/tcp` (internal) | Placeholder SPA that talks to the proxy |
| **keycloak** | `quay.io/keycloak/keycloak` | `8080/tcp` (internal) | Identity provider and OAuth/OIDC issuer |
| **postgres** | `postgres:16-alpine` | `5432/tcp` (internal) | Stores audit results and policy history |

Traffic flows:

- **Agents** → `https://gateway/agent/*` (mTLS) → `api-agent` → PostgreSQL.
- **Certificates**: Agents call `https://gateway/agent/bootstrap/ott` (no TLS client cert yet) to obtain a Step-CA token, then `https://gateway/step-ca/1.0/sign` to fetch their mTLS certificate.
- **Admins** → `https://gateway/dashboard/` (TLS) → oauth2-proxy → Keycloak → `api-user` → PostgreSQL.

`env/conf/gateway/nginx.conf` owns the routing rules. The gateway mounts:

- `env/conf/gateway/issuer/` for its own server certificate and key (`server.pem`/`server.key`).
- The Step-CA volume (`stepca_data`) to trust `certs/root_ca.crt` when validating agent certificates.

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

Edit `env/.env` and provide production-ready secrets:

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

# Step-CA bootstrap (used on first launch)
STEPCA_NAME=VT-Audit CA
STEPCA_DNS_NAMES=gateway.local,stepca
STEPCA_PROVISIONER=bootstrap@vt-audit
STEPCA_PASSWORD=ChangeMe123!
STEPCA_URL=https://stepca:9000
STEPCA_EXTERNAL_URL=https://gateway.local/step-ca
STEPCA_KEY_PATH=/stepca/secrets/provisioner_key

# Agent credentials
AGENT_BOOTSTRAP_TOKEN=change-me-bootstrap
MTLS_CERT_TTL=24h

# OIDC integration inside vt-server
OIDC_ISSUER=http://keycloak:8080/realms/vt-audit
OIDC_ADMIN_ROLE=admin
```

`STEPCA_KEY_PATH` points at the encrypted JWK stored by the Step-CA container. `vt-server` mounts the same volume read-only and decrypts the key using `STEPCA_PASSWORD` so it can mint JWTs for enrolling agents.

### 3.3 Gateway TLS assets

Place the public certificate chain and private key used by the gateway under `env/conf/gateway/issuer/`:

```bash
cd /opt/vt-audit
cp /secure/path/server.pem env/conf/gateway/issuer/
cp /secure/path/server.key env/conf/gateway/issuer/
```

`server.pem` should contain the full chain presented to browsers/agents. The Step-CA root (`certs/root_ca.crt`) is generated automatically and mounted into the gateway – no manual copy is required.

A helper script is available if you want to create self-signed assets for a lab:

```bash
./scripts/generate-mtls-assets.sh   # writes into env/conf/gateway/issuer/
```

### 3.4 Local smoke-test with Docker Desktop / WSL2

1. **Hosts file** – map `gateway.local` to `127.0.0.1` so the sample certificates validate. On Windows (administrator PowerShell):

   ```powershell
   Add-Content -Path C:\Windows\System32\drivers\etc\hosts "127.0.0.1 gateway.local"
   ```

2. **Bootstrap**

   ```powershell
   cd env
   copy .env .env.local
   docker compose --env-file .env.local build
   docker compose --env-file .env.local up -d
   ```

3. **Validate**
   * Browse to `https://gateway.local/dashboard/` and authenticate via Keycloak.
   * Install the Windows agent MSI or run the binary directly with the sample config. On first contact it will request an OTT, mint a certificate via Step-CA, and then enrol over mTLS.
   * Inspect results: `docker compose exec postgres psql -U audit -d audit -c "select * from audit.results limit 5"`.

Stop the stack with `docker compose down` when finished.

---

## 4. Repository layout (quick reference)

- `agent/` – Windows agent sources.
- `server/` – vt-server sources shared by both API modes.
- `env/` – docker-compose manifests, configuration, and dashboard shell.
- `scripts/` – helper scripts (certificate generation, etc.).

---

Happy auditing! :)
