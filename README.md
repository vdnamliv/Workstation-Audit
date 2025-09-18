# VT Audit Platform

This repository contains the Windows agent that collects workstation posture and the Go server that exposes agent APIs, a dashboard, and Step-CA style certificate issuing. The platform now relies exclusively on mutual TLS for agent authentication; the legacy shared *enrollment key* has been removed.

## Architectural overview

```
Agent (Windows) --mTLS--> NGINX gateway (443) --> vt-server (agent API) --> PostgreSQL
                                                 \
                                                  -> vt-server (dashboard API) -- OAuth2 proxy --> Keycloak
```

* The vt-server binary can run in `agent`, `dashboard`, or `all` modes. In Docker we run two dedicated containers.
* Agents generate a CSR on first run. vt-server signs the CSR with the CA material you provide and stores the issued cert in the Windows *LocalMachine* store (falling back to *CurrentUser* when the process lacks permission).
* All REST calls (`/enroll`, `/policy/*`, `/results`) now require mTLS. Agent identity is derived from the certificate Common Name.
* Agent secrets are still stored so that the server can authorise calls that are fronted by a proxy. They are delivered only after a successful mTLS handshake.

## Building from source

```powershell
# from repo root
$env:CGO_ENABLED=0
go build -o server.exe ./server/cmd/vt-server
go build -o agent.exe  ./agent/cmd/vt-agent
```

Run the tests:

```powershell
go test ./...
```

## Certificate material

vt-server will sign agent CSRs using whatever CA/key you provide. You also need a server certificate for the NGINX gateway.

1. Create a CA (you can use `step-cli` or OpenSSL). Example with OpenSSL:

   ```powershell
   openssl genrsa -out ca.key 4096
   openssl req -x509 -new -nodes -key ca.key -sha256 -days 1095 -out ca.pem \
       -subj "/CN=VT Audit Root CA"
   ```

2. Issue a leaf certificate for the gateway:

   ```powershell
   openssl genrsa -out gateway.key 2048
   openssl req -new -key gateway.key -out gateway.csr -subj "/CN=agent-gateway.local"
   openssl x509 -req -in gateway.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out gateway.pem -days 825 -sha256
   ```

3. Drop the files into `env/conf/mtls/issuer/`:

   ```text
   env/conf/mtls/issuer/
     ├── ca.pem          # CA certificate shared with agents
     ├── ca.key          # CA private key used by vt-server to mint client certs
     ├── server.pem      # Gateway certificate (what nginx serves on 443)
     └── server.key      # Gateway private key
   ```

4. Copy `ca.pem` next to `agent.exe` (or into your MSI) – the sample `config.json` assumes the file name.

## Agent configuration & packaging

`config.json` lives beside `agent.exe` (the agent also searches `%ProgramFiles%\VT Agent\config.json`).

```json
{
  "server": "https://agent-gateway.local",
  "ca_file": "ca.pem",
  "insecure_skip_verify": false
}
```

* `server` – the public URL that resolves to the mTLS gateway.
* `ca_file` – PEM bundle used to trust that gateway and to pin the issuing CA.
* `insecure_skip_verify` – keep `false` outside of development.

### Installing as a Windows service

```powershell
sc.exe create VTAgent binPath= "C:\\Program Files\\VT Agent\\agent.exe service --action run --server https://agent-gateway.local --ca-file ca.pem" start= auto
sc.exe start VTAgent
```

On first start the agent writes its issued client certificate into the Windows certificate store; no files are created on disk.

## Local testing without Docker

1. Launch vt-server in *all* mode with the CA/key you prepared:

   ```powershell
   .\server.exe --mode all \`
       --agent-addr :8444 \`
       --dashboard-addr :8081 \`
       --db "postgres://user:pass@localhost:5432/vta?sslmode=disable" \`
       --mtls-ca ca.pem \`
       --mtls-ca-key ca.key
   ```

2. Run the agent once:

   ```powershell
   .\agent.exe -once -server https://localhost:8444 -ca-file ca.pem
   ```

3. Produce an offline report:

   ```powershell
   .\agent.exe --local --html -server https://localhost:8444 -ca-file ca.pem
   ```

## Docker deployment

`env/docker-compose.yml` now mirrors the architecture diagram. Services:

| Service          | Purpose                                                   |
|------------------|-----------------------------------------------------------|
| `db`             | PostgreSQL backing store                                  |
| `agent_api`      | `vt-server --mode agent`                                  |
| `dashboard_api`  | `vt-server --mode dashboard`                              |
| `mtls_gateway`   | NGINX terminating TLS and enforcing client certificates   |
| `dashboard_oidc` | `oauth2-proxy` protecting the dashboard (Keycloak IdP)    |
| `keycloak`       | Identity provider for admins                              |

### Prerequisites

* Docker 24+
* Docker Compose V2
* Populate `env/conf/mtls/issuer/` with `ca.pem`, `ca.key`, `server.pem`, `server.key` (see above).
* Update `env/.env` with strong secrets (default values are placeholders).

### Start the stack

```powershell
cd env
docker compose up --build
```

The following endpoints become available:

* `https://localhost/` – mTLS gateway for agents (requires certificates issued from `ca.pem`).
* `https://localhost:8443/` – dashboard behind OAuth2 (Keycloak login at `http://localhost:8080`).

### Updating configuration

* The vt-server containers read `/app/rules` from the build context; edit `rules/windows.yml` and rebuild to ship policy updates.
* NGINX config lives at `env/conf/mtls/nginx.conf`. Adjust upstream ports if you change container ports.
* `dashboard_oidc` consumes `DASHBOARD_CLIENT_ID`, `DASHBOARD_CLIENT_SECRET`, and `DASHBOARD_COOKIE_SECRET` from `.env`. Create a confidential client in Keycloak matching those values.

## mTLS flow explained

1. **Bootstrap** – the agent spins up without a certificate. `newServerHTTPClient` calls `stepca.New` which creates a CSR using a non-exportable key stored in the Windows Software Key Storage Provider. If machine-scope key creation is denied, the agent automatically falls back to a user-scoped key (resolves the previous `Invalid flags specified` error).
2. **Issuance** – vt-server signs the CSR with the CA key you mounted (`--mtls-ca-key`). The certificate lands in the Windows LocalMachine\MY store (or CurrentUser when falling back).
3. **Enrollment** – the agent calls `/enroll` over mTLS. The server maps the TLS certificate Common Name to an agent record and returns the agent ID + secret which are encrypted via DPAPI on disk.
4. **Steady state** – all subsequent calls reuse the cached certificate. When the certificate is within 12h of expiry the agent transparently re-issues.

## Packaging checklist

| Artifact                     | Purpose                                      |
|------------------------------|----------------------------------------------|
| `agent.exe`                  | Windows agent binary                         |
| `config.json`                | Points the agent at your gateway + CA file   |
| `ca.pem`                     | Same CA file NGINX trusts (ship read-only)   |
| `VTAgent.msi` (optional)     | Built with WiX; include the files above      |

Ensure `%ProgramFiles%\VT Agent\pki` is writable by LocalSystem; the agent will cache its public certificate there if the KSP returns a file path.

## Troubleshooting

* **`stepca: open key: create key: Invalid flags specified.`** – occurs when the process cannot create machine-level keys. The new logic falls back to user scope automatically; confirm the agent now proceeds. If you need machine scope, run the service under `LocalSystem` or grant the account `SeMachineAccountPrivilege`.
* **Agents rejected with `client certificate required`** – verify that NGINX mounts the same `ca.pem` that vt-server uses to issue certificates and that the agent picked up the CA file from `config.json`.
* **Dashboard 502** – check that `dashboard_oidc` has a valid Keycloak client secret and that the `dashboard_api` container is healthy.

---

For additional wiring (Keycloak realm import, oauth2-proxy templates, or MSI authoring) see the assets under `env/` and `packaging/`.
