# VT Audit Platform

VT Audit is a two-sided compliance monitoring stack:

- **Agents** enrol over mutual TLS, fetch audit policies, and push findings.
- **Admins** sign in with Keycloak SSO, view dashboards, and publish policies.

The stack is delivered as a reproducible Docker Compose bundle that wires together the gateway, Step-CA, API services, dashboard SPA, oauth2-proxy, Keycloak, and PostgreSQL.

---

## 1. Architecture Overview

| Service | Purpose | Port | Exposure |
|---------|---------|------|----------|
| `stepca` (Smallstep CA) | Issues short-lived mTLS certs for agents using a JWK provisioner | 9000 | backend network only |
| `gateway` (nginx) | Single public entrypoint. Terminates TLS, enforces client certs for agents, proxies dashboard traffic | 443 | Host ? container |
| `oidc-proxy` (oauth2-proxy) | Fronts the admin API, handles OIDC login with Keycloak, issues session cookies | 4180 | backend network only |
| `keycloak` | Identity provider for admins | 8080 | backend network only (optionally exposed) |
| `api-agent` (`vt-server --mode=agent`) | Agent-facing API: bootstrap OTT tokens, enrolment, policy delivery, result ingest | 8080 | backend network only |
| `api-user` (`vt-server --mode=dashboard`) | Admin API: exposes `/dashboard/api/*` for the SPA, enforces OIDC tokens | 8081 | backend network only |
| `dashboard` | Static SPA (HTML/JS/CSS) served by nginx | 80 | backend network only |
| `postgres` | Shared database for policies, results, and Keycloak | 5432 | backend network only |

Two Docker networks are created: `frontend` (only the gateway) and `backend` (all internal services). Agents and admins only touch port **443** on the host.

### Connection flows

1. **Agent bootstrap**
   1. Agent calls `POST https://gateway.local/agent/bootstrap/ott` with a shared bootstrap token.
   2. `api-agent` mints a JWK one-time token via Step-CA and returns the Step-CA audience URL plus the CA bundle.
   3. Agent exchanges the OTT with Step-CA for a short-lived client certificate.
   4. Subsequent requests present the cert to the gateway (mTLS). Metadata is forwarded via `X-Client-*` headers to `api-agent`.
   5. Agent enrols (`/agent/enroll`), fetches policies, runs audits, and submits results over mTLS.

2. **Admin dashboard**
   1. Browser loads `https://gateway.local/dashboard/` (SPA assets served by `vt-dashboard`).
   2. SPA calls `/dashboard/api/*`; the gateway proxies to oauth2-proxy.
   3. oauth2-proxy redirects unauthenticated sessions to Keycloak.
   4. After login, oauth2-proxy sets a secure session cookie and forwards the request to `api-user` with an OIDC bearer token.
   5. `api-user` verifies the token against Keycloak and returns JSON for the SPA.

---

## 2. Prerequisites

- Docker Engine 24+ and Docker Compose plugin.
- A DNS entry (or hosts file) that points `gateway.local` to the deployment host.
- TLS material for the gateway (`server.pem`/`server.key`). For production use a certificate issued by your enterprise CA; for testing you can self-sign.
- Step-CA JWK provisioner key and password placed under the shared Step-CA volume.

---

## 3. Configuration

1. Copy the sample environment file and fill in secrets:

   ```powershell
   cd env
   Copy-Item .env.example .env
   # edit .env to set strong passwords, client secrets, and the bootstrap token
   ```

   Key fields:
   - `OIDC_CLIENT_SECRET`, `OIDC_COOKIE_SECRET`: oauth2-proxy credentials.
   - `STEPCA_KEY_PATH` / `STEPCA_PASSWORD`: path inside the container to the encrypted JWK provisioner key.
   - `AGENT_BOOTSTRAP_TOKEN`: shared secret embedded in the installer used for the OTT request.

2. Place the gateway TLS files in `env/conf/gateway/issuer/server.pem` and `server.key` (mounted read-only into nginx).

3. Ensure the Step-CA volume (`stepca_data`) contains:
   - `secrets/provisioner.key` (JWK or encrypted JWE as referenced by `.env`).
   - Step-CA state directories created automatically on first boot.

4. Optional: adjust `env/conf/gateway/nginx.conf` if you expose Keycloak externally or need extra routes.

---

## 4. Building & Running

```powershell
# From the repo root
docker compose --env-file env/.env -f env/docker-compose.yml build

docker compose --env-file env/.env -f env/docker-compose.yml up -d
```

Check container status:

```powershell
docker compose -f env/docker-compose.yml ps
docker compose -f env/docker-compose.yml logs -f gateway oidc-proxy keycloak api-agent api-user stepca
```

The dashboard SPA becomes available at `https://gateway.local/dashboard/` once all services show healthy.

---

## 5. Provisioning Keycloak

1. Browse to `http://<host>:8080/` (or tunnel through SSH) and log in with `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD`.
2. Create or import a realm named `vt-audit`.
3. Create a confidential client `dashboard-proxy` with:
   - Valid Redirect URIs: `https://gateway.local/dashboard/oauth2/callback` and `https://gateway.local/_oauth`.
   - Web Origins: `https://gateway.local`
   - Client Secret identical to `OIDC_CLIENT_SECRET`.
4. Add an `admin` realm role (or client role) and assign it to the admin user. oauth2-proxy will pass the ID token to `api-user`, which enforces that `OIDC_ADMIN_ROLE` is present for policy mutations.

---

## 6. Agent Bootstrap & mTLS Flow

1. Install the Windows agent package (`agent.exe` or MSI) and provide `config.json` with:

   ```json
   {
     "server": "https://gateway.local/agent",
     "ca_file": "C:/Program Files/VT Agent/ca.pem",
     "bootstrap_token": "<AGENT_BOOTSTRAP_TOKEN>",
     "insecure_skip_verify": false
   }
   ```

2. First run obtains an OTT and requests a client certificate:

   ```powershell
   .\agent.exe enroll
   ```

   Under the hood the agent:
   - Calls `/agent/bootstrap/ott` with the bootstrap token.
   - Exchanges the OTT with Step-CA for a short-lived cert.
   - Stores the cert/key locally and proves possession when calling `/agent/enroll`.

3. Subsequent executions (service mode or `run`) reuse the stored credentials and post results via `/agent/results`.

---

## 7. Dashboard SPA

- Served from the `dashboard` container (nginx) with client-side routing for `/audit` and `/policy`.
- Fetches data from `/dashboard/api/*`:
  - `/dashboard/api/results` – latest findings with filter support.
  - `/dashboard/api/policy/active` – YAML of the active Windows policy.
  - `/dashboard/api/policy/history` – version history.
  - `/dashboard/api/policy/save` (admin role) – store & activate a new policy version.
  - `/dashboard/api/policy/activate` (admin role) – re-activate a historical version.

The oauth2-proxy injects a bearer token for these upstream calls. If the cookie expires the SPA will be redirected back through the Keycloak login flow.

---

## 8. Certificates & Trust

- **Gateway TLS:** Provide `server.pem`/`server.key` under `env/conf/gateway/issuer/`. Distribute the issuing CA to agents and admin browsers.
- **Step-CA:** First start bootstraps the authority state in `stepca_data`. Backup the root & intermediate keys offline. The gateway mounts the volume read-only to validate client certificates (`ssl_client_certificate /etc/nginx/stepca/certs/root_ca.crt`).
- **Agent trust store:** Ship `ca.pem` (gateway certificate chain) with the installer or add to the OS trust store so the agent validates the gateway TLS session.

---

## 9. Troubleshooting Checklist

- `curl -vk https://gateway.local/dashboard/` ? verifies TLS and gateway reachability.
- `docker compose -f env/docker-compose.yml logs -f gateway` ? inspect proxy/mtls errors.
- `docker compose -f env/docker-compose.yml exec gateway sh -c "wget -qO- http://api-agent:8080/health"` ? confirm gateway can resolve internal services.
- `curl -vk --cacert ca.pem --cert client.pem --key client.key https://gateway.local/agent/policy/healthcheck` ? validate agent mTLS flow manually.
- oauth2: check oauth2-proxy logs for `nonce` or discovery errors; ensure `OIDC_ISSUER` matches the Keycloak realm OIDC metadata URL.
- Step-CA: `docker compose -f env/docker-compose.yml logs -f stepca` to confirm OTT issuance.

---

## 10. Security Notes

- Never commit `.env`, provisioner keys, or TLS private keys.
- Restrict access to the Docker host; only port 443 should be exposed publicly.
- Rotate `AGENT_BOOTSTRAP_TOKEN` and oauth2 secrets regularly; regenerate the Step-CA provisioner key if compromised.
- Enable HTTPS for Keycloak in production (behind the gateway or with its own TLS).
- Implement log rotation for nginx and oauth2-proxy to avoid disk pressure (configure via Docker logging drivers or external collectors).

---

## 11. Repository Layout

```
agent/                Windows agent source code
server/               vt-server binary (agent API + admin API)
dashboard/            SPA assets and nginx Dockerfile
env/docker-compose.yml Compose definition for the full stack
env/conf/...          Gateway, oauth2-proxy, and other deployment configs
rules/                Baseline Windows policy definitions
```

With this layout you can customise policies, extend the SPA, or integrate additional observability endpoints without altering the deployment topology described above.

