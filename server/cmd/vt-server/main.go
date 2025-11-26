package main

import (
	"flag"
	"log"
	"time"

	"vt-audit/server/pkg/model"
	"vt-audit/server/pkg/server"
)

func main() {
	// Backward-compat single address
	addr := flag.String("addr", ":8443", "Single listen address (legacy mode)")

	// New split-mode flags
	mode := flag.String("mode", "all", "Service mode: all|agent|dashboard")
	agentAddr := flag.String("agent-addr", "", "Listen address for the agent API (empty => use --addr)")
	dashAddr := flag.String("dashboard-addr", "", "Listen address for the dashboard (empty => use --addr)")

	cert := flag.String("cert", "", "TLS certificate file (PEM)")
	key := flag.String("key", "", "TLS key file (PEM)")
	rulesDir := flag.String("rules", "rules", "Rules directory (expects windows.yml inside)")
	adminKey := flag.String("admin", "", "Optional admin key for policy updates")
	mtlsCA := flag.String("mtls-ca", "", "Path to the client CA certificate (PEM)")
	mtlsCAKey := flag.String("mtls-ca-key", "", "Path to the client CA private key (PEM)")
	mtlsCertTTL := flag.Duration("mtls-cert-ttl", 24*time.Hour, "Validity for issued client certificates")

	oidcIssuer := flag.String("oidc-issuer", "", "OIDC issuer URL (e.g. https://keycloak:8080/realms/vt-audit)")
	oidcClientID := flag.String("oidc-client-id", "", "OIDC client ID for dashboard access")
	oidcClientSecret := flag.String("oidc-client-secret", "", "OIDC client secret for direct authentication")
	oidcAdminRole := flag.String("oidc-admin-role", "admin", "Realm/client role required for admin operations")

	pgDSN := flag.String("pg_dsn", "", "Optional Postgres DSN for policy versioning (reserved)")
	stepcaURL := flag.String("stepca-url", "", "Internal Step-CA URL (e.g. https://stepca:9000)")
	stepcaExternal := flag.String("stepca-external-url", "https://localhost:443/step-ca", "External Step-CA URL exposed to agents (e.g. https://gateway.local/step-ca)")
	stepcaProvisioner := flag.String("stepca-provisioner", "", "Step-CA provisioner name for agent certificates")
	stepcaKeyPath := flag.String("stepca-key-path", "", "Path to the JWK provisioner private key (JWE or raw JSON)")
	stepcaPassword := flag.String("stepca-password", "", "Password to decrypt the provisioner key (if encrypted)")
	bootstrapToken := flag.String("bootstrap-token", "", "Shared bootstrap token required for agent enrollment")

	flag.Parse()

	cfg := model.Config{
		Addr:     *addr, // provide for legacy compatibility
		CertFile: *cert, KeyFile: *key,
		RulesDir: *rulesDir, AdminKey: *adminKey,
		PGDSN: *pgDSN,
		Mode:  *mode, AgentAddr: *agentAddr, DashboardAddr: *dashAddr,
		MTLSCAFile: *mtlsCA, MTLSCAKeyFile: *mtlsCAKey, MTLSCertTTL: *mtlsCertTTL,
		OIDCIssuer: *oidcIssuer, OIDCClientID: *oidcClientID, OIDCClientSecret: *oidcClientSecret, OIDCAdminRole: *oidcAdminRole,
		StepCAURL:           *stepcaURL,
		StepCAExternalURL:   *stepcaExternal,
		StepCAProvisioner:   *stepcaProvisioner,
		StepCAKeyPath:       *stepcaKeyPath,
		StepCAPassword:      *stepcaPassword,
		AgentBootstrapToken: *bootstrapToken,
	}
	if err := server.Run(cfg); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
