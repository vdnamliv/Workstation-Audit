package main

import (
	"flag"
	"log"

	"vt-audit/server/pkg/server"
)

func main() {
	addr     := flag.String("addr", ":8443", "Listen address (e.g., :8443)")
	cert     := flag.String("cert", "", "TLS certificate file (PEM)")
	key      := flag.String("key",  "", "TLS key file (PEM)")
	rulesDir := flag.String("rules", "rules", "Rules directory (expects windows.yml inside)")
	dbPath   := flag.String("db", "server_state/audit.db", "SQLite DB path (results, agents)")
	adminKey := flag.String("admin", "", "Optional admin key for /reload_policies")

	// reserved for future Postgres policy-store; not required now
	pgDSN    := flag.String("pg_dsn", "", "Optional Postgres DSN for policy versioning (not required)")

	flag.Parse()

	cfg := server.Config{
		Addr: *addr, CertFile: *cert, KeyFile: *key,
		RulesDir: *rulesDir, DBPath: *dbPath, AdminKey: *adminKey,
		PGDSN: *pgDSN, // not used yet (safe)
	}
	if err := server.Run(cfg); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
