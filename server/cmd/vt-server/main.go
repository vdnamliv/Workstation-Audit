package main

import (
    "flag"
    "log"

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
    dbPath := flag.String("db", "server_state/audit.db", "SQLite DB path (results, agents)")
    adminKey := flag.String("admin", "", "Optional admin key for policy updates")

    pgDSN := flag.String("pg_dsn", "", "Optional Postgres DSN for policy versioning (reserved)")

    flag.Parse()

    cfg := model.Config{
        Addr: *addr, // provide for legacy compatibility
        CertFile: *cert, KeyFile: *key,
        RulesDir: *rulesDir, DBPath: *dbPath, AdminKey: *adminKey,
        PGDSN: *pgDSN,
        Mode: *mode, AgentAddr: *agentAddr, DashboardAddr: *dashAddr,
    }
    if err := server.Run(cfg); err != nil {
        log.Fatalf("server failed: %v", err)
    }
}
