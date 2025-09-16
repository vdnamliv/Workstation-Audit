package server

import (
    "log"
    "net/http"
    "os"
    "path/filepath"

    "vt-audit/server/pkg/dashboard"
    "vt-audit/server/pkg/httpagent"
    "vt-audit/server/pkg/model"
    "vt-audit/server/pkg/policy"
    "vt-audit/server/pkg/storage"
    "vt-audit/server/pkg/storage/sqlite"
    pgstore "vt-audit/server/pkg/storage/postgres"
)

// Run starts the desired HTTP services. It keeps backward compatibility
// with the old single-server mode when only Cfg.Addr is provided.
func Run(cfg model.Config) error {
    // Ensure DB dir exists
    _ = os.MkdirAll(filepath.Dir(cfg.DBPath), 0755)

    // Choose store: PostgreSQL if DSN provided; else SQLite
    var st storage.Store
    var err error
    if cfg.PGDSN != "" {
        var pst *pgstore.Store
        pst, err = pgstore.Open(cfg.PGDSN)
        if err != nil { return err }
        st = pst
        if err := pst.InitAgentSchema(); err != nil { return err }
        if err := pst.InitPolicySchema(); err != nil { return err }
        // Seed
        if _, err := httpagent.SeedIfEmpty(pst, cfg.RulesDir); err != nil { return err }
    } else {
        var sst *sqlite.Store
        sst, err = sqlite.Open(cfg.DBPath)
        if err != nil { return err }
        st = sst
        if err := sst.InitAgentSchema(); err != nil { return err }
        if err := sst.InitPolicySchema(); err != nil { return err }
        if _, err := httpagent.SeedIfEmpty(sst, cfg.RulesDir); err != nil { return err }
    }
    defer st.DB().Close()

    // Decide mode
    mode := cfg.Mode
    if mode == "" { mode = "all" }

    // Backward compatible: if AgentAddr/DashboardAddr empty, derive from Addr
    if cfg.AgentAddr == "" && cfg.DashboardAddr == "" && cfg.Addr != "" {
        cfg.AgentAddr = cfg.Addr
        cfg.DashboardAddr = cfg.Addr
    }
    if cfg.AgentAddr == "" { cfg.AgentAddr = ":443" }
    if cfg.DashboardAddr == "" { cfg.DashboardAddr = ":8443" }

    // Build handlers
    var muxAgent http.Handler
    var muxDash http.Handler

    if mode == "all" || mode == "agent" {
        as, err := httpagent.New(st, cfg)
        if err != nil { return err }
        muxAgent = as.Handler()
    }
    if mode == "all" || mode == "dashboard" {
        ds := dashboard.New(st, cfg)
        muxDash = ds.Handler()
    }

    // If single process and same address, mount under prefixes for compatibility
    if mode == "all" && cfg.AgentAddr == cfg.DashboardAddr {
        // expose both sets of routes on the same mux for legacy behavior
        root := http.NewServeMux()
        if ds := dashboard.New(st, cfg); ds != nil {
            // Rebuild to mount directly so both /api/* and /app/* are at root
            root.Handle("/", ds.Handler())
        }
        if as, err := httpagent.New(st, cfg); err == nil {
            as.Mount(root, "") // mount agent routes at root to keep old paths
        }
        log.Printf("server listening on %s (rules=%s db=%s)", cfg.DashboardAddr, cfg.RulesDir, cfg.DBPath)
        if cfg.CertFile != "" && cfg.KeyFile != "" {
            return http.ListenAndServeTLS(cfg.DashboardAddr, cfg.CertFile, cfg.KeyFile, root)
        }
        return http.ListenAndServe(cfg.DashboardAddr, root)
    }

    // Otherwise, run the selected service on its own address
    switch mode {
    case "agent":
        log.Printf("agent API listening on %s", cfg.AgentAddr)
        if cfg.CertFile != "" && cfg.KeyFile != "" {
            return http.ListenAndServeTLS(cfg.AgentAddr, cfg.CertFile, cfg.KeyFile, muxAgent)
        }
        return http.ListenAndServe(cfg.AgentAddr, muxAgent)
    case "dashboard":
        log.Printf("dashboard listening on %s", cfg.DashboardAddr)
        if cfg.CertFile != "" && cfg.KeyFile != "" {
            return http.ListenAndServeTLS(cfg.DashboardAddr, cfg.CertFile, cfg.KeyFile, muxDash)
        }
        return http.ListenAndServe(cfg.DashboardAddr, muxDash)
    default:
        // all mode, different ports: run dashboard and agent concurrently
        errc := make(chan error, 2)
        go func() {
            log.Printf("dashboard listening on %s", cfg.DashboardAddr)
            if cfg.CertFile != "" && cfg.KeyFile != "" {
                errc <- http.ListenAndServeTLS(cfg.DashboardAddr, cfg.CertFile, cfg.KeyFile, muxDash)
            } else {
                errc <- http.ListenAndServe(cfg.DashboardAddr, muxDash)
            }
        }()
        go func() {
            log.Printf("agent API listening on %s", cfg.AgentAddr)
            if cfg.CertFile != "" && cfg.KeyFile != "" {
                errc <- http.ListenAndServeTLS(cfg.AgentAddr, cfg.CertFile, cfg.KeyFile, muxAgent)
            } else {
                errc <- http.ListenAndServe(cfg.AgentAddr, muxAgent)
            }
        }()
        return <-errc
    }
}

// Re-export helpers that were previously in server.go to avoid breaking imports
var _ = policy.NormalizePolicies
