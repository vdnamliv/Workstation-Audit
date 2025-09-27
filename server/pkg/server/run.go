package server

import (
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"vt-audit/server/pkg/dashboard"
	"vt-audit/server/pkg/httpagent"
	"vt-audit/server/pkg/model"
	"vt-audit/server/pkg/policy"
	"vt-audit/server/pkg/stepca"
	"vt-audit/server/pkg/storage"
	pgstore "vt-audit/server/pkg/storage/postgres"
)

// Run starts the desired HTTP services. It keeps backward compatibility
// with the old single-server mode when only Cfg.Addr is provided.
func Run(cfg model.Config) error {
	// Ensure DB dir exists
	_ = os.MkdirAll(filepath.Dir(cfg.DBPath), 0755)

	if cfg.StepCAExternalURL == "" {
		cfg.StepCAExternalURL = cfg.StepCAURL
	}

	// Choose store: PostgreSQL if DSN provided; else SQLite
	var st storage.Store
	var err error
	if cfg.PGDSN != "" {
		var pst *pgstore.Store
		pst, err = pgstore.Open(cfg.PGDSN)
		if err != nil {
			return err
		}
		st = pst
		if err := pst.InitAgentSchema(); err != nil {
			return err
		}
		if err := pst.InitPolicySchema(); err != nil {
			return err
		}
		// Seed
		if _, err := httpagent.SeedIfEmpty(pst, cfg.RulesDir); err != nil {
			return err
		}
	} 

	// Prepare Step-CA helpers. Local issuer remains optional for legacy flows,
	// while the JWK provisioner enables delegated issuance through step-ca.
	var certIssuer stepca.CertificateIssuer
	if cfg.MTLSCAFile != "" && cfg.MTLSCAKeyFile != "" {
		issuer, err := stepca.LoadIssuer(cfg.MTLSCAFile, cfg.MTLSCAKeyFile, cfg.MTLSCertTTL)
		if err != nil {
			return err
		}
		certIssuer = issuer
	}

	var provisioner stepca.TokenProvisioner
	if cfg.StepCAProvisioner != "" && cfg.StepCAKeyPath != "" && cfg.StepCAURL != "" {
		provisioner, err = waitForProvisioner(cfg)
		if err != nil {
			return err
		}
	}

	// Decide mode
	mode := cfg.Mode
	if mode == "" {
		mode = "all"
	}

	// Backward compatible: if AgentAddr/DashboardAddr empty, derive from Addr
	if cfg.AgentAddr == "" && cfg.DashboardAddr == "" && cfg.Addr != "" {
		cfg.AgentAddr = cfg.Addr
		cfg.DashboardAddr = cfg.Addr
	}
	if cfg.AgentAddr == "" {
		cfg.AgentAddr = ":443"
	}
	if cfg.DashboardAddr == "" {
		cfg.DashboardAddr = ":8443"
	}

	// Build handlers
	var muxAgent http.Handler
	var muxDash http.Handler

	if mode == "all" || mode == "agent" {
		as, err := httpagent.New(st, cfg, certIssuer, provisioner)
		if err != nil {
			return err
		}

		mux := http.NewServeMux()
		mux.Handle("/", as.Handler())

		if provisioner != nil {
			mux.Handle("/api/enroll", stepca.NewEnrollGatewayHandler(provisioner))
		}

		muxAgent = mux
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
		if as, err := httpagent.New(st, cfg, certIssuer, provisioner); err == nil {
			as.Mount(root, "") // mount agent routes at root to keep old paths
		}
		if provisioner != nil {
			root.Handle("/api/enroll", stepca.NewEnrollGatewayHandler(provisioner))
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

func waitForProvisioner(cfg model.Config) (stepca.TokenProvisioner, error) {
	jwkCfg := stepca.JWKConfig{
		Name:     cfg.StepCAProvisioner,
		KeyPath:  cfg.StepCAKeyPath,
		Password: cfg.StepCAPassword,
		Audience: cfg.StepCAURL,
		TTL:      5 * time.Minute,
	}
	backoff := 5 * time.Second
	for {
		prov, err := stepca.LoadJWKProvisioner(jwkCfg)
		if err == nil {
			log.Printf("server: Step-CA provisioner %s ready (audience=%s)", cfg.StepCAProvisioner, cfg.StepCAURL)
			return prov, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		log.Printf("server: waiting for Step-CA provisioner key at %s", cfg.StepCAKeyPath)
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

// Re-export helpers that were previously in server.go to avoid breaking imports
var _ = policy.NormalizePolicies
