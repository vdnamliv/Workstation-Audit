// agent/cmd/vt-agent/main.go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"vt-audit/agent/pkg/audit"
	"vt-audit/agent/pkg/enroll"
	"vt-audit/agent/pkg/policy"
	"vt-audit/agent/pkg/render"
	"vt-audit/agent/pkg/stepca"
	"vt-audit/agent/pkg/storage"
	"vt-audit/agent/pkg/svcwin"
	"vt-audit/agent/pkg/tlsclient"
)

/*
Change log (important):
- Remove all agent-side interval flags/env/logic. Poll interval is controlled by server via /enroll.
- Add --log-file (CLI). When running as service, default logs to C:\Program Files\VT Agent\agent.log.
- Keep compatibility: LoadOrEnroll() still returns poll from server; loops will use that.
*/

type AppConfig struct {
	ServerURL             string `json:"server"`
	CAFile                string `json:"ca_file"`
	InsecureTLSSkipVerify bool   `json:"insecure_skip_verify"`
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func configPath() string {
	// prioritize config next to the executable
	p := filepath.Join(exeDir(), "config.json")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("Program Files"); pd != "" {
			pdPath := filepath.Join(pd, "VT Agent", "config.json")
			if _, err := os.Stat(pdPath); err == nil {
				return pdPath
			}
		}
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			laPath := filepath.Join(la, "VT Agent", "config.json")
			if _, err := os.Stat(laPath); err == nil {
				return laPath
			}
		}
	}
	return filepath.Join(exeDir(), "config.json")
}

func loadJSON[T any](p string, out *T) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func mustHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown-host"
	}
	return h
}

func fromEnv(cfg *AppConfig) {
	if v := os.Getenv("AGENT_SERVER"); v != "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("AGENT_CA_FILE"); v != "" {
		cfg.CAFile = v
	}
	if v := os.Getenv("AGENT_TLS_INSECURE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.InsecureTLSSkipVerify = b
		}
	}
}

// --- logging helpers (default to ProgramData when running as service)
func dataDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("Program Files"); pd != "" {
			return filepath.Join(pd, "VT Agent")
		}
	}
	return filepath.Join(exeDir(), "data")
}

func initLogger(defaultToFile bool, explicit string) {
	var w io.Writer
	if explicit != "" {
		if err := os.MkdirAll(filepath.Dir(explicit), 0o755); err == nil {
			if f, err := os.OpenFile(explicit, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				w = f
			}
		}
	} else if defaultToFile {
		p := filepath.Join(dataDir(), "agent.log")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err == nil {
			if f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				w = f
			}
		}
	}
	if w != nil {
		log.SetOutput(w)
	} else {
		log.SetOutput(os.Stdout)
	}
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
}

// -- simple runner for service control commands
func runShell(cmd string) error {
	c := exec.Command("cmd", "/c", cmd)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func requireServer(cfg *AppConfig) error {
	if !strings.HasPrefix(cfg.ServerURL, "http://") && !strings.HasPrefix(cfg.ServerURL, "https://") {
		return fmt.Errorf("invalid server URL: %s", cfg.ServerURL)
	}
	return nil
}

func resolveCAPath(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	if filepath.IsAbs(name) {
		return name, nil
	}
	candidates := []string{
		filepath.Join(exeDir(), name),
		filepath.Join(dataDir(), name),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return candidates[0], fmt.Errorf("ca file not found: %s (checked %s and %s)", name, candidates[0], candidates[1])
}

func newServerHTTPClient(cfg AppConfig) (*tlsclient.Client, error) {
	caPath, err := resolveCAPath(cfg.CAFile)
	if err != nil {
		return nil, err
	}

	baseClient, err := tlsclient.New(caPath, cfg.InsecureTLSSkipVerify)
	if err != nil {
		return nil, fmt.Errorf("tls bootstrap: %w", err)
	}

	stepClient, err := stepca.New(baseClient, cfg.ServerURL, mustHostname())
	if err != nil {
		return nil, fmt.Errorf("stepca init: %w", err)
	}
	if _, err := stepClient.Ensure(context.Background()); err != nil {
		return nil, fmt.Errorf("stepca ensure: %w", err)
	}

	opts := tlsclient.Options{
		CAFile:             caPath,
		InsecureSkipVerify: cfg.InsecureTLSSkipVerify,
		GetClientCertificate: func(*tlsclient.CertificateRequestInfo) (*tlsclient.Certificate, error) {
			return stepClient.Ensure(context.Background())
		},
	}
	if pool := stepClient.CAPool(); pool != nil {
		opts.CAPool = pool
	}

	return tlsclient.NewWithOptions(opts)
}

func defaultOutName(ext string) string {
	host := mustHostname()
	ts := time.Now().Format("20060102_150405") // YYYYMMDD_HHMMSS
	return fmt.Sprintf("%s_%s.%s", ts, host, ext)
}

func main() {
	// ===== subcommands =====
	serviceCmd := flag.NewFlagSet("service", flag.ExitOnError)
	auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)

	// service flags (NO interval here)
	var (
		flagServer = serviceCmd.String("server", "", "Server URL (https://host:port)")
		flagCA     = serviceCmd.String("ca-file", "", "CA PEM for TLS pinning")
		flagInsec  = serviceCmd.Bool("tls-skip-verify", false, "INSECURE: skip TLS verify (lab only)")
	)
	var flagSvcVerb string
	serviceCmd.StringVar(&flagSvcVerb, "action", "run", "install|uninstall|start|stop|run")

	// audit (local) flags
	var (
		aServer = auditCmd.String("server", "", "Server URL (optional if --policy-file)")
		aCA     = auditCmd.String("ca-file", "", "CA PEM for TLS pinning")
		aInsec  = auditCmd.Bool("tls-skip-verify", false, "INSECURE: skip TLS verify (lab only)")
		aPolicy = auditCmd.String("policy-file", "", "Local windows.yml (offline)")
		aJSON   = auditCmd.Bool("json", false, "Output JSON to stdout or --out")
		aHTML   = auditCmd.Bool("html", false, "Render HTML report to --out")
		aExcel  = auditCmd.Bool("excel", false, "Export XLSX report to --out")
	)

	// top-level flags (compat + local shortcut)
	var (
		tServer = flag.String("server", "", "Server URL")
		tOnce   = flag.Bool("once", false, "Run one cycle then exit")
		tCA     = flag.String("ca-file", "", "CA PEM file")
		tInsec  = flag.Bool("tls-skip-verify", false, "INSECURE: skip TLS verify")
		tLog    = flag.String("log-file", "", "Log file path (defaults to Program Files when running as service)")

		tLocal = flag.Bool("local", false, "Run local audit: fetch policies but DO NOT submit to server")
		tJSON  = flag.Bool("json", false, "With --local: print JSON report to stdout")
		tHTML  = flag.Bool("html", false, "With --local: render HTML report")
		tExcel = flag.Bool("excel", false, "With --local: export XLSX report")
	)
	flag.Parse()

	// decide subcommand
	args := flag.Args()
	if len(args) > 0 {
		switch args[0] {
		case "service":
			_ = serviceCmd.Parse(args[1:])
			runServiceMode(*flagServer, *flagCA, *flagInsec, flagSvcVerb)
			return
		case "audit":
			_ = auditCmd.Parse(args[1:])
			runAuditLocal(*aServer, *aCA, *aInsec, *aPolicy, *aJSON, *aHTML, *aExcel)
			return
		default:
			fmt.Println("Usage:")
			fmt.Println("  vt-agent service --action {install|uninstall|start|stop|run} [--server ... --ca-file ...]")
			fmt.Println("  vt-agent audit   [--policy-file windows.yml] [--server ...] [--json|--html|--excel] [--out path]")
			fmt.Println("  vt-agent         [-server ... -once | --local (--json|--html|--excel) --out <file>]")
			os.Exit(2)
		}
	}

	// ===== compat mode (no subcommand) =====
	cfg := AppConfig{}
	_ = loadJSON(configPath(), &cfg)
	fromEnv(&cfg)

	// flags override
	if *tServer != "" {
		cfg.ServerURL = *tServer
	}
	if *tCA != "" {
		cfg.CAFile = *tCA
	}
	if *tInsec {
		cfg.InsecureTLSSkipVerify = true
	}

	// init logger for CLI (console by default). If --log-file provided -> file.
	initLogger(false, *tLog)

	// Local mode shortcut
	if *tLocal {
		if err := localMain(cfg, *tJSON, *tHTML, *tExcel); err != nil {
			log.Fatalf("local audit failed: %v", err)
		}
		return
	}

	// Windows double-click -> run once
	if runtime.GOOS == "windows" && len(os.Args) == 1 {
		*tOnce = true
	}

	if err := requireServer(&cfg); err != nil {
		log.Fatalf("config error: %v", err)
	}
	httpClient, err := newServerHTTPClient(cfg)
	if err != nil {
		log.Fatalf("TLS client error: %v", err)
	}

	aid, sec, poll := storage.LoadOrEnroll(httpClient, cfg.ServerURL)
	host := mustHostname()

	if *tOnce {
		if err := runOnce(httpClient, cfg.ServerURL, aid, sec, host); err != nil {
			log.Fatalf("Run failed: %v", err)
		}
		return
	}

	if poll <= 0 {
		poll = 600
	} // server controls poll; fallback safety
	log.Printf("Polling interval: %d seconds", poll)
	for {
		if err := runOnce(httpClient, cfg.ServerURL, aid, sec, host); err != nil {
			log.Printf("Run error: %v", err)
		}
		time.Sleep(time.Duration(poll) * time.Second)
	}
}

/* ==================== service mode ==================== */

func runServiceMode(server, ca string, insecure bool, action string) {
	switch strings.ToLower(action) {
	case "install":
		exe, _ := os.Executable()

		// build arguments; no --interval flag (server controls)
		caPart := ""
		if ca != "" {
			caPart = fmt.Sprintf(` --ca-file "%s"`, ca)
		}
		insecPart := ""
		if insecure {
			insecPart = ` --tls-skip-verify`
		}

		// binPath: wrap the whole command line in "..."
		binPath := fmt.Sprintf(`"%s service --action run --server %s%s%s"`,
			exe, server, caPart, insecPart)

		cmd := exec.Command("sc.exe", "create", "VTAgent", "binPath=", binPath, "start=", "auto")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("service install failed: %v", err)
		}
		_ = runShell(`sc.exe description VTAgent "VT Agent - Compliance baseline scanner"`)

	case "uninstall":
		if err := runShell(`sc.exe stop VTAgent`); err != nil {
			log.Println("stop:", err)
		}
		if err := runShell(`sc.exe delete VTAgent`); err != nil {
			log.Fatalf("delete: %v", err)
		}

	case "start":
		if err := runShell(`sc.exe start VTAgent`); err != nil {
			log.Fatalf("start: %v", err)
		}

	case "stop":
		if err := runShell(`sc.exe stop VTAgent`); err != nil {
			log.Fatalf("stop: %v", err)
		}

	case "run":
		// Service default: log to ProgramFiles\VT Agent\agent.log
		initLogger(true, "")

		cfg := AppConfig{ServerURL: server, CAFile: ca, InsecureTLSSkipVerify: insecure}
		if err := requireServer(&cfg); err != nil {
			log.Fatalf("config error: %v", err)
		}
		httpClient, err := newServerHTTPClient(cfg)
		if err != nil {
			log.Fatalf("TLS client error: %v", err)
		}

		aid, sec, poll := storage.LoadOrEnroll(httpClient, cfg.ServerURL)
		host := mustHostname()
		if poll <= 0 {
			poll = 600
		}

		// If under SCM, integrate with service controller
		if svcwin.IsWindowsService() {
			r := &svcRunner{
				httpClient: httpClient,
				serverURL:  cfg.ServerURL,
				agentID:    aid, agentSecret: sec,
				hostname:    host,
				intervalSec: poll,
			}
			if err := svcwin.Run("VTAgent", svcwin.NewService(r)); err != nil {
				log.Fatalf("service run error: %v", err)
			}
			return
		}

		// fallback console loop (for debugging)
		for {
			if err := runOnce(httpClient, cfg.ServerURL, aid, sec, host); err != nil {
				log.Printf("Run error: %v", err)
			}
			time.Sleep(time.Duration(poll) * time.Second)
		}

	default:
		log.Fatalf("unknown service action: %s", action)
	}
}

/* ==================== audit local (subcommand) ==================== */

func runAuditLocal(server, ca string, insecure bool, policyFile string, outJSON, outHTML, outExcel bool) {
	if !outJSON && !outHTML && !outExcel {
		outJSON = true
	}

	var pol policy.Bundle
	var err error

	if policyFile != "" {
		pol, err = policy.LoadFromFile(policyFile)
		if err != nil {
			log.Fatalf("load policy: %v", err)
		}
	} else {
		cfg := AppConfig{ServerURL: server, CAFile: ca, InsecureTLSSkipVerify: insecure}
		if err := requireServer(&cfg); err != nil {
			log.Fatalf("config error: %v", err)
		}
		httpClient, err := newServerHTTPClient(cfg)
		if err != nil {
			log.Fatalf("TLS client error: %v", err)
		}
		aid, sec, _ := storage.LoadOrEnroll(httpClient, cfg.ServerURL)
		pol, err = policy.Fetch(httpClient, cfg.ServerURL, "windows", aid, sec)
		if err != nil {
			log.Fatalf("fetch policy: %v", err)
		}
	}

	results, err := audit.Execute(struct {
		Version  int
		Policies []map[string]interface{}
	}{Version: pol.Version, Policies: pol.Policies}, "windows")
	if err != nil {
		log.Fatalf("audit: %v", err)
	}

	switch {
	case outExcel:
		data, err := render.Excel(results)
		if err != nil {
			log.Fatalf("render excel: %v", err)
		}
		out := defaultOutName("xlsx")
		if err := os.WriteFile(out, data, 0o644); err != nil {
			log.Fatalf("write excel: %v", err)
		}
		log.Printf("Excel report saved: %s", out)
	case outHTML:
		htmlStr, err := render.HTML(results)
		if err != nil {
			log.Fatalf("render html: %v", err)
		}
		out := defaultOutName("html")
		if err := os.WriteFile(out, []byte(htmlStr), 0o644); err != nil {
			log.Fatalf("write html: %v", err)
		}
		log.Printf("HTML report saved: %s", out)
	default:
		b, _ := json.MarshalIndent(map[string]any{
			"os": "windows", "hostname": mustHostname(), "results": results,
		}, "", "  ")
		out := defaultOutName("json")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			log.Fatalf("write json: %v", err)
		}
		log.Printf("JSON report saved: %s", out)
	}
}

/* ==================== local shortcut (compat mode) ==================== */

func localMain(cfg AppConfig, asJSON, asHTML, asExcel bool) error {
	if cfg.ServerURL == "" {
		return fmt.Errorf("missing server (config/flags)")
	}
	if !asJSON && !asHTML && !asExcel {
		asJSON = true
	}

	client, err := newServerHTTPClient(cfg)
	if err != nil {
		return fmt.Errorf("TLS: %w", err)
	}

	aid, sec, _ := storage.LoadCredentials()
	if aid == "" || sec == "" {
		aid, sec, _ = storage.LoadOrEnroll(client, cfg.ServerURL)
	}

	pol, err := policy.Fetch(client, cfg.ServerURL, "windows", aid, sec)
	if err != nil {
		return fmt.Errorf("fetch policy: %w", err)
	}

	results, err := audit.Execute(struct {
		Version  int
		Policies []map[string]interface{}
	}{Version: pol.Version, Policies: pol.Policies}, "windows")
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	switch {
	case asExcel:
		data, err := render.Excel(results)
		if err != nil {
			return err
		}
		if err := os.WriteFile(defaultOutName("xlsx"), data, 0o644); err != nil {
			return err
		}
		log.Printf("Excel report saved.")
	case asHTML:
		htmlStr, err := render.HTML(results)
		if err != nil {
			return err
		}
		if err := os.WriteFile(defaultOutName("html"), []byte(htmlStr), 0o644); err != nil {
			return err
		}
		log.Printf("HTML report saved.")
	default:
		b, _ := json.MarshalIndent(map[string]any{
			"os": "windows", "hostname": mustHostname(), "results": results,
		}, "", "  ")
		if err := os.WriteFile(defaultOutName("json"), b, 0o644); err != nil {
			return err
		}
		log.Printf("JSON report saved.")
	}
	return nil
}

/* ==================== core one-shot ==================== */

func runOnce(httpClient *tlsclient.Client, serverURL, agentID, agentSecret, hostname string) error {
	// 1) fetch policies
	pol, err := policy.Fetch(httpClient, serverURL, "windows", agentID, agentSecret)
	if err != nil {
		return fmt.Errorf("fetch policy: %w", err)
	}

	// 2) audit
	results, err := audit.Execute(struct {
		Version  int
		Policies []map[string]interface{}
	}{Version: pol.Version, Policies: pol.Policies}, "windows")
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	// 3) submit
	if err := enroll.PostResults(httpClient, serverURL, agentID, agentSecret, "windows", hostname, results); err != nil {
		return fmt.Errorf("post results: %w", err)
	}
	log.Printf("Sent %d results", len(results))
	return nil
}

// ---- bridge to svcwin.Runner ----
type svcRunner struct {
	httpClient  *tlsclient.Client
	serverURL   string
	agentID     string
	agentSecret string
	hostname    string
	intervalSec int
}

func (s *svcRunner) RunOnce(_ context.Context) error {
	return runOnce(s.httpClient, s.serverURL, s.agentID, s.agentSecret, s.hostname)
}
func (s *svcRunner) PollInterval() int { return s.intervalSec }
