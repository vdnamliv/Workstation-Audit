package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"vt-audit/agent/pkg/audit"
	"vt-audit/agent/pkg/enroll"
	"vt-audit/agent/pkg/policy"
	"vt-audit/agent/pkg/render"
	"vt-audit/agent/pkg/report"
	"vt-audit/agent/pkg/svcwin"
	"vt-audit/agent/pkg/tlsclient"
)

const (
	defaultServerURL = "https://gateway.local:8443/agent"
)

type AppConfig struct {
	ServerURL string
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func mustHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown-host"
	}
	return h
}

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

func printUsage() {
	fmt.Printf(`VT-Agent - Windows Compliance Monitoring Agent

USAGE:
    %s [OPTIONS]

MAIN MODES:
    --local          Fetch policy from server, run audit locally, do NOT submit results
    --once           Fetch policy from server, run audit once, submit results to server  
    --service        Run as Windows service with periodic audits (server-defined interval)

SERVICE MANAGEMENT:
    --install        Install as Windows service
    --uninstall      Uninstall Windows service

OPTIONS:
    --server URL     Server endpoint (default: %s)
    --bootstrap-token TOKEN   Bootstrap OTT token for initial enrollment
    --skip-mtls      Skip mTLS authentication (for testing)
    --log-file PATH  Log file path (auto-detected for service mode)
    --json           With --local: output JSON report
    --html           With --local: output HTML report  
    --excel          With --local: output Excel report

EXAMPLES:
    %s --local --html                    # Local audit with HTML report
    %s --once                           # Single audit cycle with server submission
    %s --service                        # Run as background service
    %s --install                        # Install Windows service
    %s --bootstrap-token 123456 --once  # Bootstrap and run once

DEPLOYMENT NOTES:
    - Agent always fetches policies from server (no local policy files)
    - All modes require initial server connection for policy download
    - Service mode runs with server-hardcoded interval (default: 1 hour)
    - Use --install to deploy as Windows service in production

`, os.Args[0], defaultServerURL, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func newServerHTTPClient(bootstrapToken, serverURL string, skipMTLS bool) (*tlsclient.Client, error) {
	if skipMTLS {
		return tlsclient.NewInsecure(), nil
	}
	// Extract base URL (remove /agent suffix if present)
	baseURL := strings.TrimSuffix(serverURL, "/agent")
	cm, err := enroll.EnsureCertificateWithServer(context.Background(), bootstrapToken, baseURL)
	if err != nil {
		return nil, fmt.Errorf("ensure cert: %w", err)
	}
	return tlsclient.New(*cm.Certificate, cm.CA)
}

func buildAuthHeader(creds enroll.Credentials) string {
	return fmt.Sprintf("Bearer %s:%s", strings.TrimSpace(creds.AgentID), strings.TrimSpace(creds.AgentSecret))
}

func agentSession(bootstrapToken, serverEndpoint, hostname string, skipMTLS bool) (*tlsclient.Client, string, error) {
	client, err := newServerHTTPClient(bootstrapToken, serverEndpoint, skipMTLS)
	if err != nil {
		return nil, "", err
	}
	trimmed := strings.TrimRight(serverEndpoint, "/")
	if skipMTLS {
		// For testing without mTLS, create dummy credentials
		return client, "Bearer test:test", nil
	}
	creds, err := enroll.EnsureCredentials(context.Background(), client, trimmed, hostname)
	if err != nil {
		return nil, "", err
	}
	return client, buildAuthHeader(creds), nil
}

func loadConfig() map[string]string {
	config := make(map[string]string)
	configPath := filepath.Join(exeDir(), "agent.conf")

	file, err := os.Open(configPath)
	if err != nil {
		return config // Return empty config if file doesn't exist
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			config[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return config
}

func getConfigValue(config map[string]string, key, defaultValue string) string {
	if val, ok := config[key]; ok && val != "" {
		return val
	}
	return defaultValue
}

func defaultOutName(ext string) string {
	host := mustHostname()
	ts := time.Now().Format("20060102_150405")
	return fmt.Sprintf("%s_%s.%s", ts, host, ext)
}

// Policy caching and health check logic
func getOrFetchPolicy(httpClient *tlsclient.Client, serverEndpoint, authHeader string) (policy.Bundle, error) {
	cacheFile := filepath.Join(exeDir(), "data", "policy_cache.json")

	// TEMPORARY: Skip health check and always fetch fresh policy
	log.Printf("Bypassing health check - always fetching fresh policy from server")

	// // Try to load cached policy first
	// if cached, version, err := loadCachedPolicy(cacheFile); err == nil {
	//	log.Printf("Found cached policy v%d", version)
	//
	//	// Health check: compare server version with cached version
	//	if serverVersion, err := checkPolicyVersion(httpClient, serverEndpoint, authHeader); err == nil {
	//		if serverVersion == version {
	//			log.Printf("Policy up to date (v%d), using cache", version)
	//			return cached, nil
	//		}
	//		log.Printf("Policy outdated (cached: v%d, server: v%d), fetching new policy", version, serverVersion)
	//	} else {
	//		log.Printf("Health check failed: %v, using cached policy", err)
	//		return cached, nil // Use cache when server unreachable
	//	}
	// } else {
	//	log.Printf("No cached policy found: %v", err)
	// }

	// Fetch new policy from server
	log.Printf("Fetching policy from server...")
	pol, err := policy.Fetch(httpClient, serverEndpoint, "windows", authHeader)
	if err != nil {
		return policy.Bundle{}, fmt.Errorf("fetch policy: %w", err)
	}

	// Cache the new policy
	if err := savePolicyCache(cacheFile, pol); err != nil {
		log.Printf("Warning: failed to cache policy: %v", err)
	} else {
		log.Printf("Cached policy v%d", pol.Version)
	}

	return pol, nil
}

func loadCachedPolicy(cacheFile string) (policy.Bundle, int, error) {
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return policy.Bundle{}, 0, fmt.Errorf("cache file not found")
	}

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return policy.Bundle{}, 0, err
	}

	var cached struct {
		Version   int           `json:"version"`
		Timestamp int64         `json:"timestamp"`
		Policy    policy.Bundle `json:"policy"`
	}

	if err := json.Unmarshal(data, &cached); err != nil {
		return policy.Bundle{}, 0, err
	}

	// Check if cache is too old (optional: expire after 24h)
	if time.Now().Unix()-cached.Timestamp > 86400 {
		return policy.Bundle{}, 0, fmt.Errorf("cache expired")
	}

	return cached.Policy, cached.Version, nil
}

func savePolicyCache(cacheFile string, pol policy.Bundle) error {
	// Ensure data directory exists
	if err := os.MkdirAll(filepath.Dir(cacheFile), 0755); err != nil {
		return err
	}

	cached := struct {
		Version   int           `json:"version"`
		Timestamp int64         `json:"timestamp"`
		Policy    policy.Bundle `json:"policy"`
	}{
		Version:   pol.Version,
		Timestamp: time.Now().Unix(),
		Policy:    pol,
	}

	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(cacheFile, data, 0644)
}

func checkPolicyVersion(httpClient *tlsclient.Client, serverEndpoint, authHeader string) (int, error) {
	url := fmt.Sprintf("%s/health", serverEndpoint)
	req, _ := http.NewRequest("GET", url, nil)

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("health check failed: %s", resp.Status)
	}

	var health struct {
		ActiveVersion int `json:"active_version"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return 0, err
	}

	return health.ActiveVersion, nil
}

func main() {
	// Load configuration file
	config := loadConfig()

	serviceCmd := flag.NewFlagSet("service", flag.ExitOnError)
	auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)

	var flagSvcVerb string
	serviceCmd.StringVar(&flagSvcVerb, "action", "run", "install|uninstall|start|stop|run")

	var (
		aJSON  = auditCmd.Bool("json", false, "Output JSON to stdout or --out")
		aHTML  = auditCmd.Bool("html", false, "Render HTML report to --out")
		aExcel = auditCmd.Bool("excel", false, "Export XLSX report to --out")
	)

	var (
		tServer    = flag.String("server", getConfigValue(config, "SERVER_URL", defaultServerURL), "Server URL")
		tOnce      = flag.Bool("once", false, "Fetch policy from server, run audit once, and submit results")
		tLocal     = flag.Bool("local", false, "Fetch policy from server, run audit locally, DO NOT submit results")
		tService   = flag.Bool("service", false, "Run as Windows service with periodic audit cycles")
		tLog       = flag.String("log-file", getConfigValue(config, "LOG_FILE", ""), "Log file path (defaults to Program Files when running as service)")
		tBootstrap = flag.String("bootstrap-token", getConfigValue(config, "BOOTSTRAP_TOKEN", ""), "Bootstrap OTT token (falls back to VT_AGENT_BOOTSTRAP_TOKEN)")
		tJSON      = flag.Bool("json", false, "With --local: print JSON report to stdout")
		tHTML      = flag.Bool("html", false, "With --local: render HTML report")
		tExcel     = flag.Bool("excel", false, "With --local: export XLSX report")
		tSkipMTLS  = flag.Bool("skip-mtls", false, "Skip mTLS for testing (use insecure HTTP client)")
		tInstall   = flag.Bool("install", false, "Install as Windows service")
		tUninstall = flag.Bool("uninstall", false, "Uninstall Windows service")
	)
	fmt.Printf("DEBUG: About to parse flags\n")
	flag.Parse()
	fmt.Printf("DEBUG: Flags parsed, args count: %d\n", len(flag.Args()))

	// Handle service management commands first
	if *tInstall {
		if err := installService(); err != nil {
			log.Fatalf("Service installation failed: %v", err)
		}
		log.Printf("VT-Agent service installed successfully")
		return
	}

	if *tUninstall {
		if err := uninstallService(); err != nil {
			log.Fatalf("Service uninstallation failed: %v", err)
		}
		log.Printf("VT-Agent service uninstalled successfully")
		return
	}

	// Handle legacy subcommands for backward compatibility
	args := flag.Args()
	if len(args) > 0 {
		fmt.Printf("DEBUG: Got subcommand: %s\n", args[0])
		switch args[0] {
		case "service":
			_ = serviceCmd.Parse(args[1:])
			runServiceMode(flagSvcVerb, *tServer, *tBootstrap)
			return
		case "audit":
			_ = auditCmd.Parse(args[1:])
			runAuditLocal("", *aJSON, *aHTML, *aExcel, *tBootstrap, *tServer)
			return
		default:
			printUsage()
			os.Exit(2)
		}
	}

	fmt.Printf("DEBUG: About to init logger with log-file=%s\n", *tLog)
	initLogger(*tService, *tLog) // Use file logging for service mode
	fmt.Printf("DEBUG: Logger initialized\n")

	log.Printf("VT-Agent starting - server=%s, local=%t, once=%t, service=%t", *tServer, *tLocal, *tOnce, *tService)

	host := mustHostname()
	log.Printf("Starting agent session with hostname=%s", host)

	// All modes require server connection - no local policy files
	httpClient, authHeader, err := agentSession(*tBootstrap, *tServer, host, *tSkipMTLS)
	if err != nil {
		log.Fatalf("agent session error: %v", err)
	}

	if *tLocal {
		// Local mode: fetch policy, run audit locally, do NOT submit results
		log.Printf("Running in LOCAL mode - results will NOT be submitted to server")
		if err := runLocalAudit(httpClient, *tServer, host, authHeader, *tJSON, *tHTML, *tExcel); err != nil {
			log.Fatalf("Local audit failed: %v", err)
		}
		return
	}

	if *tOnce {
		// Once mode: fetch policy, run audit, submit results once
		log.Printf("Running in ONCE mode - single audit cycle with result submission")
		if err := runOnce(httpClient, *tServer, host, authHeader); err != nil {
			log.Fatalf("Once mode failed: %v", err)
		}
		return
	}

	if *tService {
		// Service mode: run periodic audits with server-defined interval
		log.Printf("Running in SERVICE mode - periodic audit cycles")
		runServiceMode("run", *tServer, *tBootstrap)
		return
	}

	// Default mode: auto-detect based on environment
	if runtime.GOOS == "windows" && len(os.Args) == 1 {
		// Windows with no args: run once
		log.Printf("Auto-detected ONCE mode for Windows")
		if err := runOnce(httpClient, *tServer, host, authHeader); err != nil {
			log.Fatalf("Run failed: %v", err)
		}
		return
	}

	// Fallback: continuous mode with hardcoded interval
	poll := 3600 // 1 hour - server hardcoded interval
	log.Printf("Running in CONTINUOUS mode - polling interval: %d seconds", poll)
	for {
		if err := runOnce(httpClient, *tServer, host, authHeader); err != nil {
			log.Printf("Run error: %v", err)
		}
		time.Sleep(time.Duration(poll) * time.Second)
	}
}

func runServiceMode(action, serverEndpoint, bootstrapToken string) {
	switch strings.ToLower(action) {
	case "install":
		exe, _ := os.Executable()
		binPath := fmt.Sprintf(`"%s service --action run"`, exe)
		cmd := exec.Command("sc.exe", "create", "VTAgent", "binPath=", binPath, "start=", "auto")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("service install failed: %v", err)
		}
		_ = runShell(`sc.exe description VTAgent "VT Agent - Compliance baseline scanner"`)

	case "uninstall":
		_ = runShell(`sc.exe stop VTAgent`)
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
		initLogger(true, "")
		host := mustHostname()
		httpClient, authHeader, err := agentSession(bootstrapToken, serverEndpoint, host, false)
		if err != nil {
			log.Fatalf("agent session error: %v", err)
		}
		poll := 600

		if svcwin.IsWindowsService() {
			r := &svcRunner{
				httpClient:  httpClient,
				serverURL:   serverEndpoint,
				hostname:    host,
				intervalSec: poll,
				authHeader:  authHeader,
			}
			if err := svcwin.Run("VTAgent", svcwin.NewService(r)); err != nil {
				log.Fatalf("service run error: %v", err)
			}
			return
		}

		for {
			if err := runOnce(httpClient, serverEndpoint, host, authHeader); err != nil {
				log.Printf("Run error: %v", err)
			}
			time.Sleep(time.Duration(poll) * time.Second)
		}

	default:
		log.Fatalf("unknown service action: %s", action)
	}
}

func runAuditLocal(policyFile string, outJSON, outHTML, outExcel bool, bootstrapToken, serverEndpoint string) {
	if !outJSON && !outHTML && !outExcel {
		outJSON = true
	}

	// Always fetch policy from server - no local policy files supported
	log.Printf("Fetching policy from server (local policy files not supported)...")
	host := mustHostname()
	client, authHeader, err := agentSession(bootstrapToken, serverEndpoint, host, false)
	if err != nil {
		log.Fatalf("TLS client error: %v", err)
	}

	pol, err := policy.Fetch(client, serverEndpoint, "windows", authHeader)
	if err != nil {
		log.Fatalf("fetch policy: %v", err)
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

func runLocalAudit(client *tlsclient.Client, serverEndpoint, hostname, authHeader string, asJSON, asHTML, asExcel bool) error {
	if !asJSON && !asHTML && !asExcel {
		asJSON = true
	}

	log.Printf("Fetching policy from server for local audit...")
	pol, err := getOrFetchPolicy(client, serverEndpoint, authHeader)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}

	log.Printf("Running local audit with policy v%d...", pol.Version)
	results, err := audit.Execute(struct {
		Version  int
		Policies []map[string]interface{}
	}{Version: pol.Version, Policies: pol.Policies}, "windows")
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	log.Printf("Local audit completed with %d results. Generating reports...", len(results))

	switch {
	case asExcel:
		data, err := render.Excel(results)
		if err != nil {
			return err
		}
		if err := os.WriteFile(defaultOutName("xlsx"), data, 0o644); err != nil {
			return err
		}
		log.Printf("Excel report saved to %s", defaultOutName("xlsx"))
	case asHTML:
		htmlStr, err := render.HTML(results)
		if err != nil {
			return err
		}
		if err := os.WriteFile(defaultOutName("html"), []byte(htmlStr), 0o644); err != nil {
			return err
		}
		log.Printf("HTML report saved to %s", defaultOutName("html"))
	default:
		b, _ := json.MarshalIndent(map[string]any{
			"os": "windows", "hostname": hostname, "results": results,
		}, "", "  ")
		if err := os.WriteFile(defaultOutName("json"), b, 0o644); err != nil {
			return err
		}
		log.Printf("JSON report saved to %s", defaultOutName("json"))
	}

	log.Printf("Local audit completed successfully - results NOT submitted to server")
	return nil
}

func installService() error {
	// Install VT-Agent as Windows service
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	cmd := exec.Command("sc", "create", "VT-Agent",
		"binPath=", fmt.Sprintf(`"%s" --service`, exePath),
		"DisplayName=", "VT Compliance Agent",
		"start=", "auto")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sc create failed: %w", err)
	}

	return nil
}

func uninstallService() error {
	// Stop service first
	exec.Command("sc", "stop", "VT-Agent").Run()

	// Delete service
	cmd := exec.Command("sc", "delete", "VT-Agent")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sc delete failed: %w", err)
	}

	return nil
}

func runOnce(httpClient *tlsclient.Client, serverEndpoint, hostname, authHeader string) error {
	log.Printf("Starting audit cycle - fetching policy from server...")

	// Get current policy (with caching and health check)
	pol, err := getOrFetchPolicy(httpClient, serverEndpoint, authHeader)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}

	log.Printf("Running audit with policy v%d...", pol.Version)
	results, err := audit.Execute(struct {
		Version  int
		Policies []map[string]interface{}
	}{Version: pol.Version, Policies: pol.Policies}, "windows")
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	log.Printf("Audit completed with %d results - submitting to server...", len(results))
	if err := report.PostResults(httpClient, serverEndpoint, "windows", hostname, authHeader, results); err != nil {
		return fmt.Errorf("post results: %w", err)
	}

	log.Printf("Successfully submitted %d audit results for policy v%d", len(results), pol.Version)
	return nil
}

type svcRunner struct {
	httpClient  *tlsclient.Client
	serverURL   string
	hostname    string
	intervalSec int
	authHeader  string
}

func (s *svcRunner) RunOnce(_ context.Context) error {
	return runOnce(s.httpClient, s.serverURL, s.hostname, s.authHeader)
}

func (s *svcRunner) PollInterval() int { return s.intervalSec }
