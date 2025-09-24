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
	"strings"
	"time"

	"vt-audit/agent/pkg/audit"
	"vt-audit/agent/pkg/enroll"
	"vt-audit/agent/pkg/policy"
	"vt-audit/agent/pkg/render"
	"vt-audit/agent/pkg/svcwin"
	"vt-audit/agent/pkg/tlsclient"
	"vt-audit/agent/pkg/report"
)

const (
	serverURL = "https://gateway.local/agent"
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

func newServerHTTPClient() (*tlsclient.Client, error) {
	cm, err := enroll.EnsureCertificate(context.Background())
	if err != nil {
		return nil, fmt.Errorf("ensure cert: %w", err)
	}
	return tlsclient.New(*cm.Certificate, cm.CA)
}

func defaultOutName(ext string) string {
	host := mustHostname()
	ts := time.Now().Format("20060102_150405")
	return fmt.Sprintf("%s_%s.%s", ts, host, ext)
}

func main() {
	// ===== subcommands =====
	serviceCmd := flag.NewFlagSet("service", flag.ExitOnError)
	auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)

	var flagSvcVerb string
	serviceCmd.StringVar(&flagSvcVerb, "action", "run", "install|uninstall|start|stop|run")

	var (
		aPolicy = auditCmd.String("policy-file", "", "Local windows.yml (offline)")
		aJSON   = auditCmd.Bool("json", false, "Output JSON to stdout or --out")
		aHTML   = auditCmd.Bool("html", false, "Render HTML report to --out")
		aExcel  = auditCmd.Bool("excel", false, "Export XLSX report to --out")
	)

	var (
		tServer = flag.String("server", serverURL, "Server URL")
		tOnce   = flag.Bool("once", false, "Run one cycle then exit")
		tLog    = flag.String("log-file", "", "Log file path (defaults to Program Files when running as service)")

		tLocal = flag.Bool("local", false, "Run local audit: fetch policies but DO NOT submit to server")
		tJSON  = flag.Bool("json", false, "With --local: print JSON report to stdout")
		tHTML  = flag.Bool("html", false, "With --local: render HTML report")
		tExcel = flag.Bool("excel", false, "With --local: export XLSX report")
	)
	flag.Parse()

	args := flag.Args()
	if len(args) > 0 {
		switch args[0] {
		case "service":
			_ = serviceCmd.Parse(args[1:])
			runServiceMode(flagSvcVerb)
			return
		case "audit":
			_ = auditCmd.Parse(args[1:])
			runAuditLocal(*aPolicy, *aJSON, *aHTML, *aExcel)
			return
		default:
			fmt.Println("Usage: ...")
			os.Exit(2)
		}
	}

	initLogger(false, *tLog)

	if *tLocal {
		if err := localMain(*tJSON, *tHTML, *tExcel); err != nil {
			log.Fatalf("local audit failed: %v", err)
		}
		return
	}

	httpClient, err := newServerHTTPClient()
	if err != nil {
		log.Fatalf("TLS client error: %v", err)
	}

	host := mustHostname()

	if runtime.GOOS == "windows" && len(os.Args) == 1 {
		*tOnce = true
	}

	if *tOnce {
		if err := runOnce(httpClient, *tServer, host); err != nil {
			log.Fatalf("Run failed: %v", err)
		}
		return
	}

	poll := 600 // default interval (seconds)
	log.Printf("Polling interval: %d seconds", poll)
	for {
		if err := runOnce(httpClient, *tServer, host); err != nil {
			log.Printf("Run error: %v", err)
		}
		time.Sleep(time.Duration(poll) * time.Second)
	}
}

/* ==================== service mode ==================== */

func runServiceMode(action string) {
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

		httpClient, err := newServerHTTPClient()
		if err != nil {
			log.Fatalf("TLS client error: %v", err)
		}
		host := mustHostname()
		poll := 600

		if svcwin.IsWindowsService() {
			r := &svcRunner{
				httpClient:  httpClient,
				serverURL:   serverURL,
				hostname:    host,
				intervalSec: poll,
			}
			if err := svcwin.Run("VTAgent", svcwin.NewService(r)); err != nil {
				log.Fatalf("service run error: %v", err)
			}
			return
		}

		for {
			if err := runOnce(httpClient, serverURL, host); err != nil {
				log.Printf("Run error: %v", err)
			}
			time.Sleep(time.Duration(poll) * time.Second)
		}

	default:
		log.Fatalf("unknown service action: %s", action)
	}
}

/* ==================== audit local (subcommand) ==================== */

func runAuditLocal(policyFile string, outJSON, outHTML, outExcel bool) {
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
		httpClient, err := newServerHTTPClient()
		if err != nil {
			log.Fatalf("TLS client error: %v", err)
		}
		pol, err = policy.Fetch(httpClient, serverURL, "windows")
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

func localMain(asJSON, asHTML, asExcel bool) error {
	if !asJSON && !asHTML && !asExcel {
		asJSON = true
	}

	client, err := newServerHTTPClient()
	if err != nil {
		return fmt.Errorf("TLS: %w", err)
	}

	pol, err := policy.Fetch(client, serverURL, "windows")
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

func runOnce(httpClient *tlsclient.Client, serverURL, hostname string) error {
	// 1) fetch policies
	pol, err := policy.Fetch(httpClient, serverURL, "windows")
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
	if err := report.PostResults(httpClient, serverURL, "windows", hostname, results); err != nil {
		return fmt.Errorf("post results: %w", err)
	}
	log.Printf("Sent %d results", len(results))
	return nil
}

type svcRunner struct {
	httpClient  *tlsclient.Client
	serverURL   string
	hostname    string
	intervalSec int
}

func (s *svcRunner) RunOnce(_ context.Context) error {
	return runOnce(s.httpClient, s.serverURL, s.hostname)
}
func (s *svcRunner) PollInterval() int { return s.intervalSec }
