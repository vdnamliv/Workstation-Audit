package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"vt-audit/agent/pkg/audit"
	"vt-audit/agent/pkg/enroll"
	"vt-audit/agent/pkg/machineid"
	"vt-audit/agent/pkg/policy"
	"vt-audit/agent/pkg/render"
	"vt-audit/agent/pkg/report"
	"vt-audit/agent/pkg/tlsclient"
)

var (
	// BuildServerURL will be injected at build time using -ldflags
	// Example: go build -ldflags "-X 'main.BuildServerURL=https://server.com:443/agent'"
	BuildServerURL = "https://192.168.1.226:443/agent"
)

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func mustHostname() string {
	host, err := os.Hostname()
	if err != nil {
		log.Fatalf("hostname: %v", err)
	}
	return host
}

func mustMachineID() string {
	machineID, err := machineid.GetMachineID()
	if err != nil {
		log.Fatalf("machine ID: %v", err)
	}
	return machineID
}

func dataDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("Program Files"); pd != "" {
			return filepath.Join(pd, "VT Agent")
		}
	}
	return filepath.Join(exeDir(), "data")
}

func printUsage() {
	fmt.Printf(`VT-Agent - Windows Compliance Monitoring Agent

USAGE:
    %s [OPTIONS]

MODES:
    Default (no flags):  Daemon mode - continuously audits and submits results to server
    With flags:          Local mode - audit once and save report to file

OPTIONS:
    --json           Output JSON report (local mode)
    --html           Output HTML report (local mode)
    --excel          Output Excel report (local mode)

EXAMPLES:
    %s                           # Run as daemon, submit to server
    %s --html                    # Local audit with HTML report

NOTES:
    - Daemon mode: Polling interval configured on server
    - Server URL: %s

`, os.Args[0], os.Args[0], os.Args[0], BuildServerURL)
}

func newServerHTTPClient(serverURL string) (*tlsclient.Client, error) {
	// Extract base URL (remove /agent suffix if present)
	baseURL := strings.TrimSuffix(serverURL, "/agent")
	cm, err := enroll.EnsureCertificateWithServer(context.Background(), baseURL)
	if err != nil {
		return nil, fmt.Errorf("ensure cert: %w", err)
	}

	// Create combined CA pool: Step-CA + Server CA
	combinedCAPool := x509.NewCertPool()
	if cm.CA != nil {
		// Copy existing Step-CA certificates
		combinedCAPool = cm.CA.Clone()
	}

	// Try to load server CA certificate for HTTPS trust
	serverCAPath := filepath.Join("data", "certs", "server-ca.pem")
	if serverCABytes, err := os.ReadFile(serverCAPath); err == nil {
		combinedCAPool.AppendCertsFromPEM(serverCABytes)
	} else {
		// Fallback: try nginx server cert as CA
		nginxCertPath := filepath.Join("env", "certs", "nginx", "server.crt")
		if nginxCABytes, err := os.ReadFile(nginxCertPath); err == nil {
			combinedCAPool.AppendCertsFromPEM(nginxCABytes)
		}
	}

	return tlsclient.New(*cm.Certificate, combinedCAPool)
}

func agentSession(serverEndpoint, agentID string) (*tlsclient.Client, string, error) {
	client, err := newServerHTTPClient(serverEndpoint)
	if err != nil {
		return nil, "", err
	}

	// Production mTLS mode - use certificate-based authentication
	// mTLS certificate is embedded in client - server validates certificate directly
	// No additional credentials enrollment needed for certificate-based authentication
	return client, "", nil
}

func defaultOutName(ext string) string {
	host := mustHostname()
	ts := time.Now().Format("20060102_150405")
	return fmt.Sprintf("%s_%s.%s", ts, host, ext)
}

// Policy caching and health check logic
func getOrFetchPolicy(httpClient *tlsclient.Client, serverEndpoint, authHeader, agentID string) (policy.Bundle, error) {
	cacheFile := filepath.Join(exeDir(), "data", "policy_cache.json")

	// Try to load cached policy first
	if cachedBundle, version, err := loadCachedPolicy(cacheFile); err == nil {
		log.Printf("Found cached policy v%d", version)

		// Enhanced health check: get server policy metadata including hash
		if healthResp, err := checkPolicyHealth(httpClient, serverEndpoint, authHeader); err == nil {
			// Load cache metadata for hash comparison
			if cachedData, err := os.ReadFile(cacheFile); err == nil {
				var cachedMeta PolicyCacheMetadata
				if err := json.Unmarshal(cachedData, &cachedMeta); err == nil {
					// Validate integrity: version AND hash must match
					if healthResp.Policy.Version == version && validatePolicyIntegrity(cachedMeta, healthResp.Policy.Hash) {
						log.Printf("Policy up to date (v%d, hash validated), using cache", version)
						// Report successful policy sync
						reportAgentStatus(httpClient, serverEndpoint, authHeader, agentID, "policy_sync", "Policy up to date")
						return cachedBundle, nil
					}
					log.Printf("Policy outdated or corrupted (cached: v%d/%s, server: v%d/%s), fetching new policy",
						version, cachedMeta.Hash, healthResp.Policy.Version, healthResp.Policy.Hash)

					// Report policy mismatch
					reportAgentStatus(httpClient, serverEndpoint, authHeader, agentID, "policy_mismatch", "Policy hash/version mismatch, re-downloading")

					// Delete corrupted cache
					deletePolicyCache(cacheFile)
				}
			}
		} else {
			log.Printf("Health check failed: %v, using cached policy", err)
			return cachedBundle, nil // Use cache when server unreachable
		}
	} else {
		log.Printf("No cached policy found: %v", err)
	}

	// Fetch new policy from server
	log.Printf("Fetching policy from server...")
	pol, err := policy.Fetch(httpClient, serverEndpoint, "windows", authHeader)
	if err != nil {
		reportAgentStatus(httpClient, serverEndpoint, authHeader, agentID, "policy_fetch_failed", fmt.Sprintf("Failed to fetch policy: %v", err))
		return policy.Bundle{}, fmt.Errorf("fetch policy: %w", err)
	}

	// Cache the new policy
	if err := savePolicyCache(cacheFile, pol); err != nil {
		log.Printf("Warning: failed to cache policy: %v", err)
	} else {
		log.Printf("Cached policy v%d", pol.Version)
		// Report successful policy download
		reportAgentStatus(httpClient, serverEndpoint, authHeader, agentID, "policy_updated", fmt.Sprintf("New policy v%d cached successfully", pol.Version))
	}

	return pol, nil
}

// PolicyCacheMetadata represents the enhanced JSON cache format
type PolicyCacheMetadata struct {
	Version   int                      `json:"version"`
	Hash      string                   `json:"hash"`
	UpdatedAt string                   `json:"updated_at"`
	PolicyID  string                   `json:"policy_id"`
	Timestamp int64                    `json:"timestamp"`
	Policies  []map[string]interface{} `json:"policies"`
}

func loadCachedPolicy(cacheFile string) (policy.Bundle, int, error) {
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return policy.Bundle{}, 0, fmt.Errorf("cache file not found")
	}

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return policy.Bundle{}, 0, err
	}

	var cached PolicyCacheMetadata
	if err := json.Unmarshal(data, &cached); err != nil {
		return policy.Bundle{}, 0, err
	}

	// Check if cache is too old (optional: expire after 24h)
	if time.Now().Unix()-cached.Timestamp > 86400 {
		return policy.Bundle{}, 0, fmt.Errorf("cache expired")
	}

	// Convert back to policy.Bundle format
	bundle := policy.Bundle{
		Version:  cached.Version,
		Policies: cached.Policies,
	}

	return bundle, cached.Version, nil
}

func savePolicyCache(cacheFile string, pol policy.Bundle) error {
	// Ensure data directory exists
	if err := os.MkdirAll(filepath.Dir(cacheFile), 0755); err != nil {
		return err
	}

	// Calculate hash for integrity validation
	policyData, _ := json.Marshal(pol.Policies)
	hash := fmt.Sprintf("sha256:%x", sha256.Sum256(policyData))

	cached := PolicyCacheMetadata{
		Version:   pol.Version,
		Hash:      hash,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		PolicyID:  "windows_baseline",
		Timestamp: time.Now().Unix(),
		Policies:  pol.Policies,
	}

	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(cacheFile, data, 0644)
}

// PolicyHealthResponse represents server response for policy health check
type PolicyHealthResponse struct {
	Policy struct {
		PolicyID string `json:"policy_id"`
		Version  int    `json:"version"`
		Hash     string `json:"hash"`
	} `json:"policy"`
}

func checkPolicyHealth(httpClient *tlsclient.Client, serverEndpoint, authHeader string) (*PolicyHealthResponse, error) {
	url := fmt.Sprintf("%s/health", serverEndpoint)
	req, _ := http.NewRequest("GET", url, nil)

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("health check failed: %s", resp.Status)
	}

	var healthResp PolicyHealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
		return nil, err
	}

	return &healthResp, nil
}

// validatePolicyIntegrity checks if cached policy hash matches server hash
func validatePolicyIntegrity(cached PolicyCacheMetadata, serverHash string) bool {
	if cached.Hash != serverHash {
		log.Printf("⚠️ Policy integrity check failed: cached=%s, server=%s", cached.Hash, serverHash)
		return false
	}
	return true
}

// deletePolicyCache removes corrupted or outdated cache file
func deletePolicyCache(cacheFile string) error {
	if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete cache file: %v", err)
	}
	log.Printf("🗑️ Deleted corrupted policy cache: %s", cacheFile)
	return nil
}

// reportAgentStatus sends agent status to server for monitoring
func reportAgentStatus(httpClient *tlsclient.Client, serverEndpoint, authHeader, agentID, status, details string) error {
	payload := map[string]interface{}{
		"agent_id":  agentID,
		"status":    status, // "online", "offline", "policy_sync", "policy_mismatch", "enrollment"
		"details":   details,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/status", serverEndpoint)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status report failed: %s", resp.Status)
	}

	log.Printf("📊 Agent status reported: %s - %s", status, details)
	return nil
}

func main() {
	var (
		tJSON  = flag.Bool("json", false, "Output JSON report (local mode)")
		tHTML  = flag.Bool("html", false, "Output HTML report (local mode)")
		tExcel = flag.Bool("excel", false, "Output Excel report (local mode)")
	)
	flag.Parse()

	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime)

	host := mustHostname()
	agentID := mustMachineID()

	log.Printf("Connecting to server: %s", BuildServerURL)

	httpClient, authHeader, err := agentSession(BuildServerURL, agentID)
	if err != nil {
		log.Fatalf("Agent session error: %v", err)
	}

	// Check if any output flag is set (local mode)
	if *tJSON || *tHTML || *tExcel {
		// Local report mode - audit once and save to file
		log.Printf("Running in LOCAL REPORT mode...")
		if err := runLocalAudit(httpClient, BuildServerURL, agentID, host, authHeader, *tJSON, *tHTML, *tExcel); err != nil {
			log.Fatalf("Audit failed: %v", err)
		}
	} else {
		// Daemon mode - continuously audit and submit to server
		log.Printf("Running in DAEMON mode - will continuously audit and submit results to server...")
		if err := runDaemonMode(httpClient, BuildServerURL, agentID, host, authHeader); err != nil {
			log.Fatalf("Daemon error: %v", err)
		}
	}
}

// runDaemonMode runs the agent in daemon mode - continuously audits and submits results to server
func runDaemonMode(client *tlsclient.Client, serverEndpoint, agentID, hostname, authHeader string) error {
	log.Printf("Agent %s starting daemon mode...", agentID)

	// Enroll agent with server
	if err := enrollAgent(client, serverEndpoint, hostname, authHeader); err != nil {
		log.Printf("Warning: Agent enrollment failed: %v", err)
	}

	// Main daemon loop
	for {
		// Get policy and polling interval from server
		pol, pollingInterval, err := getOrFetchPolicyWithInterval(client, serverEndpoint, authHeader, agentID)
		if err != nil {
			log.Printf("ERROR: Failed to get policy: %v, retrying in 60s...", err)
			time.Sleep(60 * time.Second)
			continue
		}

		log.Printf("Running audit with policy v%d (next audit in %d seconds)...", pol.Version, pollingInterval)

		// Run audit
		results, err := audit.Execute(struct {
			Version  int
			Policies []map[string]interface{}
		}{Version: pol.Version, Policies: pol.Policies}, "windows")
		if err != nil {
			log.Printf("ERROR: Audit failed: %v", err)
			time.Sleep(60 * time.Second)
			continue
		}

		log.Printf("Audit completed with %d results, submitting to server...", len(results))

		// Submit results to server
		if err := submitResults(client, serverEndpoint, agentID, hostname, authHeader, results); err != nil {
			log.Printf("ERROR: Failed to submit results: %v", err)
		} else {
			log.Printf("✅ Results submitted successfully")
		}

		// Wait for next polling interval
		log.Printf("Sleeping for %d seconds until next audit...", pollingInterval)
		time.Sleep(time.Duration(pollingInterval) * time.Second)
	}
}

// enrollAgent enrolls the agent with the server
func enrollAgent(client *tlsclient.Client, serverEndpoint, hostname, authHeader string) error {
	// Remove /agent suffix to get base URL
	baseURL := strings.TrimSuffix(serverEndpoint, "/agent")
	url := baseURL + "/agent/enroll"

	payload := map[string]interface{}{
		"hostname":    hostname,
		"os":          "windows",
		"arch":        runtime.GOARCH,
		"version":     "1.0.0",
		"fingerprint": mustMachineID(),
	}

	jsonData, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("enrollment failed: %s", resp.Status)
	}

	var enrollResp struct {
		AgentID         string `json:"agent_id"`
		AgentSecret     string `json:"agent_secret"`
		PollIntervalSec int    `json:"poll_interval_sec"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return err
	}

	log.Printf("✅ Agent enrolled successfully: ID=%s, PollInterval=%ds", enrollResp.AgentID, enrollResp.PollIntervalSec)
	return nil
}

// getOrFetchPolicyWithInterval fetches policy and polling interval from server
func getOrFetchPolicyWithInterval(httpClient *tlsclient.Client, serverEndpoint, authHeader, agentID string) (policy.Bundle, int, error) {
	// First, try to get polling interval from server
	pollingInterval := 3600 // Default 1 hour

	baseURL := strings.TrimSuffix(serverEndpoint, "/agent")
	intervalURL := baseURL + "/api/polling-interval"

	req, _ := http.NewRequest("GET", intervalURL, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	if resp, err := httpClient.Do(req); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var intervalResp struct {
				Interval int `json:"interval"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&intervalResp); err == nil && intervalResp.Interval > 0 {
				pollingInterval = intervalResp.Interval
				log.Printf("📊 Polling interval from server: %d seconds", pollingInterval)
			}
		}
	}

	// Get policy using existing function
	pol, err := getOrFetchPolicy(httpClient, serverEndpoint, authHeader, agentID)
	if err != nil {
		return policy.Bundle{}, pollingInterval, err
	}

	return pol, pollingInterval, nil
}

// submitResults submits audit results to server
func submitResults(client *tlsclient.Client, serverEndpoint, agentID, hostname, authHeader string, results []report.Result) error {
	url := fmt.Sprintf("%s/results", serverEndpoint)

	// Convert results to the format expected by server
	var resultMaps []map[string]interface{}
	for _, r := range results {
		resultMaps = append(resultMaps, map[string]interface{}{
			"id":        r.RuleID,
			"title":     r.Title,
			"severity":  r.Severity,
			"status":    r.Status,
			"expected":  r.Expected,
			"reason":    r.Reason,
			"fix":       r.Fix,
			"policy_id": r.PolicyID,
		})
	}

	payload := map[string]interface{}{
		"agent_id": agentID,
		"hostname": hostname,
		"results":  resultMaps,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submit failed: %s - %s", resp.Status, string(bodyBytes))
	}

	log.Printf("Results submitted: %d checks", len(results))
	return nil
}

func runLocalAudit(client *tlsclient.Client, serverEndpoint, agentID, hostname, authHeader string, asJSON, asHTML, asExcel bool) error {
	// If no format specified, default to JSON
	if !asJSON && !asHTML && !asExcel {
		asJSON = true
	}

	log.Printf("Fetching policy from server for local audit...")
	pol, err := getOrFetchPolicy(client, serverEndpoint, authHeader, agentID)
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
			"os": "windows", "hostname": hostname, "agent_id": agentID, "results": results,
		}, "", "  ")
		if err := os.WriteFile(defaultOutName("json"), b, 0o644); err != nil {
			return err
		}
		log.Printf("JSON report saved to %s", defaultOutName("json"))
	}

	log.Printf("Local audit completed successfully - results NOT submitted to server")
	return nil
}
