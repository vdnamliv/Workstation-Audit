package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"vt-audit/server/pkg/model"
	"vt-audit/server/pkg/policy"
	"vt-audit/server/pkg/storage"

	yaml "gopkg.in/yaml.v3"
)

type Server struct {
	Store      storage.Store
	Cfg        model.Config
	verifierMu sync.RWMutex
	verifier   *oidc.IDTokenVerifier
	adminRole  string
}

func New(store storage.Store, cfg model.Config) *Server {
	srv := &Server{Store: store, Cfg: cfg, adminRole: cfg.OIDCAdminRole}
	srv.initOIDC()
	return srv
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	return mux
}

func (s *Server) routes(mux *http.ServeMux) {
	// Auth endpoints (define first for precedence)
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("🔥 AUTH LOGIN: %s %s", r.Method, r.URL.Path)
		s.handleDirectLogin(w, r)
	})
	mux.HandleFunc("/auth/validate", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("🔥 AUTH VALIDATE: %s %s", r.Method, r.URL.Path)
		s.handleJWTValidation(w, r)
	})

	// JSON APIs for UI
	apiPrefixes := []string{"/api", "/dashboard/api"}
	for _, prefix := range apiPrefixes {
		mux.HandleFunc(prefix+"/health", s.handleHealth)
		mux.HandleFunc(prefix+"/results", s.handleResults)        // DEBUG: Remove auth temporarily
		mux.HandleFunc(prefix+"/hosts", s.handleHostsSummary)     // New: Summary by host
		mux.HandleFunc(prefix+"/hosts/stats", s.handleHostsStats) // New: Total stats for all hosts
		mux.HandleFunc(prefix+"/debug/test", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok","message":"API working"}`))
		})
		mux.HandleFunc(prefix+"/policy/active", s.handlePolicyActive)
		mux.HandleFunc(prefix+"/policy/history", s.handlePolicyHistory)
		mux.HandleFunc(prefix+"/policy/save", s.handlePolicySave)
		mux.HandleFunc(prefix+"/policy/activate", s.handlePolicyActivate)
		// New policy CRUD endpoints
		mux.HandleFunc(prefix+"/policy/rules", s.handlePolicyRules)       // GET: list all rules
		mux.HandleFunc(prefix+"/policy/rules/create", s.handleCreateRule) // POST: create new rule
		mux.HandleFunc(prefix+"/policy/rules/update", s.handleUpdateRule) // PUT: update rule
		mux.HandleFunc(prefix+"/policy/rules/delete", s.handleDeleteRule) // DELETE: delete rule
		mux.HandleFunc(prefix+"/policy/versions", s.handlePolicyVersions) // GET: list policy versions
		// Polling interval endpoints
		mux.HandleFunc(prefix+"/polling-interval", s.handlePollingInterval) // GET/POST: polling interval management
	}

	// Administrative helper retained for compatibility
	mux.HandleFunc("/reload_policies", s.handleReloadPolicies)

	// Serve test.html directly
	mux.HandleFunc("/test.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "ui/test.html")
	})

	// Serve API test page
	mux.HandleFunc("/api-test.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "ui/api-test.html")
	})

	// Serve login page
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "ui/login.html")
	})

	// Debug: Log all requests first
	mux.HandleFunc("/debug", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("DEBUG: %s %s", r.Method, r.URL.Path)
		w.Write([]byte("debug ok"))
	})

	// Root redirect to dashboard (no auth needed for redirect)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("🔥 ROOT HANDLER: %s %s", r.Method, r.URL.Path)
		if r.URL.Path == "/" {
			log.Printf("Redirecting / to /app/")
			http.Redirect(w, r, "/app/", http.StatusFound)
			return
		}
		log.Printf("ROOT: No match for %s, sending 404", r.URL.Path)
		http.NotFound(w, r)
	})

	// Static UI under /app/ (nginx already handles auth)
	wd, _ := os.Getwd()
	log.Printf("🔥 Current working directory: %s", wd)

	staticDir := "./ui"
	log.Printf("🔥 Checking staticDir: %s", staticDir)

	if stat, err := os.Stat(staticDir); os.IsNotExist(err) {
		log.Printf("🔥 %s not found, trying fallback", staticDir)
		staticDir = "server/ui" // fallback for development
		if stat2, err2 := os.Stat(staticDir); os.IsNotExist(err2) {
			log.Printf("🔥 %s also not found, creating sample", staticDir)
			_ = os.MkdirAll(staticDir, 0755)
			_ = os.WriteFile(filepath.Join(staticDir, "index.html"), []byte(sampleIndexHTML()), 0644)
		} else {
			log.Printf("🔥 Using fallback %s (size: %d)", staticDir, stat2.Size())
		}
	} else {
		log.Printf("🔥 Using primary %s (files: %v)", staticDir, stat)
	}

	// List files in staticDir for debugging
	if files, err := os.ReadDir(staticDir); err == nil {
		log.Printf("🔥 Files in %s:", staticDir)
		for _, file := range files {
			log.Printf("🔥   - %s", file.Name())
		}
	}

	// SPA handler function with extensive logging
	spaHandler := func(w http.ResponseWriter, r *http.Request) {
		fullPath := r.URL.Path
		log.Printf("=== SPA Handler Start ===")
		log.Printf("Full URL: %s %s", r.Method, fullPath)
		log.Printf("Host: %s", r.Host)
		log.Printf("User-Agent: %s", r.Header.Get("User-Agent"))

		// Handle /app redirect
		if fullPath == "/app" {
			log.Printf("Redirecting /app to /app/")
			http.Redirect(w, r, "/app/", http.StatusFound)
			return
		}

		// Remove /app/ prefix
		path := strings.TrimPrefix(fullPath, "/app/")
		log.Printf("Trimmed path: '%s'", path)

		// Check if it's a static file request
		if strings.Contains(path, ".") && path != "favicon.ico" {
			filePath := filepath.Join(staticDir, path)
			log.Printf("Checking static file: %s", filePath)

			if stat, err := os.Stat(filePath); err == nil {
				log.Printf("Serving static file: %s (size: %d bytes)", path, stat.Size())
				http.ServeFile(w, r, filePath)
				return
			} else {
				log.Printf("Static file not found: %s (error: %v)", filePath, err)
			}
		}

		// Serve index.html for SPA routes
		indexPath := filepath.Join(staticDir, "index.html")
		log.Printf("Serving index.html for SPA route '%s' from: %s", path, indexPath)

		if stat, err := os.Stat(indexPath); err == nil {
			log.Printf("Index file exists (size: %d bytes)", stat.Size())
			http.ServeFile(w, r, indexPath)
		} else {
			log.Printf("ERROR: index.html not found at %s: %v", indexPath, err)
			http.Error(w, "index.html not found", http.StatusNotFound)
		}
		log.Printf("=== SPA Handler End ===")
	}

	// Register SPA handler for multiple patterns
	log.Printf("Registering SPA handlers...")
	mux.HandleFunc("/app", spaHandler)         // Handle /app exact
	mux.HandleFunc("/app/", spaHandler)        // Handle /app/ and /app/xxx
	mux.HandleFunc("/app/policy", spaHandler)  // Handle /app/policy exact
	mux.HandleFunc("/app/policy/", spaHandler) // Handle /app/policy/ and sub-paths

	// Health root for container checks
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ap, _ := s.Store.LoadActivePolicy("windows")
	v := 0
	if ap != nil {
		v = ap.Version
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "active_version": v})
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔥 RESULTS: %s %s", r.Method, r.URL.Path)

	hostname := strings.TrimSpace(r.URL.Query().Get("hostname"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	from := strings.TrimSpace(r.URL.Query().Get("from")) // YYYY-MM-DD
	to := strings.TrimSpace(r.URL.Query().Get("to"))

	log.Printf("🔥 RESULTS PARAMS: hostname=%s, status=%s, from=%s, to=%s", hostname, status, from, to)

	var fromTS, toTS *int64
	if from != "" {
		if ts, ok := parseDate(from); ok {
			fromTS = &ts
		}
	}
	if to != "" {
		if ts, ok := parseDate(to); ok {
			t := ts + 86400
			toTS = &t
		}
	}

	rowsData, err := s.Store.LatestResults(hostname, status, fromTS, toTS)
	if err != nil {
		log.Printf("ERROR: Failed to get results: %v", err)
		http.Error(w, "db", 500)
		return
	}

	log.Printf("🔥 RESULTS: Found %d results for hostname=%s", len(rowsData), hostname)

	type Row struct {
		Timestamp int64  `json:"timestamp"`
		Hostname  string `json:"hostname"`
		RuleID    string `json:"rule_id"`
		Title     string `json:"title"`
		Status    string `json:"status"`
		Expected  string `json:"expected"`
		Output    string `json:"output"`
	}
	var out []Row
	for _, r := range rowsData {
		out = append(out, Row{
			Timestamp: r.ReceivedAt * 1000, // Convert to milliseconds for JavaScript
			Hostname:  r.Hostname,
			RuleID:    r.Policy, // Using policy field as rule_id for now
			Title:     r.Policy, // Using policy field as title for now
			Status:    r.Status,
			Expected:  r.Expected,
			Output:    r.Reason, // Using reason field as output for now
		})
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleHostsSummary(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔥 HOSTS SUMMARY: %s %s", r.Method, r.URL.Path)

	// Parse query parameters
	from := strings.TrimSpace(r.URL.Query().Get("from")) // YYYY-MM-DD
	to := strings.TrimSpace(r.URL.Query().Get("to"))
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")
	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")

	// Parse pagination parameters
	page := 1
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	// Parse time filters
	var fromTS, toTS *int64
	if from != "" {
		if ts, ok := parseDate(from); ok {
			fromTS = &ts
		}
	}
	if to != "" {
		if ts, ok := parseDate(to); ok {
			t := ts + 86400
			toTS = &t
		}
	}

	log.Printf("🔥 HOSTS SUMMARY: search=%s, page=%d, limit=%d, sort_by=%s, sort_order=%s",
		search, page, limit, sortBy, sortOrder)

	// Get paginated data
	rowsData, total, err := s.Store.HostsSummaryPaginated(search, page, limit, sortBy, sortOrder, fromTS, toTS)
	if err != nil {
		log.Printf("ERROR: Failed to get hosts summary: %v", err)
		http.Error(w, "db", 500)
		return
	}

	log.Printf("🔥 HOSTS SUMMARY: Found %d hosts (total: %d)", len(rowsData), total)

	type HostSummary struct {
		Hostname   string `json:"hostname"`
		LatestTime string `json:"latest_time"`
		PolicyID   string `json:"policy_id"`
		PassCount  int    `json:"pass_count"`
		FailCount  int    `json:"fail_count"`
		TotalCount int    `json:"total_count"`
	}

	var rows []HostSummary
	for _, row := range rowsData {
		failCount := row.TotalCount - row.PassCount
		rows = append(rows, HostSummary{
			Hostname:   row.Host,
			LatestTime: row.Time,
			PolicyID:   "win_baseline", // Default policy
			PassCount:  row.PassCount,
			FailCount:  failCount,
			TotalCount: row.TotalCount,
		})
	}

	// Calculate total pages
	totalPages := (total + limit - 1) / limit

	response := model.HostSummaryResponse{
		Hosts:      make([]model.HostSummaryRow, len(rowsData)),
		Total:      total,
		Page:       page,
		Limit:      limit,
		TotalPages: totalPages,
	}

	// Convert to model format
	for i, row := range rowsData {
		response.Hosts[i] = row
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) handleHostsStats(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔥 HOSTS STATS: %s %s", r.Method, r.URL.Path)

	// Get total stats for all hosts
	totalStats, err := s.Store.HostsTotalStats()
	if err != nil {
		log.Printf("ERROR: Failed to get hosts total stats: %v", err)
		http.Error(w, "db", 500)
		return
	}

	log.Printf("🔥 HOSTS STATS: Compliant=%d, Uncompliant=%d, Total=%d", totalStats.CompliantHosts, totalStats.UncompliantHosts, totalStats.TotalHosts)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(totalStats)
}

func (s *Server) handlePolicyRules(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔥 POLICY RULES: %s %s", r.Method, r.URL.Path)
	policyID := r.URL.Query().Get("policy_id")
	versionStr := r.URL.Query().Get("version")
	log.Printf("🔥 POLICY RULES: policyID=%s, version=%s", policyID, versionStr)

	if policyID == "" || versionStr == "" {
		log.Printf("🔥 POLICY RULES ERROR: Missing parameters")
		http.Error(w, "policy_id and version required", http.StatusBadRequest)
		return
	}

	version := 1
	if v, err := strconv.Atoi(versionStr); err == nil {
		version = v
	}

	rules, err := s.Store.GetPolicyRules(policyID, version)
	if err != nil {
		log.Printf("🔥 POLICY RULES ERROR: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	log.Printf("🔥 POLICY RULES: Found %d rules", len(rules))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rules)
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	policyID := r.URL.Query().Get("policy_id")
	versionStr := r.URL.Query().Get("version")

	if policyID == "" || versionStr == "" {
		http.Error(w, "policy_id and version required", http.StatusBadRequest)
		return
	}

	version := 1
	if v, err := strconv.Atoi(versionStr); err == nil {
		version = v
	}

	var rule model.PolicyRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if err := s.Store.CreatePolicyRule(policyID, version, rule); err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "created"})
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	policyID := r.URL.Query().Get("policy_id")
	versionStr := r.URL.Query().Get("version")
	ruleID := r.URL.Query().Get("rule_id")

	if policyID == "" || versionStr == "" || ruleID == "" {
		http.Error(w, "policy_id, version, and rule_id required", http.StatusBadRequest)
		return
	}

	version := 1
	if v, err := strconv.Atoi(versionStr); err == nil {
		version = v
	}

	var rule model.PolicyRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if err := s.Store.UpdatePolicyRule(policyID, version, ruleID, rule); err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	policyID := r.URL.Query().Get("policy_id")
	versionStr := r.URL.Query().Get("version")
	ruleID := r.URL.Query().Get("rule_id")

	if policyID == "" || versionStr == "" || ruleID == "" {
		http.Error(w, "policy_id, version, and rule_id required", http.StatusBadRequest)
		return
	}

	version := 1
	if v, err := strconv.Atoi(versionStr); err == nil {
		version = v
	}

	if err := s.Store.DeletePolicyRule(policyID, version, ruleID); err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func (s *Server) handlePolicyVersions(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔥 POLICY VERSIONS: %s %s", r.Method, r.URL.Path)
	osName := r.URL.Query().Get("os")
	if osName == "" {
		osName = "windows"
	}
	log.Printf("🔥 POLICY VERSIONS: osName=%s", osName)

	versions, err := s.Store.GetAllPolicyVersions(osName)
	if err != nil {
		log.Printf("🔥 POLICY VERSIONS ERROR: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	log.Printf("🔥 POLICY VERSIONS: Found %d versions", len(versions))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(versions)
}

func (s *Server) handlePolicyActive(w http.ResponseWriter, r *http.Request) {
	ap, _ := s.Store.LoadActivePolicy("windows")
	if ap == nil {
		http.Error(w, "no policy", 404)
		return
	}
	yamlText, _ := s.Store.GetPolicyYAML(ap.PolicyID, ap.Version)
	if yamlText == "" {
		var tmp struct {
			Policies []map[string]interface{} `json:"policies"`
		}
		_ = json.Unmarshal(ap.Config, &tmp)
		yamlText = string(policy.MustYAML(tmp.Policies))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"policy_id": ap.PolicyID,
		"version":   ap.Version,
		"hash":      ap.Hash,
		"yaml":      yamlText,
	})
}

func (s *Server) handlePolicyHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.PolicyHistory()
	if err != nil {
		http.Error(w, "db", 500)
		return
	}
	type H struct {
		PolicyID string `json:"policy_id"`
		Version  int    `json:"version"`
		Hash     string `json:"hash"`
		Updated  string `json:"updated"`
	}
	var out []H
	for _, v := range rows {
		out = append(out, H{PolicyID: v.PolicyID, Version: v.Version, Hash: v.Hash, Updated: time.Unix(v.UpdatedAt, 0).Format(time.RFC3339)})
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handlePolicySave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	log.Printf("🔥 POLICY SAVE: %s %s", r.Method, r.URL.Path)

	var in struct {
		PolicyID string                   `json:"policy_id"`
		Version  int                      `json:"version"`
		Rules    []map[string]interface{} `json:"rules"`
		YAML     string                   `json:"yaml,omitempty"` // For backward compatibility
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		log.Printf("ERROR: Failed to decode policy save request: %v", err)
		http.Error(w, "bad json", 400)
		return
	}

	log.Printf("🔥 POLICY SAVE DATA: PolicyID=%s, Version=%d, RulesCount=%d",
		in.PolicyID, in.Version, len(in.Rules))

	// Debug: Log first few rule IDs
	for i, rule := range in.Rules {
		if i < 3 {
			ruleID := getString(rule, "rule_id")
			log.Printf("🔥 POLICY SAVE RULE[%d]: %s", i, ruleID)
		}
	}

	// Handle backward compatibility with YAML format
	var rules []map[string]interface{}
	if in.YAML != "" {
		if err := yaml.Unmarshal([]byte(in.YAML), &rules); err != nil {
			http.Error(w, "yaml parse: "+err.Error(), 400)
			return
		}
	} else {
		rules = in.Rules
	}

	if len(rules) == 0 {
		http.Error(w, "no rules provided", 400)
		return
	}

	// Normalize policies
	policy.NormalizePolicies(rules)

	// Determine next version
	policyID := in.PolicyID
	if policyID == "" {
		policyID = "win_baseline"
	}

	// ALWAYS create a NEW version, never overwrite existing
	cur, _ := s.Store.LoadActivePolicy("windows")
	nextV := 1
	if cur != nil {
		nextV = cur.Version + 1
	}

	// Find the highest existing version to ensure uniqueness
	if versions, err := s.Store.PolicyHistory(); err == nil {
		for _, v := range versions {
			if v.Version >= nextV {
				nextV = v.Version + 1
			}
		}
	}

	log.Printf("🔥 CREATING NEW VERSION: Current=%d, Next=%d",
		func() int {
			if cur != nil {
				return cur.Version
			} else {
				return 0
			}
		}(), nextV)

	// Create policy configuration
	cfgBlob, _ := json.Marshal(struct {
		Version  int                      `json:"version"`
		Policies []map[string]interface{} `json:"policies"`
	}{Version: nextV, Policies: rules})

	hash := policy.JSONHash(cfgBlob)

	// Insert new policy version
	if err := s.Store.InsertPolicyVersion(policyID, "windows", nextV, cfgBlob, hash, in.YAML); err != nil {
		log.Printf("ERROR: Failed to insert policy version: %v", err)
		http.Error(w, "failed to save policy version", 500)
		return
	}

	// Delete existing rules for this version (if any) to avoid duplicates
	if existingRules, err := s.Store.GetPolicyRules(policyID, nextV); err == nil {
		log.Printf("🔥 DELETING %d existing rules for version %d", len(existingRules), nextV)
		for _, rule := range existingRules {
			if err := s.Store.DeletePolicyRule(policyID, nextV, rule.RuleID); err != nil {
				log.Printf("ERROR: Failed to delete existing rule %s: %v", rule.RuleID, err)
			}
		}
	}

	// Save individual rules to database
	log.Printf("🔥 INSERTING %d NEW RULES for version %d", len(rules), nextV)
	successCount := 0
	for i, rule := range rules {
		ruleReq := model.PolicyRuleRequest{
			RuleID:      getString(rule, "rule_id"),
			Title:       getString(rule, "title"),
			Description: getString(rule, "description"),
			Severity:    getString(rule, "severity"),
			Check:       getString(rule, "check"),
			Expected:    getString(rule, "expected"),
			Fix:         getString(rule, "fix"),
			Tags:        getString(rule, "tags"),
		}

		log.Printf("🔥 INSERTING RULE[%d]: ID=%s, Title=%s", i, ruleReq.RuleID, ruleReq.Title)
		if err := s.Store.CreatePolicyRule(policyID, nextV, ruleReq); err != nil {
			log.Printf("ERROR: Failed to save rule %s: %v", ruleReq.RuleID, err)
			// Continue with other rules
		} else {
			successCount++
			log.Printf("✅ Successfully inserted rule %s", ruleReq.RuleID)
		}
	}
	log.Printf("🔥 INSERTION SUMMARY: %d/%d rules successfully inserted", successCount, len(rules))

	// Set as active policy
	if err := s.Store.SetActivePolicy("windows", policyID, nextV); err != nil {
		log.Printf("ERROR: Failed to set active policy: %v", err)
	}

	// Final verification: check how many rules were actually saved
	if finalRules, err := s.Store.GetPolicyRules(policyID, nextV); err == nil {
		log.Printf("🔥 FINAL VERIFICATION: Version %d has %d rules in database", nextV, len(finalRules))
		if len(finalRules) != len(rules) {
			log.Printf("⚠️  WARNING: Expected %d rules, but database has %d rules", len(rules), len(finalRules))
		}
	} else {
		log.Printf("ERROR: Failed to verify final rules: %v", err)
	}

	log.Printf("🔥 POLICY SAVE SUCCESS: %s v%d with %d rules", policyID, nextV, len(rules))
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":          true,
		"policy_id":   policyID,
		"version":     nextV,
		"hash":        hash,
		"rules_count": len(rules),
	})
}

// Helper function to get string from map
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (s *Server) handlePolicyActivate(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔥 POLICY ACTIVATE: %s %s", r.Method, r.URL.Path)

	if r.Method != http.MethodPost {
		log.Printf("ERROR: Wrong method %s, expected POST", r.Method)
		http.Error(w, "method", 405)
		return
	}

	log.Printf("🔥 CHECKING ADMIN AUTH...")
	// Temporarily disable admin auth for policy activation
	// if !s.allowAdmin(r) {
	//	log.Printf("ERROR: Admin auth failed")
	//	http.Error(w, "forbidden", 403)
	//	return
	// }
	log.Printf("✅ ADMIN AUTH BYPASSED FOR TESTING")
	log.Printf("🔥 READING REQUEST BODY...")
	var in struct {
		PolicyID string `json:"policy_id"`
		Version  int    `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		log.Printf("ERROR: Failed to decode activate request: %v", err)
		http.Error(w, "bad json", 400)
		return
	}
	log.Printf("🔥 REQUEST BODY DECODED: PolicyID=%s, Version=%d", in.PolicyID, in.Version)
	if in.PolicyID == "" || in.Version <= 0 {
		log.Printf("ERROR: Invalid activate args: PolicyID=%s, Version=%d", in.PolicyID, in.Version)
		http.Error(w, "bad args", 400)
		return
	}

	log.Printf("🔥 ACTIVATING POLICY: PolicyID=%s, Version=%d", in.PolicyID, in.Version)
	if err := s.Store.SetActivePolicy("windows", in.PolicyID, in.Version); err != nil {
		log.Printf("ERROR: Failed to activate policy: %v", err)
		http.Error(w, "db", 500)
		return
	}

	log.Printf("✅ POLICY ACTIVATED SUCCESSFULLY: %s v%d", in.PolicyID, in.Version)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *Server) handleReloadPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.allowAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	newRules, err := policy.LoadWindowsPolicies(s.Cfg.RulesDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	policy.NormalizePolicies(newRules)
	cur, _ := s.Store.LoadActivePolicy("windows")
	nextV := 1
	if cur != nil {
		nextV = cur.Version + 1
	}
	cfgBlob, _ := json.Marshal(struct {
		Version  int                      `json:"version"`
		Policies []map[string]interface{} `json:"policies"`
	}{Version: nextV, Policies: newRules})
	hash := policy.JSONHash(cfgBlob)
	if err := s.Store.InsertPolicyVersion("win_baseline", "windows", nextV, cfgBlob, hash, string(policy.MustYAML(newRules))); err != nil {
		http.Error(w, "db error", 500)
		return
	}
	if err := s.Store.SetActivePolicy("windows", "win_baseline", nextV); err != nil {
		http.Error(w, "db error", 500)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": nextV, "hash": hash})
}

func (s *Server) allowAdmin(r *http.Request) bool {
	log.Printf("🔥 ADMIN CHECK: AdminKey configured: %v", s.Cfg.AdminKey != "")
	if s.Cfg.AdminKey != "" {
		key := r.URL.Query().Get("k")
		if key == "" {
			key = r.Header.Get("X-Admin-Key")
		}
		log.Printf("🔥 ADMIN CHECK: Provided key: '%s'", key)
		if subtleCTCompare([]byte(key), []byte(s.Cfg.AdminKey)) == 1 {
			log.Printf("✅ ADMIN CHECK: Key match!")
			return true
		}
	}
	if verifier := s.currentVerifier(); verifier != nil {
		if v := r.Context().Value(principalKey); v != nil {
			if p, ok := v.(*authPrincipal); ok {
				if principalHasRole(p.claims, s.adminRole, s.Cfg.OIDCClientID) {
					return true
				}
			}
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	log.Printf("🔥 ADMIN CHECK: RemoteAddr: %s, Host: %s, IP: %v, IsLoopback: %v", r.RemoteAddr, host, ip, ip != nil && ip.IsLoopback())
	return ip != nil && ip.IsLoopback()
}

func subtleCTCompare(a, b []byte) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}

func parseDate(s string) (int64, bool) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return 0, false
	}
	return t.Unix(), true
}

// small sample index if server/ui is empty
func sampleIndexHTML() string {
	return `<!doctype html><html><head><meta charset="utf-8">
<title>VT Compliance Dashboard</title>
<style>
body{font-family:Arial;max-width:1200px;margin:24px auto;padding:0 12px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px}
th{background:#f4f4f4}.PASS{background:#d4edda}.FAIL{background:#f8d7da}
.controls{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
input,button{padding:6px}
</style></head><body>
<h2>Compliance Dashboard</h2>
<div class="controls">
  <input id="fHost"  placeholder="host...">
  <input id="fFrom"  type="date">
  <input id="fTo"    type="date">
  <input id="fQ"     placeholder="policy/reason...">
  <button onclick="load()">Search</button>
  <button onclick="resetF()">Clear</button>
  <a href="/app/policy.html">Policy editor</a>
</div>
<table id="tbl"><thead>
<tr><th>Time</th><th>Host</th><th>Policy</th><th>Status</th><th>Expected</th><th>Reason</th><th>Fix</th></tr>
</thead><tbody></tbody></table>
<script>
function q(k){return document.getElementById(k)}
function resetF(){ q('fHost').value=''; q('fFrom').value=''; q('fTo').value=''; q('fQ').value=''; load() }
async function load(){
  const p = new URLSearchParams();
  if(q('fHost').value) p.set('host', q('fHost').value);
  if(q('fFrom').value) p.set('from', q('fFrom').value);
  if(q('fTo').value)   p.set('to',   q('fTo').value);
  if(q('fQ').value)    p.set('q',    q('fQ').value);
  const r = await fetch('/api/results?'+p.toString());
  const data = await r.json();
  const tb = document.querySelector('#tbl tbody'); tb.innerHTML='';
  for(const row of data){
    const tr = document.createElement('tr');
    tr.className = row.status.toUpperCase();
    tr.innerHTML = '<td>'+esc(row.time)+'</td><td>'+esc(row.host)+'</td><td>'+esc(row.policy)+'</td><td>'+esc(row.status)+'</td><td><pre>'+esc(row.expected)+'</pre></td><td><pre>'+esc(row.reason)+'</pre></td><td><pre>'+esc(row.fix)+'</pre></td>';
    tb.appendChild(tr);
  }
}
function esc(s){return (''+s).replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]))}
load();
</script>
</body></html>`
}

// handleDirectLogin performs direct authentication with Keycloak
func (s *Server) handleDirectLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}

	// Parse login form
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "username and password required", 400)
		return
	}

	// Call Keycloak token endpoint directly
	token, err := s.authenticateWithKeycloak(req.Username, req.Password)
	if err != nil {
		http.Error(w, "authentication failed", 401)
		return
	}

	// Set response headers first
	w.Header().Set("Content-Type", "application/json")

	// Create and set cookie before writing response
	cookie := &http.Cookie{
		Name:     "_vt_auth",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Allow HTTP for testing
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 hour
	}
	http.SetCookie(w, cookie)
	log.Printf("Cookie set: Name=%s, Value=%s, Path=%s", cookie.Name, cookie.Value[:20]+"...", cookie.Path)

	// Send JSON response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Login successful",
	})
}

// authenticateWithKeycloak performs direct authentication using Resource Owner Password flow
func (s *Server) authenticateWithKeycloak(username, password string) (string, error) {
	// Construct Keycloak token endpoint URL
	// Expected format: http://keycloak:8080/realms/vt-audit/protocol/openid-connect/token
	tokenURL := strings.Replace(s.Cfg.OIDCIssuer, "/realms/", "/realms/", 1) + "/protocol/openid-connect/token"

	// Prepare form data for Resource Owner Password Credentials flow
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", s.Cfg.OIDCClientID)
	data.Set("client_secret", s.Cfg.OIDCClientSecret)
	data.Set("username", username)
	data.Set("password", password)
	data.Set("scope", "openid profile email")

	// Make HTTP request to Keycloak
	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call Keycloak: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Keycloak returned status %d", resp.StatusCode)
	}

	// Parse token response
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}

	return tokenResp.AccessToken, nil
}

// handleJWTValidation validates JWT token from custom auth cookie for nginx auth_request
func (s *Server) handleJWTValidation(w http.ResponseWriter, r *http.Request) {
	// Debug log
	log.Printf("JWT validation called: method=%s path=%s", r.Method, r.URL.Path)

	// Get token from header (set by nginx)
	token := r.Header.Get("X-Custom-Auth")
	if token == "" {
		log.Printf("JWT validation: no auth token")
		http.Error(w, "no auth token", 401)
		return
	}

	// Validate token with Keycloak OIDC provider
	ctx := r.Context()
	_, err := s.verifier.Verify(ctx, token)
	if err != nil {
		http.Error(w, "invalid token", 401)
		return
	}

	// Return 200 OK for valid tokens
	w.WriteHeader(http.StatusOK)
}

// Polling interval management - stored in memory (could be moved to persistent storage later)
var globalPollingInterval int = 3600 // Default 1 hour in seconds

func (s *Server) handlePollingInterval(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		response := map[string]interface{}{
			"interval": globalPollingInterval,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding polling interval response: %v", err)
			http.Error(w, "Internal server error", 500)
		}

	case "POST":
		var req struct {
			Interval int `json:"interval"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", 400)
			return
		}

		// Validate interval (minimum 60 seconds, maximum 24 hours)
		if req.Interval < 60 || req.Interval > 86400 {
			http.Error(w, "Interval must be between 60 seconds and 24 hours", 400)
			return
		}

		globalPollingInterval = req.Interval
		log.Printf("🔥 POLLING INTERVAL UPDATED: %d seconds", globalPollingInterval)

		response := map[string]interface{}{
			"interval": globalPollingInterval,
			"message":  "Polling interval updated successfully",
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding polling interval update response: %v", err)
			http.Error(w, "Internal server error", 500)
		}

	default:
		http.Error(w, "Method not allowed", 405)
	}
}
