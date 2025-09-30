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
		mux.HandleFunc(prefix+"/results", s.withAuth("", s.handleResults))
		mux.HandleFunc(prefix+"/policy/active", s.withAuth("", s.handlePolicyActive))
		mux.HandleFunc(prefix+"/policy/history", s.withAuth("", s.handlePolicyHistory))
		mux.HandleFunc(prefix+"/policy/save", s.withAuth(s.adminRole, s.handlePolicySave))
		mux.HandleFunc(prefix+"/policy/activate", s.withAuth(s.adminRole, s.handlePolicyActivate))
	}

	// Administrative helper retained for compatibility
	mux.HandleFunc("/reload_policies", s.handleReloadPolicies)

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
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	from := strings.TrimSpace(r.URL.Query().Get("from")) // YYYY-MM-DD
	to := strings.TrimSpace(r.URL.Query().Get("to"))

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

	rowsData, err := s.Store.LatestResults(host, q, fromTS, toTS)
	if err != nil {
		http.Error(w, "db", 500)
		return
	}

	type Row struct {
		Time     string `json:"time"`
		Host     string `json:"host"`
		Policy   string `json:"policy"`
		Status   string `json:"status"`
		Expected string `json:"expected"`
		Reason   string `json:"reason"`
		Fix      string `json:"fix"`
	}
	var out []Row
	for _, r := range rowsData {
		out = append(out, Row{
			Time: time.Unix(r.ReceivedAt, 0).Format("2006-01-02 15:04:05"),
			Host: r.Hostname, Policy: r.Policy, Status: r.Status, Expected: r.Expected, Reason: r.Reason, Fix: r.Fix,
		})
	}
	_ = json.NewEncoder(w).Encode(out)
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
	if !s.allowAdmin(r) {
		http.Error(w, "forbidden", 403)
		return
	}
	var in struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	var rules []map[string]interface{}
	if err := yaml.Unmarshal([]byte(in.YAML), &rules); err != nil {
		http.Error(w, "yaml parse: "+err.Error(), 400)
		return
	}
	policy.NormalizePolicies(rules)
	cur, _ := s.Store.LoadActivePolicy("windows")
	nextV := 1
	if cur != nil {
		nextV = cur.Version + 1
	}
	cfgBlob, _ := json.Marshal(struct {
		Version  int                      `json:"version"`
		Policies []map[string]interface{} `json:"policies"`
	}{Version: nextV, Policies: rules})
	hash := policy.JSONHash(cfgBlob)
	if err := s.Store.InsertPolicyVersion("win_baseline", "windows", nextV, cfgBlob, hash, in.YAML); err != nil {
		http.Error(w, "db", 500)
		return
	}
	if err := s.Store.SetActivePolicy("windows", "win_baseline", nextV); err != nil {
		http.Error(w, "db", 500)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": nextV, "hash": hash})
}

func (s *Server) handlePolicyActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	if !s.allowAdmin(r) {
		http.Error(w, "forbidden", 403)
		return
	}
	var in struct {
		PolicyID string `json:"policy_id"`
		Version  int    `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if in.PolicyID == "" || in.Version <= 0 {
		http.Error(w, "bad args", 400)
		return
	}
	if err := s.Store.SetActivePolicy("windows", in.PolicyID, in.Version); err != nil {
		http.Error(w, "db", 500)
		return
	}
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
	if s.Cfg.AdminKey != "" {
		key := r.URL.Query().Get("k")
		if key == "" {
			key = r.Header.Get("X-Admin-Key")
		}
		if subtleCTCompare([]byte(key), []byte(s.Cfg.AdminKey)) == 1 {
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
