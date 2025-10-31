package httpagent

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"vt-audit/server/pkg/model"
	"vt-audit/server/pkg/policy"
	"vt-audit/server/pkg/stepca"
	"vt-audit/server/pkg/storage"
)

type Server struct {
	Store       storage.Store
	Cfg         model.Config
	CertIssuer  stepca.CertificateIssuer
	Provisioner stepca.TokenProvisioner

	// cached active policy for quick healthchecks
	active *model.ActivePolicy
}

func New(store storage.Store, cfg model.Config, issuer stepca.CertificateIssuer, provisioner stepca.TokenProvisioner) (*Server, error) {
	ap, err := store.LoadActivePolicy("windows")
	if err != nil {
		return nil, err
	}
	return &Server{Store: store, Cfg: cfg, CertIssuer: issuer, Provisioner: provisioner, active: ap}, nil
}

func (s *Server) routes(mux *http.ServeMux, prefix string) {
	// helper to add optional prefix without duplicate slashes
	p := func(path string) string {
		if prefix == "" || prefix == "/" {
			return path
		}
		if path == "/" {
			return prefix
		}
		if prefix[len(prefix)-1] == '/' {
			return prefix[:len(prefix)-1] + path
		}
		return prefix + path
	}
	mux.HandleFunc(p("/bootstrap/ott"), s.handleBootstrapOTT)
	mux.HandleFunc(p("/enroll"), s.handleEnroll)
	mux.HandleFunc(p("/mtls/cert"), s.handleMTLSCert)
	mux.HandleFunc(p("/policies"), s.handlePoliciesCompat)
	mux.HandleFunc(p("/policy/enroll"), s.handlePolicyEnroll)
	mux.HandleFunc(p("/policy/healthcheck"), s.handlePolicyHealth)
	mux.HandleFunc(p("/health"), s.handleHealth) // For agent policy version check
	mux.HandleFunc(p("/results"), s.handleResults)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux, "")
	return mux
}

// Mount registers agent routes onto an external mux with an optional prefix.
func (s *Server) Mount(mux *http.ServeMux, prefix string) { s.routes(mux, prefix) }

func (s *Server) handleMTLSCert(w http.ResponseWriter, r *http.Request) {
	if s.CertIssuer == nil {
		http.Error(w, "mtls disabled", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		CSR     string `json:"csr"`
		Subject string `json:"subject"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	certPEM, err := s.CertIssuer.SignCSRPEM([]byte(in.CSR))
	if err != nil {
		http.Error(w, "csr invalid", http.StatusBadRequest)
		return
	}
	ttl := s.Cfg.MTLSCertTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"certificate_pem": string(certPEM),
		"ca_pem":          string(s.CertIssuer.BundlePEM()),
		"subject":         strings.TrimSpace(in.Subject),
		"expires_at":      time.Now().Add(ttl).UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleBootstrapOTT(w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG: handleBootstrapOTT called, method=%s, provisioner=%v", r.Method, s.Provisioner != nil)
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	// Temporary bypass mode for testing
	if s.Provisioner == nil {
		log.Printf("WARNING: Step-CA unavailable, using bypass mode for testing")
		s.handleBootstrapBypass(w, r)
		return
	}
	if s.Cfg.AgentBootstrapToken == "" {
		http.Error(w, "bootstrap disabled", http.StatusForbidden)
		return
	}
	var in struct {
		Subject string   `json:"subject"`
		SANs    []string `json:"sans"`
		Token   string   `json:"bootstrap_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		log.Printf("bootstrap OTT request decode failed: %v", err)
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(in.Token), []byte(s.Cfg.AgentBootstrapToken)) != 1 {
		log.Printf("bootstrap OTT denied: subject=%q reason=bad bootstrap token", strings.TrimSpace(in.Subject))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	subject := strings.TrimSpace(in.Subject)
	if subject == "" {
		log.Print("bootstrap OTT denied: subject missing")
		http.Error(w, "subject required", http.StatusBadRequest)
		return
	}
	sans := uniqueStrings(append([]string{subject}, in.SANs...))
	token, expires, err := s.Provisioner.IssueOTT(subject, sans)
	if err != nil {
		log.Printf("bootstrap OTT error: subject=%q error=%v", subject, err)
		http.Error(w, "ott", http.StatusInternalServerError)
		return
	}
	log.Printf("bootstrap OTT issued: subject=%q sans=%v audience=%s expires_at=%s", subject, sans, s.Provisioner.Audience(), expires.UTC().Format(time.RFC3339))
	stepcaURL := strings.TrimSpace(s.Cfg.StepCAExternalURL)
	if stepcaURL == "" {
		stepcaURL = strings.TrimSpace(s.Cfg.StepCAURL)
	}
	log.Printf("DEBUG: stepcaURL=%q (external=%q, internal=%q)", stepcaURL, s.Cfg.StepCAExternalURL, s.Cfg.StepCAURL)
	resp := map[string]any{
		"ott":         token,
		"provisioner": s.Provisioner.Name(),
		"audience":    s.Provisioner.Audience(),
		"stepca_url":  stepcaURL,
		"expires_at":  expires.UTC().Format(time.RFC3339),
	}
	if s.CertIssuer != nil {
		resp["ca_pem"] = string(s.CertIssuer.BundlePEM())
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleBootstrapBypass - temporary bypass for testing without Step-CA
func (s *Server) handleBootstrapBypass(w http.ResponseWriter, r *http.Request) {
	if s.Cfg.AgentBootstrapToken == "" {
		http.Error(w, "bootstrap disabled", http.StatusForbidden)
		return
	}
	var in struct {
		Subject string   `json:"subject"`
		SANs    []string `json:"sans"`
		Token   string   `json:"bootstrap_token"`
	}
	// Debug: read raw body first
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("bootstrap bypass: failed to read body: %v", err)
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	log.Printf("bootstrap bypass: received body: %q", string(bodyBytes))

	if err := json.Unmarshal(bodyBytes, &in); err != nil {
		log.Printf("bootstrap bypass request decode failed: %v", err)
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(in.Token), []byte(s.Cfg.AgentBootstrapToken)) != 1 {
		log.Printf("bootstrap bypass denied: subject=%q reason=bad bootstrap token", strings.TrimSpace(in.Subject))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	subject := strings.TrimSpace(in.Subject)
	if subject == "" {
		log.Print("bootstrap bypass denied: subject missing")
		http.Error(w, "subject required", http.StatusBadRequest)
		return
	}
	log.Printf("bootstrap bypass SUCCESS: subject=%q (testing mode)", subject)

	// Return mock response for testing
	resp := map[string]any{
		"ott":         "mock-ott-token-for-testing",
		"provisioner": "testing-bypass",
		"audience":    "testing",
		"stepca_url":  "http://bypass-mode",
		"expires_at":  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"bypass_mode": true,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) requireClientCert(w http.ResponseWriter, r *http.Request) bool {
	require := s.CertIssuer != nil || s.Provisioner != nil
	if !require {
		return true
	}
	// Allow test mode with specific test header
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Test-Mode")), "true") {
		return true
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Client-Verify")), "SUCCESS") {
		return true
	}
	http.Error(w, "client certificate required", http.StatusUnauthorized)
	return false
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireClientCert(w, r) {
		return
	}
	var in struct {
		Hostname    string `json:"hostname"`
		OS          string `json:"os"`
		Arch        string `json:"arch"`
		Version     string `json:"version"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		log.Printf("bootstrap OTT request decode failed: %v", err)
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	if in.Hostname == "" {
		in.Hostname = clientCommonNameFromRequest(r)
	}
	if strings.TrimSpace(in.Hostname) == "" {
		http.Error(w, "hostname required", http.StatusBadRequest)
		return
	}

	aid, sec, err := s.Store.UpsertAgent(in.Hostname, in.OS, in.Fingerprint)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"agent_id": aid, "agent_secret": sec, "poll_interval_sec": 30,
	})
}

func (s *Server) handlePoliciesCompat(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔥 AGENT POLICIES REQUEST: %s %s", r.Method, r.URL.Path)

	// Allow bypass mode with test header
	bypassMode := strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Test-Mode")), "true")
	log.Printf("DEBUG: handlePoliciesCompat - bypass mode: %t, test header: %q", bypassMode, r.Header.Get("X-Test-Mode"))
	if !bypassMode {
		log.Printf("DEBUG: About to call AuthAgent...")
		aid, _, ok := s.Store.AuthAgent(r)
		log.Printf("DEBUG: AuthAgent returned - aid=%q, ok=%t", aid, ok)
		if !ok {
			log.Printf("DEBUG: AuthAgent failed - returning 401")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	} else {
		log.Printf("DEBUG: Using bypass mode for policies")
	}
	if !s.requireClientCert(w, r) {
		return
	}

	// ALWAYS load fresh active policy from database
	ap, _ := s.Store.LoadActivePolicy("windows")
	log.Printf("🔥 ACTIVE POLICY FROM DB: PolicyID=%s, Version=%d",
		func() string {
			if ap != nil {
				return ap.PolicyID
			} else {
				return "nil"
			}
		}(),
		func() int {
			if ap != nil {
				return ap.Version
			} else {
				return 0
			}
		}())

	// Update cached policy
	if ap != nil {
		s.active = ap
		log.Printf("🔥 UPDATED CACHED POLICY: PolicyID=%s, Version=%d", s.active.PolicyID, s.active.Version)
	}

	if s.active == nil {
		log.Printf("ERROR: No active policy available")
		http.Error(w, "no policy", http.StatusNotFound)
		return
	}

	var tmp struct {
		Version  int                      `json:"version"`
		Policies []map[string]interface{} `json:"policies"`
	}
	_ = json.Unmarshal(s.active.Config, &tmp)
	log.Printf("🔥 SENDING POLICY TO AGENT: PolicyID=%s, Version=%d, Rules=%d",
		s.active.PolicyID, s.active.Version, len(tmp.Policies))

	// Debug: Print first policy rule structure
	if len(tmp.Policies) > 0 {
		firstRule, _ := json.MarshalIndent(tmp.Policies[0], "", "  ")
		log.Printf("🔥 DEBUG FIRST RULE STRUCTURE:\n%s", string(firstRule))
	}

	_ = json.NewEncoder(w).Encode(tmp)
}

func (s *Server) handlePolicyEnroll(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔥 AGENT POLICY ENROLL: %s %s", r.Method, r.URL.Path)
	ap, _ := s.Store.LoadActivePolicy("windows")
	log.Printf("🔥 ACTIVE POLICY FROM DB: PolicyID=%s, Version=%d",
		func() string {
			if ap != nil {
				return ap.PolicyID
			} else {
				return "nil"
			}
		}(),
		func() int {
			if ap != nil {
				return ap.Version
			} else {
				return 0
			}
		}())

	if !s.requireClientCert(w, r) {
		return
	}
	if ap != nil {
		s.active = ap
		log.Printf("🔥 UPDATED CACHED POLICY: PolicyID=%s, Version=%d", s.active.PolicyID, s.active.Version)
	}
	if s.active == nil {
		log.Printf("ERROR: No active policy available")
		http.Error(w, "no policy", http.StatusNotFound)
		return
	}

	// Parse config to count rules
	var config struct {
		Policies []map[string]interface{} `json:"policies"`
	}
	if err := json.Unmarshal(s.active.Config, &config); err == nil {
		log.Printf("🔥 SENDING POLICY TO AGENT: PolicyID=%s, Version=%d, Rules=%d",
			s.active.PolicyID, s.active.Version, len(config.Policies))
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"policy_id": s.active.PolicyID,
		"version":   s.active.Version,
		"hash":      s.active.Hash,
		"config":    json.RawMessage(s.active.Config),
	})
}

func (s *Server) handlePolicyHealth(w http.ResponseWriter, r *http.Request) {
	if !s.requireClientCert(w, r) {
		return
	}
	var req struct {
		OS       string `json:"os"`
		PolicyID string `json:"policy_id"`
		Version  int    `json:"version"`
		Hash     string `json:"hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	ap, _ := s.Store.LoadActivePolicy("windows")
	if ap == nil {
		http.Error(w, "no policy", http.StatusNotFound)
		return
	}
	s.active = ap
	if req.PolicyID == s.active.PolicyID && req.Version == s.active.Version && req.Hash == s.active.Hash {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "update",
		"policy": map[string]any{
			"policy_id": s.active.PolicyID,
			"version":   s.active.Version,
			"hash":      s.active.Hash,
			"config":    json.RawMessage(s.active.Config),
		},
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔥 AGENT HEALTH CHECK: %s %s", r.Method, r.URL.Path)

	// Load fresh active policy from database
	ap, _ := s.Store.LoadActivePolicy("windows")
	log.Printf("🔥 HEALTH CHECK - ACTIVE POLICY: PolicyID=%s, Version=%d",
		func() string {
			if ap != nil {
				return ap.PolicyID
			} else {
				return "nil"
			}
		}(),
		func() int {
			if ap != nil {
				return ap.Version
			} else {
				return 0
			}
		}())

	if ap == nil {
		log.Printf("ERROR: No active policy for health check")
		http.Error(w, "no policy", http.StatusNotFound)
		return
	}

	// Update cached policy
	s.active = ap

	// Return active version for agent version comparison
	_ = json.NewEncoder(w).Encode(map[string]any{
		"active_version": ap.Version,
		"policy_id":      ap.PolicyID,
		"hash":           ap.Hash,
	})
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG: handleResults called - method=%s, url=%s, headers=%v", r.Method, r.URL.String(), r.Header)
	if !s.requireClientCert(w, r) {
		log.Printf("DEBUG: handleResults - requireClientCert failed")
		return
	}
	// Allow bypass mode with test header
	bypassMode := strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Test-Mode")), "true")
	log.Printf("DEBUG: handleResults bypass mode: %t", bypassMode)
	var aid string
	if !bypassMode {
		var ok bool
		aid, _, ok = s.Store.AuthAgent(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	} else {
		aid = "test-agent" // Use dummy agent ID for bypass mode
	}
	log.Printf("DEBUG: handleResults using agent_id: %s", aid)

	var payload model.ResultsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("DEBUG: handleResults JSON decode error: %v", err)
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	log.Printf("DEBUG: handleResults decoded payload with %d results", len(payload.Results))

	// Debug: Log first result to check Title field
	if len(payload.Results) > 0 {
		log.Printf("DEBUG: First result - ID: %s, Title: %s, Status: %s", payload.Results[0].ID, payload.Results[0].Title, payload.Results[0].Status)
	}

	log.Printf("DEBUG: handleResults - about to store %d results to database for agent=%s", len(payload.Results), aid)
	if err := s.Store.ReplaceLatestResults(aid, payload); err != nil {
		log.Printf("ERROR: handleResults database error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	log.Printf("SUCCESS: handleResults - stored %d results for agent=%s", len(payload.Results), aid)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "stored": len(payload.Results)})
}

func clientCommonNameFromRequest(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if cn := strings.TrimSpace(r.TLS.PeerCertificates[0].Subject.CommonName); cn != "" {
			return cn
		}
	}
	if cn := strings.TrimSpace(r.Header.Get("X-Client-CN")); cn != "" {
		return cn
	}
	if subj := strings.TrimSpace(r.Header.Get("X-Client-Subject")); subj != "" {
		if cn := extractCommonName(subj); cn != "" {
			return cn
		}
	}
	return ""
}

func extractCommonName(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if len(part) >= 3 && strings.EqualFold(part[:3], "CN=") {
			return strings.TrimSpace(part[3:])
		}
	}
	return ""
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// Utilities exposed for other modules that need to seed policies.
func SeedIfEmpty(st storage.Store, rulesDir string) (*model.ActivePolicy, error) {
	ap, err := st.LoadActivePolicy("windows")
	if err != nil {
		return nil, err
	}
	if ap != nil {
		return ap, nil
	}
	rules, err := policy.LoadWindowsPolicies(rulesDir)
	if err != nil {
		return nil, err
	}
	policy.NormalizePolicies(rules)
	cfgBlob, _ := json.Marshal(struct {
		Version  int                      `json:"version"`
		Policies []map[string]interface{} `json:"policies"`
	}{Version: 1, Policies: rules})
	hash := policy.JSONHash(cfgBlob)
	if err := st.InsertPolicyVersion("win_baseline", "windows", 1, cfgBlob, hash, string(policy.MustYAML(rules))); err != nil {
		return nil, err
	}
	if err := st.SetActivePolicy("windows", "win_baseline", 1); err != nil {
		return nil, err
	}
	return st.LoadActivePolicy("windows")
}
