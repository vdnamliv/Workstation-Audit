package httpagent

import (
	"crypto/subtle"
	"encoding/json"
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
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if s.Provisioner == nil {
		http.Error(w, "stepca unavailable", http.StatusServiceUnavailable)
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

func (s *Server) requireClientCert(w http.ResponseWriter, r *http.Request) bool {
	require := s.CertIssuer != nil || s.Provisioner != nil
	if !require {
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
	if _, _, ok := s.Store.AuthAgent(r); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.requireClientCert(w, r) {
		return
	}
	if s.active == nil {
		http.Error(w, "no policy", http.StatusNotFound)
		return
	}
	var tmp struct {
		Version  int                      `json:"version"`
		Policies []map[string]interface{} `json:"policies"`
	}
	_ = json.Unmarshal(s.active.Config, &tmp)
	_ = json.NewEncoder(w).Encode(tmp)
}

func (s *Server) handlePolicyEnroll(w http.ResponseWriter, r *http.Request) {
	ap, _ := s.Store.LoadActivePolicy("windows")
	if !s.requireClientCert(w, r) {
		return
	}
	if ap != nil {
		s.active = ap
	}
	if s.active == nil {
		http.Error(w, "no policy", http.StatusNotFound)
		return
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

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	if !s.requireClientCert(w, r) {
		return
	}
	aid, _, ok := s.Store.AuthAgent(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var payload model.ResultsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := s.Store.ReplaceLatestResults(aid, payload); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
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
