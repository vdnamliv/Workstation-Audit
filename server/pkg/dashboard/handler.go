package dashboard

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	yaml "gopkg.in/yaml.v3"
	"vt-audit/server/pkg/model"
	"vt-audit/server/pkg/policy"
	"vt-audit/server/pkg/storage"
)

type Server struct {
	Store     storage.Store
	Cfg       model.Config
	verifier  *oidc.IDTokenVerifier
	adminRole string
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
	// Redirect root to dashboard for compatibility
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/app/", http.StatusFound) })
	// JSON APIs for UI
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/results", s.withAuth("", s.handleResults))
	mux.HandleFunc("/api/policy/active", s.withAuth("", s.handlePolicyActive))
	mux.HandleFunc("/api/policy/history", s.withAuth("", s.handlePolicyHistory))
	mux.HandleFunc("/api/policy/save", s.withAuth(s.adminRole, s.handlePolicySave))
	mux.HandleFunc("/api/policy/activate", s.withAuth(s.adminRole, s.handlePolicyActivate))

	// Administrative helper retained for compatibility
	mux.HandleFunc("/reload_policies", s.handleReloadPolicies)

	// Static UI under /app/
	staticDir := "server/ui"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		_ = os.MkdirAll(staticDir, 0755)
		_ = os.WriteFile(filepath.Join(staticDir, "index.html"), []byte(sampleIndexHTML()), 0644)
	}
	mux.Handle("/app/", http.StripPrefix("/app/", http.FileServer(http.Dir(staticDir))))

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
	if s.verifier != nil {
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
