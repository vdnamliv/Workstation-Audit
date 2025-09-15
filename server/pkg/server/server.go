package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

/* ========== Config & Types ========== */

type Config struct {
	Addr     string
	CertFile string
	KeyFile  string
	RulesDir string
	DBPath   string
	AdminKey string
	PGDSN    string // reserved for future
}

type ResultsPayload struct {
	AgentID  string `json:"agent_id"`
	RunID    string `json:"run_id"`
	OS       string `json:"os"`
	Hostname string `json:"hostname"`
	Results  []struct {
		PolicyID string `json:"policy_id"`
		ID       string `json:"id"`
		Title    string `json:"title"`
		Status   string `json:"status"`
		Expected string `json:"expected"`
		Reason   string `json:"reason"`
		Fix      string `json:"fix"`
	} `json:"results"`
}

type store struct{ db *sql.DB }

/* ---------- Policy active (RAM snapshot) ---------- */

type activePolicy struct {
	PolicyID string          `json:"policy_id"`
	OS       string          `json:"os"`
	Version  int             `json:"version"`
	Hash     string          `json:"hash"`
	Config   json.RawMessage `json:"config"` // {"version":X,"policies":[...]}
}

type policyRAM struct{ win activePolicy }

func jsonHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func normalizePolicies(rules []map[string]interface{}) {
	for _, r := range rules {
		if v, ok := r["querry"]; ok { // normalize misspelled field
			r["query"] = v
			delete(r, "querry")
		}
	}
}

/* ========== Entry ========== */

func Run(cfg Config) error {
	// DB open/init
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0755); err != nil {
		return err
	}
	st, err := openDB(cfg.DBPath)
	if err != nil { return err }
	defer st.db.Close()
	if err := st.initSchema(); err != nil { return err }
	if err := st.initPolicySchema(); err != nil { return err }

	// Seed policy if none: read YAML → version=1
	ap, err := st.loadActivePolicy("windows")
	if err != nil { return err }
	if ap == nil {
		rules, _ := loadWindowsPolicies(cfg.RulesDir)
		normalizePolicies(rules)
		cfgBlob, _ := json.Marshal(struct {
			Version  int                        `json:"version"`
			Policies []map[string]interface{}   `json:"policies"`
		}{Version: 1, Policies: rules})
		hash := jsonHash(cfgBlob)
		if err := st.insertPolicyVersion("win_baseline", "windows", 1, cfgBlob, hash, string(mustYAML(rules))); err != nil {
			return err
		}
		if err := st.setActivePolicy("windows", "win_baseline", 1); err != nil {
			return err
		}
		ap, _ = st.loadActivePolicy("windows")
	}
	active := policyRAM{win: *ap}

	/* ================== Routes ================== */

	mux := http.NewServeMux()

	// --- Agent enroll / policy / results (giữ nguyên) ---
	// Redirect root to dashboard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/", http.StatusFound)
	})

	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { http.Error(w, "method", http.StatusMethodNotAllowed); return }
		var in struct {
			EnrollmentKey string `json:"enrollment_key"`
			Hostname      string `json:"hostname"`
			OS            string `json:"os"`
			Arch          string `json:"arch"`
			Version       string `json:"version"`
			Fingerprint   string `json:"fingerprint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest); return
		}
		if in.EnrollmentKey != "ORG_KEY_DEMO" {
			http.Error(w, "bad enrollment key", http.StatusForbidden); return
		}
		aid, sec, err := st.upsertAgent(in.Hostname, in.OS, in.Fingerprint)
		if err != nil { http.Error(w, "db error", http.StatusInternalServerError); return }
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent_id": aid, "agent_secret": sec, "poll_interval_sec": 30,
		})
	})

	// Compat: agent cũ
	mux.HandleFunc("/policies", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := st.authAgent(r); !ok { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
		var tmp struct {
			Version  int                        `json:"version"`
			Policies []map[string]interface{}   `json:"policies"`
		}
		_ = json.Unmarshal(active.win.Config, &tmp)
		_ = json.NewEncoder(w).Encode(tmp)
	})

	// Agent mới: enroll policy meta
	mux.HandleFunc("/policy/enroll", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policy_id": active.win.PolicyID,
			"version":   active.win.Version,
			"hash":      active.win.Hash,
			"config":    json.RawMessage(active.win.Config),
		})
	})
	// Agent mới: healthcheck
	mux.HandleFunc("/policy/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			OS       string `json:"os"`
			PolicyID string `json:"policy_id"`
			Version  int    `json:"version"`
			Hash     string `json:"hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest); return
		}
		ap2, _ := st.loadActivePolicy("windows")
		if ap2 == nil { http.Error(w, "no policy", http.StatusNotFound); return }
		active.win = *ap2 // refresh snapshot

		if req.PolicyID == active.win.PolicyID && req.Version == active.win.Version && req.Hash == active.win.Hash {
			_ = json.NewEncoder(w).Encode(map[string]any{"status":"ok"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":"update",
			"policy": map[string]any{
				"policy_id": active.win.PolicyID,
				"version":   active.win.Version,
				"hash":      active.win.Hash,
				"config":    json.RawMessage(active.win.Config),
			},
		})
	})

	// Agent results (flattened)
	mux.HandleFunc("/results", func(w http.ResponseWriter, r *http.Request) {
		aid, _, ok := st.authAgent(r)
		if !ok { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
		var payload ResultsPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest); return
		}
		if err := st.replaceLatestResults(aid, payload); err != nil {
			http.Error(w, "db error", http.StatusInternalServerError); return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "stored": len(payload.Results)})
	})

	// --- Admin reload from YAML (giữ) ---
	mux.HandleFunc("/reload_policies", func(w http.ResponseWriter, r *http.Request) {
		if !allowAdmin(cfg, r) { http.Error(w, "forbidden", http.StatusForbidden); return }
		newRules, err := loadWindowsPolicies(cfg.RulesDir)
		if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
		normalizePolicies(newRules)
		cur, _ := st.loadActivePolicy("windows")
		nextV := 1; if cur != nil { nextV = cur.Version + 1 }
		cfgBlob, _ := json.Marshal(struct {
			Version  int                        `json:"version"`
			Policies []map[string]interface{}   `json:"policies"`
		}{Version: nextV, Policies: newRules})
		hash := jsonHash(cfgBlob)
		if err := st.insertPolicyVersion("win_baseline","windows",nextV,cfgBlob,hash,string(mustYAML(newRules))); err != nil {
			http.Error(w,"db error",500); return
		}
		if err := st.setActivePolicy("windows","win_baseline",nextV); err != nil {
			http.Error(w,"db error",500); return
		}
		active.win = activePolicy{PolicyID:"win_baseline",OS:"windows",Version:nextV,Hash:hash,Config:cfgBlob}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok":true,"version":nextV,"hash":hash})
	})

	/* ================== JSON APIs for UI ================== */

	// Health (UI)
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok":true,"active_version":active.win.Version})
	})

	// Results filter API
	mux.HandleFunc("/api/results", func(w http.ResponseWriter, r *http.Request) {
		host   := strings.TrimSpace(r.URL.Query().Get("host"))
		q      := strings.TrimSpace(r.URL.Query().Get("q"))
		from   := strings.TrimSpace(r.URL.Query().Get("from")) // YYYY-MM-DD
		to     := strings.TrimSpace(r.URL.Query().Get("to"))

		where := []string{}
		args  := []any{}
		if host != "" {
			where = append(where, "LOWER(rf.hostname) LIKE ?")
			args = append(args, "%"+strings.ToLower(host)+"%")
		}
		if q != "" {
			where = append(where, "(LOWER(rf.policy_title) LIKE ? OR LOWER(rf.reason) LIKE ?)")
			args = append(args, "%"+strings.ToLower(q)+"%", "%"+strings.ToLower(q)+"%")
		}
		if from != "" {
			if ts, ok := parseDate(from); ok {
				where = append(where, "rf.received_at >= ?")
				args = append(args, ts)
			}
		}
		if to != "" {
			if ts, ok := parseDate(to); ok {
				where = append(where, "rf.received_at < ?")
				args = append(args, ts+86400)
			}
		}

		query := `
			WITH latest AS (
			  SELECT agent_id, MAX(received_at) AS ts
			  FROM results_flat
			  GROUP BY agent_id
			)
			SELECT rf.received_at, rf.hostname, rf.policy_title, rf.status, rf.expected, rf.reason, rf.fix
			FROM results_flat rf
			INNER JOIN latest ON latest.agent_id = rf.agent_id AND latest.ts = rf.received_at
		`
		if len(where) > 0 { query += " WHERE " + strings.Join(where, " AND ") }
		query += " ORDER BY rf.received_at DESC, rf.agent_id"

		rows, err := st.db.Query(query, args...)
		if err != nil { http.Error(w,"db",500); return }
		defer rows.Close()

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
		for rows.Next() {
			var ts int64
			var h,title,stt,exp,rea,fix string
			if err := rows.Scan(&ts,&h,&title,&stt,&exp,&rea,&fix); err == nil {
				out = append(out, Row{
					Time: time.Unix(ts,0).Format("2006-01-02 15:04:05"),
					Host: h, Policy: title, Status: stt, Expected: exp, Reason: rea, Fix: fix,
				})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	})

	// Active policy (for editor)
	mux.HandleFunc("/api/policy/active", func(w http.ResponseWriter, r *http.Request) {
		ap2, _ := st.loadActivePolicy("windows")
		if ap2 == nil { http.Error(w,"no policy",404); return }
		// Prefer the stored YAML of that version if present; else dump from JSON
		yamlText, _ := st.getPolicyYAML(ap2.PolicyID, ap2.Version)
		if yamlText == "" {
			var tmp struct{ Policies []map[string]interface{} `json:"policies"` }
			_ = json.Unmarshal(ap2.Config, &tmp)
			yamlText = string(mustYAML(tmp.Policies))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policy_id": ap2.PolicyID,
			"version":   ap2.Version,
			"hash":      ap2.Hash,
			"yaml":      yamlText,
		})
	})

	// Policy history (list)
	mux.HandleFunc("/api/policy/history", func(w http.ResponseWriter, r *http.Request) {
		rows, err := st.db.Query(`SELECT policy_id, os, version, hash, updated_at FROM policy_versions WHERE os='windows' ORDER BY version DESC`)
		if err != nil { http.Error(w,"db",500); return }
		defer rows.Close()
		type H struct {
			PolicyID string `json:"policy_id"`
			Version  int    `json:"version"`
			Hash     string `json:"hash"`
			Updated  string `json:"updated"`
		}
		var out []H
		for rows.Next() {
			var pid, osName, hash string
			var ver int
			var ts int64
			if err := rows.Scan(&pid,&osName,&ver,&hash,&ts); err == nil {
				out = append(out, H{PolicyID: pid, Version: ver, Hash: hash, Updated: time.Unix(ts,0).Format(time.RFC3339)})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	})

	// Save new version from YAML & activate (admin)
	mux.HandleFunc("/api/policy/save", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { http.Error(w,"method",405); return }
		if !allowAdmin(cfg,r) { http.Error(w,"forbidden",403); return }
		var in struct{ YAML string `json:"yaml"` }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil { http.Error(w,"bad json",400); return }
		var rules []map[string]interface{}
		if err := yaml.Unmarshal([]byte(in.YAML), &rules); err != nil { http.Error(w,"yaml parse: "+err.Error(),400); return }
		normalizePolicies(rules)
		cur, _ := st.loadActivePolicy("windows")
		nextV := 1; if cur != nil { nextV = cur.Version + 1 }
		cfgBlob, _ := json.Marshal(struct {
			Version  int                        `json:"version"`
			Policies []map[string]interface{}   `json:"policies"`
		}{Version: nextV, Policies: rules})
		hash := jsonHash(cfgBlob)
		if err := st.insertPolicyVersion("win_baseline","windows",nextV,cfgBlob,hash,in.YAML); err != nil { http.Error(w,"db",500); return }
		if err := st.setActivePolicy("windows","win_baseline",nextV); err != nil { http.Error(w,"db",500); return }
		_ = json.NewEncoder(w).Encode(map[string]any{"ok":true,"version":nextV,"hash":hash})
	})

	// Activate specific version (admin)
	mux.HandleFunc("/api/policy/activate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { http.Error(w,"method",405); return }
		if !allowAdmin(cfg,r) { http.Error(w,"forbidden",403); return }
		var in struct {
			PolicyID string `json:"policy_id"`
			Version  int    `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil { http.Error(w,"bad json",400); return }
		if in.PolicyID == "" || in.Version <= 0 { http.Error(w,"bad args",400); return }
		if err := st.setActivePolicy("windows", in.PolicyID, in.Version); err != nil { http.Error(w,"db",500); return }
		_ = json.NewEncoder(w).Encode(map[string]any{"ok":true})
	})

	// ---------- Static UI under /app/* ----------
	// Put your SPA/static files in server/ui (or server/ui/dist) and visit http://host:port/app/
	staticDir := "server/ui"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		_ = os.MkdirAll(staticDir, 0755)
		// seed a tiny index so you have something to see
		_ = os.WriteFile(filepath.Join(staticDir,"index.html"), []byte(sampleIndexHTML()), 0644)
	}
	mux.Handle("/app/", http.StripPrefix("/app/", http.FileServer(http.Dir(staticDir))))

	// Health (root)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	log.Printf("server listening on %s (rules=%s db=%s)", cfg.Addr, cfg.RulesDir, cfg.DBPath)
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		return http.ListenAndServeTLS(cfg.Addr, cfg.CertFile, cfg.KeyFile, mux)
	}
	return http.ListenAndServe(cfg.Addr, mux)
}

/* ========== DB: agents/results (giữ nguyên) ========== */

func openDB(path string) (*store, error) {
	dsn := fmt.Sprintf("file:%s?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil { return nil, err }
	return &store{db: db}, nil
}

func (s *store) initSchema() error {
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS agents (
			agent_id     TEXT PRIMARY KEY,
			agent_secret TEXT NOT NULL,
			hostname     TEXT,
			os           TEXT,
			fingerprint  TEXT UNIQUE,
			enrolled_at  INTEGER,
			last_seen    INTEGER
		);`); err != nil { return err }

	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS results_flat (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id     TEXT NOT NULL,
			hostname     TEXT,
			os           TEXT,
			run_id       TEXT,
			received_at  INTEGER,
			policy_title TEXT,
			status       TEXT,
			expected     TEXT,
			reason       TEXT,
			fix          TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_results_flat_agent_time ON results_flat(agent_id, received_at);`)
	return err
}

/* ========== DB: policy versioning ========== */

func (s *store) initPolicySchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS policy_versions (
  policy_id  TEXT NOT NULL,
  os         TEXT NOT NULL,
  version    INTEGER NOT NULL,
  config     TEXT NOT NULL,   -- JSON blob {"version":X,"policies":[...]}
  hash       TEXT NOT NULL,
  yaml_src   TEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(policy_id, os, version)
);
CREATE TABLE IF NOT EXISTS policy_heads (
  os         TEXT PRIMARY KEY,
  policy_id  TEXT NOT NULL,
  version    INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
`)
	return err
}

func (s *store) insertPolicyVersion(policyID, osName string, version int, cfgJSON []byte, hash string, yamlText string) error {
	_, err := s.db.Exec(`INSERT INTO policy_versions(policy_id, os, version, config, hash, yaml_src, updated_at)
VALUES(?,?,?,?,?,?,?) ON CONFLICT(policy_id,os,version) DO UPDATE SET config=excluded.config, hash=excluded.hash, yaml_src=excluded.yaml_src, updated_at=excluded.updated_at`,
		policyID, osName, version, string(cfgJSON), hash, yamlText, time.Now().Unix())
	return err
}
func (s *store) setActivePolicy(osName, policyID string, version int) error {
	_, err := s.db.Exec(`INSERT INTO policy_heads(os, policy_id, version, updated_at)
VALUES(?,?,?,?) ON CONFLICT(os) DO UPDATE SET policy_id=excluded.policy_id, version=excluded.version, updated_at=excluded.updated_at`,
		osName, policyID, version, time.Now().Unix())
	return err
}
func (s *store) loadActivePolicy(osName string) (*activePolicy, error) {
	row := s.db.QueryRow(`SELECT h.policy_id, v.os, v.version, v.config, v.hash
FROM policy_heads h
JOIN policy_versions v ON v.policy_id=h.policy_id AND v.os=? AND v.version=h.version
WHERE h.os=?`, osName, osName)
	var pid, osnm, cfg, hash string
	var ver int
	if err := row.Scan(&pid,&osnm,&ver,&cfg,&hash); err != nil {
		if err == sql.ErrNoRows { return nil, nil }
		return nil, err
	}
	return &activePolicy{PolicyID: pid, OS: osnm, Version: ver, Hash: hash, Config: json.RawMessage(cfg)}, nil
}
func (s *store) getPolicyYAML(policyID string, version int) (string, error) {
	var y string
	err := s.db.QueryRow(`SELECT yaml_src FROM policy_versions WHERE policy_id=? AND os='windows' AND version=?`, policyID, version).Scan(&y)
	if err == sql.ErrNoRows { return "", nil }
	return y, err
}

/* ========== Agents helper ========== */

func (s *store) upsertAgent(hostname, osName, fingerprint string) (string, string, error) {
	now := time.Now().Unix()
	aid := ""
	if fingerprint != "" {
		_ = s.db.QueryRow(`SELECT agent_id FROM agents WHERE fingerprint=?`, fingerprint).Scan(&aid)
	}
	if aid == "" { aid = fmt.Sprintf("ag_%d", time.Now().UnixMilli()) }
	sec := "s_" + randHex(16)
	if _, err := s.db.Exec(`
		INSERT INTO agents(agent_id, agent_secret, hostname, os, fingerprint, enrolled_at, last_seen)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(agent_id) DO UPDATE SET agent_secret=excluded.agent_secret, hostname=excluded.hostname, os=excluded.os, last_seen=excluded.last_seen
	`, aid, sec, hostname, osName, fingerprint, now, now); err != nil {
		return "", "", err
	}
	return aid, sec, nil
}

func (s *store) authAgent(r *http.Request) (string, struct{}, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") { return "", struct{}{}, false }
	parts := strings.SplitN(h[len("Bearer "):], ":", 2)
	if len(parts) != 2 { return "", struct{}{}, false }
	aid, sec := parts[0], parts[1]
	var dbSec string
	if err := s.db.QueryRow(`SELECT agent_secret FROM agents WHERE agent_id=?`, aid).Scan(&dbSec); err != nil {
		return "", struct{}{}, false
	}
	if subtle.ConstantTimeCompare([]byte(dbSec), []byte(sec)) != 1 { return "", struct{}{}, false }
	_, _ = s.db.Exec(`UPDATE agents SET last_seen=? WHERE agent_id=?`, time.Now().Unix(), aid)
	return aid, struct{}{}, true
}

func (s *store) replaceLatestResults(aid string, payload ResultsPayload) error {
	tx, err := s.db.Begin()
	if err != nil { return err }
	defer func(){ if err != nil { _=tx.Rollback() } }()

	// delete old snapshot for this agent
	if _, err = tx.Exec(`DELETE FROM results_flat WHERE agent_id=?`, aid); err != nil { return err }

	stmt, err := tx.Prepare(`
		INSERT INTO results_flat(agent_id, hostname, os, run_id, received_at, policy_title, status, expected, reason, fix)
		VALUES(?,?,?,?,?,?,?,?,?,?)`)
	if err != nil { return err }
	defer stmt.Close()

	now := time.Now().Unix()
	for _, rr := range payload.Results {
		fixToStore := "None"
		if strings.EqualFold(rr.Status, "FAIL") && strings.TrimSpace(rr.Fix) != "" {
			fixToStore = rr.Fix
		}
		if _, err = stmt.Exec(aid, payload.Hostname, payload.OS, payload.RunID, now,
			rr.Title, rr.Status, rr.Expected, rr.Reason, fixToStore); err != nil {
			return err
		}
	}
	return tx.Commit()
}

/* ========== Rules loader & helpers ========== */

func loadWindowsPolicies(rulesDir string) ([]map[string]interface{}, error) {
	p := filepath.Join(rulesDir, "windows.yml")
	raw, err := os.ReadFile(p)
	if err != nil { return nil, fmt.Errorf("read %s: %w", p, err) }
	var rules []map[string]interface{}
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	return rules, nil
}

func mustYAML(v any) []byte {
	b, _ := yaml.Marshal(v)
	return b
}

func randHex(n int) string { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }

func allowAdmin(cfg Config, r *http.Request) bool {
	if cfg.AdminKey != "" {
		key := r.URL.Query().Get("k")
		if key == "" { key = r.Header.Get("X-Admin-Key") }
		return subtle.ConstantTimeCompare([]byte(key), []byte(cfg.AdminKey)) == 1
	}
	// nếu không set admin key → chỉ cho localhost
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseDate(s string) (int64, bool) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil { return 0, false }
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
function esc(s){return (''+s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
load();
</script>
</body></html>`
}
