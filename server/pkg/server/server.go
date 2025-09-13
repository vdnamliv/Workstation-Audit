package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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

	// reserved for future Postgres policy versioning (not used in this minimal patch)
	PGDSN string
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

type policyBundle struct {
	Version  int                      `json:"version"`
	Policies []map[string]interface{} `json:"policies"`
}

/* -------- Minimal in-memory policy store (from YAML) -------- */

type activePolicy struct {
	PolicyID string          `json:"policy_id"`
	OS       string          `json:"os"`
	Version  int             `json:"version"`
	Hash     string          `json:"hash"`
	Config   json.RawMessage `json:"config"` // {"version":X, "policies":[...]}
}

type policyRAM struct {
	win activePolicy
}

func hashJSONRaw(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func normalizePolicies(rules []map[string]interface{}) {
	// sort keys inside each map to keep stable JSON (best effort)
	// policies are small so we just leave as-is; stable hash achieved by Marshal below.
	// Also normalize "querry" -> "query"
	for _, r := range rules {
		if v, ok := r["querry"]; ok {
			r["query"] = v
			delete(r, "querry")
		}
	}
}

/* ========== Entry ========== */

func Run(cfg Config) error {
	// DB
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0755); err != nil {
		return err
	}
	st, err := openDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.db.Close()
	if err := st.initSchema(); err != nil {
		return err
	}

	// Load rules (Windows only trong dự án này) -> active policy in memory
	polWin, err := loadWindowsPolicies(cfg.RulesDir)
	if err != nil {
		log.Printf("rules load warning: %v (serve empty set)", err)
	}
	normalizePolicies(polWin)

	// build active policy JSON blob
	ap := policyRAM{}
	ap.win = makeActivePolicyFromRules("win_baseline", "windows", 1, polWin)

	// HTTP mux
	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": ap.win.Version})
	})

	// ------------- NEW: policy enroll -------------
	mux.HandleFunc("/policy/enroll", func(w http.ResponseWriter, r *http.Request) {
		// hiện hỗ trợ windows, query param os để dành
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policy_id": ap.win.PolicyID,
			"version":   ap.win.Version,
			"hash":      ap.win.Hash,
			"config":    json.RawMessage(ap.win.Config),
		})
	})

	// ------------- NEW: policy healthcheck -------------
	mux.HandleFunc("/policy/healthcheck", func(w http.ResponseWriter, r *http.Request) {
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
		// so sánh với active policy hiện tại
		if req.PolicyID == ap.win.PolicyID && req.Version == ap.win.Version && req.Hash == ap.win.Hash {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "update",
			"policy": map[string]any{
				"policy_id": ap.win.PolicyID,
				"version":   ap.win.Version,
				"hash":      ap.win.Hash,
				"config":    json.RawMessage(ap.win.Config),
			},
		})
	})

	// Enroll (agent creds) – giữ nguyên
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			EnrollmentKey string `json:"enrollment_key"`
			Hostname      string `json:"hostname"`
			OS            string `json:"os"`
			Arch          string `json:"arch"`
			Version       string `json:"version"`
			Fingerprint   string `json:"fingerprint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if in.EnrollmentKey != "ORG_KEY_DEMO" {
			http.Error(w, "bad enrollment key", http.StatusForbidden)
			return
		}
		aid, sec, err := st.upsertAgent(in.Hostname, in.OS, in.Fingerprint)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent_id":          aid,
			"agent_secret":      sec,
			"poll_interval_sec": 30, // server điều khiển interval
		})
	})

	// Policies (cũ) – vẫn giữ để tương thích agent cũ
	mux.HandleFunc("/policies", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := st.authAgent(r); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(policyBundle{Version: ap.win.Version, Policies: decodeBundlePolicies(ap.win.Config)})
	})

	// Results (flattened)
	mux.HandleFunc("/results", func(w http.ResponseWriter, r *http.Request) {
		aid, _, ok := st.authAgent(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var payload ResultsPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if err := st.replaceLatestResults(aid, payload); err != nil {
			log.Printf("replaceLatestResults error: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "stored": len(payload.Results)})
	})

	// Reload rules (admin key hoặc localhost) – tăng version + tính hash mới
	mux.HandleFunc("/reload_policies", func(w http.ResponseWriter, r *http.Request) {
		if cfg.AdminKey != "" {
			key := r.URL.Query().Get("k")
			if key == "" {
				key = r.Header.Get("X-Admin-Key")
			}
			if subtle.ConstantTimeCompare([]byte(key), []byte(cfg.AdminKey)) != 1 {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		} else {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		newPol, err := loadWindowsPolicies(cfg.RulesDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		normalizePolicies(newPol)
		ap.win = makeActivePolicyFromRules(ap.win.PolicyID, ap.win.OS, ap.win.Version+1, newPol)

		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": ap.win.Version, "hash": ap.win.Hash})
	})

	// Dashboard (latest snapshot per agent)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rows, err := st.db.Query(`
			WITH latest AS (
			  SELECT agent_id, MAX(received_at) AS ts
			  FROM results_flat
			  GROUP BY agent_id
			)
			SELECT rf.received_at, rf.hostname, rf.policy_title, rf.status, rf.expected, rf.reason, rf.fix
			FROM results_flat rf
			INNER JOIN latest ON latest.agent_id = rf.agent_id AND latest.ts = rf.received_at
			ORDER BY rf.received_at DESC, rf.agent_id
		`)
		if err != nil {
			http.Error(w, "db query", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var trs []string
		esc := html.EscapeString
		for rows.Next() {
			var ts int64
			var host, title, status, expected, reason, fix string
			if err := rows.Scan(&ts, &host, &title, &status, &expected, &reason, &fix); err != nil {
				continue
			}
			cls := map[string]string{"PASS": "PASS", "FAIL": "FAIL"}[strings.ToUpper(status)]
			tm := time.Unix(ts, 0).Format("2006-01-02 15:04:05")
			trs = append(trs, fmt.Sprintf(
				"<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><pre>%s</pre></td><td><pre>%s</pre></td><td><pre>%s</pre></td></tr>",
				cls, esc(tm), esc(host), esc(title), esc(status), esc(expected), esc(reason), esc(fix),
			))
		}
		page := fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><style>
		body{font-family:Arial} table{border-collapse:collapse;width:100%%}
		th,td{border:1px solid #ccc;padding:6px} th{background:#f4f4f4}
		.PASS{background:#d4edda}.FAIL{background:#f8d7da} pre{white-space:pre-wrap;margin:0}
		</style></head><body>
		<h2>Compliance Dashboard</h2>
		<form method="POST" action="/reload_policies"><button>Reload policies</button></form>
		<table>
		  <tr><th>Time</th><th>Host</th><th>Policy</th><th>Status</th><th>Expected</th><th>Reason</th><th>Fix</th></tr>
		  %s
		</table>
		</body></html>`, strings.Join(trs, ""))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	log.Printf("server listening on %s (rules=%s db=%s) [policy=%s v%d hash=%s]",
		cfg.Addr, cfg.RulesDir, cfg.DBPath, ap.win.PolicyID, ap.win.Version, ap.win.Hash)

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		return http.ListenAndServeTLS(cfg.Addr, cfg.CertFile, cfg.KeyFile, mux)
	}
	return http.ListenAndServe(cfg.Addr, mux)
}

/* ========== DB layer (unchanged) ========== */

func openDB(path string) (*store, error) {
	dsn := fmt.Sprintf("file:%s?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	return &store{db: db}, nil
}

func (s *store) initSchema() error {
	// agents
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS agents (
			agent_id     TEXT PRIMARY KEY,
			agent_secret TEXT NOT NULL,
			hostname     TEXT,
			os           TEXT,
			fingerprint  TEXT UNIQUE,
			enrolled_at  INTEGER,
			last_seen    INTEGER
		);
	`); err != nil {
		return err
	}
	// results_flat
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
		CREATE INDEX IF NOT EXISTS idx_results_flat_agent_time ON results_flat(agent_id, received_at);
	`)
	return err
}

func (s *store) upsertAgent(hostname, osName, fingerprint string) (string, string, error) {
	now := time.Now().Unix()
	aid := ""
	if fingerprint != "" {
		_ = s.db.QueryRow(`SELECT agent_id FROM agents WHERE fingerprint=?`, fingerprint).Scan(&aid)
	}
	if aid == "" {
		aid = fmt.Sprintf("ag_%d", time.Now().UnixMilli())
	}
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
	if !strings.HasPrefix(h, "Bearer ") {
		return "", struct{}{}, false
	}
	parts := strings.SplitN(h[len("Bearer "):], ":", 2)
	if len(parts) != 2 {
		return "", struct{}{}, false
	}
	aid, sec := parts[0], parts[1]

	var dbSec string
	if err := s.db.QueryRow(`SELECT agent_secret FROM agents WHERE agent_id=?`, aid).Scan(&dbSec); err != nil {
		return "", struct{}{}, false
	}
	if subtle.ConstantTimeCompare([]byte(dbSec), []byte(sec)) != 1 {
		return "", struct{}{}, false
	}
	_, _ = s.db.Exec(`UPDATE agents SET last_seen=? WHERE agent_id=?`, time.Now().Unix(), aid)
	return aid, struct{}{}, true
}

func (s *store) replaceLatestResults(aid string, payload ResultsPayload) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// delete old snapshot for this agent
	if _, err = tx.Exec(`DELETE FROM results_flat WHERE agent_id=?`, aid); err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
		INSERT INTO results_flat(agent_id, hostname, os, run_id, received_at, policy_title, status, expected, reason, fix)
		VALUES(?,?,?,?,?,?,?,?,?,?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().Unix()
	for _, rr := range payload.Results {
		fixToStore := "None"
		if strings.EqualFold(rr.Status, "FAIL") && strings.TrimSpace(rr.Fix) != "" {
			fixToStore = rr.Fix
		}
		if _, err = stmt.Exec(
			aid, payload.Hostname, payload.OS, payload.RunID, now,
			rr.Title, rr.Status, rr.Expected, rr.Reason, fixToStore,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

/* ========== Rules loader & helpers ========== */

func loadWindowsPolicies(rulesDir string) ([]map[string]interface{}, error) {
	p := filepath.Join(rulesDir, "windows.yml")
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	var rules []map[string]interface{}
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	return rules, nil
}

func makeActivePolicyFromRules(policyID, osName string, version int, rules []map[string]interface{}) activePolicy {
	// wrap to {version, policies}
	cfg := struct {
		Version  int                        `json:"version"`
		Policies []map[string]interface{}   `json:"policies"`
	}{Version: version, Policies: rules}

	// stable JSON (sort map keys by re-marshal) – best effort
	blob, _ := json.Marshal(cfg)
	// to make hash less sensitive to key order in inner maps, we can sort by "id" if exists
	sort.SliceStable(cfg.Policies, func(i, j int) bool {
		idi, _ := cfg.Policies[i]["id"].(string)
		idj, _ := cfg.Policies[j]["id"].(string)
		return idi < idj
	})
	blob, _ = json.Marshal(cfg)

	return activePolicy{
		PolicyID: policyID,
		OS:       osName,
		Version:  version,
		Hash:     hashJSONRaw(blob),
		Config:   blob,
	}
}

func decodeBundlePolicies(cfg json.RawMessage) []map[string]interface{} {
	var tmp struct {
		Version  int                        `json:"version"`
		Policies []map[string]interface{}   `json:"policies"`
	}
	if err := json.Unmarshal(cfg, &tmp); err != nil {
		return nil
	}
	return tmp.Policies
}

/* ========== helpers ========== */

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
