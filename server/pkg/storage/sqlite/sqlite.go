package sqlite

import (
    "crypto/rand"
    "database/sql"
    "encoding/hex"
    "fmt"
    "net/http"
    "strings"
    "time"

    _ "github.com/mattn/go-sqlite3"

    "vt-audit/server/pkg/model"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
    dsn := fmt.Sprintf("file:%s?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL", path)
    db, err := sql.Open("sqlite3", dsn)
    if err != nil { return nil, err }
    return &Store{db: db}, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) InitAgentSchema() error {
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

func (s *Store) InitPolicySchema() error {
    _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS policy_versions (
  policy_id  TEXT NOT NULL,
  os         TEXT NOT NULL,
  version    INTEGER NOT NULL,
  config     TEXT NOT NULL,
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

func (s *Store) InsertPolicyVersion(policyID, osName string, version int, cfgJSON []byte, hash string, yamlText string) error {
    _, err := s.db.Exec(`INSERT INTO policy_versions(policy_id, os, version, config, hash, yaml_src, updated_at)
VALUES(?,?,?,?,?,?,?) ON CONFLICT(policy_id,os,version) DO UPDATE SET config=excluded.config, hash=excluded.hash, yaml_src=excluded.yaml_src, updated_at=excluded.updated_at`,
        policyID, osName, version, string(cfgJSON), hash, yamlText, time.Now().Unix())
    return err
}
func (s *Store) SetActivePolicy(osName, policyID string, version int) error {
    _, err := s.db.Exec(`INSERT INTO policy_heads(os, policy_id, version, updated_at)
VALUES(?,?,?,?) ON CONFLICT(os) DO UPDATE SET policy_id=excluded.policy_id, version=excluded.version, updated_at=excluded.updated_at`,
        osName, policyID, version, time.Now().Unix())
    return err
}
func (s *Store) LoadActivePolicy(osName string) (*model.ActivePolicy, error) {
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
    return &model.ActivePolicy{PolicyID: pid, OS: osnm, Version: ver, Hash: hash, Config: []byte(cfg)}, nil
}
func (s *Store) GetPolicyYAML(policyID string, version int) (string, error) {
    var y string
    err := s.db.QueryRow(`SELECT yaml_src FROM policy_versions WHERE policy_id=? AND os='windows' AND version=?`, policyID, version).Scan(&y)
    if err == sql.ErrNoRows { return "", nil }
    return y, err
}

func (s *Store) UpsertAgent(hostname, osName, fingerprint string) (string, string, error) {
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

func (s *Store) AuthAgent(r *http.Request) (string, struct{}, bool) {
    h := r.Header.Get("Authorization")
    if !strings.HasPrefix(h, "Bearer ") { return "", struct{}{}, false }
    parts := strings.SplitN(h[len("Bearer "):], ":", 2)
    if len(parts) != 2 { return "", struct{}{}, false }
    aid, sec := parts[0], parts[1]
    var dbSec string
    if err := s.db.QueryRow(`SELECT agent_secret FROM agents WHERE agent_id=?`, aid).Scan(&dbSec); err != nil {
        return "", struct{}{}, false
    }
    if subtleConstantTimeCompare([]byte(dbSec), []byte(sec)) != 1 { return "", struct{}{}, false }
    _, _ = s.db.Exec(`UPDATE agents SET last_seen=? WHERE agent_id=?`, time.Now().Unix(), aid)
    return aid, struct{}{}, true
}

func (s *Store) ReplaceLatestResults(aid string, payload model.ResultsPayload) error {
    tx, err := s.db.Begin()
    if err != nil { return err }
    defer func(){ if err != nil { _ = tx.Rollback() } }()

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

func randHex(n int) string { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }

// local inline to avoid importing crypto/subtle directly outside
func subtleConstantTimeCompare(x, y []byte) int {
    // Copy of subtle.ConstantTimeCompare to keep package list minimal here.
    if len(x) != len(y) {
        return 0
    }
    var v byte
    for i := 0; i < len(x); i++ {
        v |= x[i] ^ y[i]
    }
    return subtleByteEq(v, 0)
}
func subtleByteEq(x, y byte) int { z := uint32(x ^ y); z |= z >> 1; z |= z >> 2; z |= z >> 4; z &= 1; return int(^z & 1) }

// Dashboard helpers for SQLite (use '?' style placeholders)
func (s *Store) LatestResults(host, q string, from, to *int64) ([]model.ResultRow, error) {
    where := []string{}
    args := []any{}
    if host != "" { where = append(where, "LOWER(rf.hostname) LIKE ?"); args = append(args, "%"+strings.ToLower(host)+"%") }
    if q != "" { where = append(where, "(LOWER(rf.policy_title) LIKE ? OR LOWER(rf.reason) LIKE ?)");
        args = append(args, "%"+strings.ToLower(q)+"%", "%"+strings.ToLower(q)+"%") }
    if from != nil { where = append(where, "rf.received_at >= ?"); args = append(args, *from) }
    if to != nil { where = append(where, "rf.received_at < ?"); args = append(args, *to) }

    query := `
            WITH latest AS (
              SELECT agent_id, MAX(received_at) AS ts
              FROM results_flat
              GROUP BY agent_id
            )
            SELECT rf.received_at, rf.hostname, rf.policy_title, rf.status, rf.expected, rf.reason, rf.fix
            FROM results_flat rf
            INNER JOIN latest ON latest.agent_id = rf.agent_id AND latest.ts = rf.received_at`
    if len(where) > 0 { query += " WHERE " + strings.Join(where, " AND ") }
    query += " ORDER BY rf.received_at DESC, rf.agent_id"

    rows, err := s.db.Query(query, args...)
    if err != nil { return nil, err }
    defer rows.Close()
    out := []model.ResultRow{}
    for rows.Next() {
        var r model.ResultRow
        if err := rows.Scan(&r.ReceivedAt, &r.Hostname, &r.Policy, &r.Status, &r.Expected, &r.Reason, &r.Fix); err == nil {
            out = append(out, r)
        }
    }
    return out, nil
}

func (s *Store) PolicyHistory() ([]model.PolicyVersion, error) {
    rows, err := s.db.Query(`SELECT policy_id, os, version, hash, updated_at FROM policy_versions WHERE os='windows' ORDER BY version DESC`)
    if err != nil { return nil, err }
    defer rows.Close()
    var out []model.PolicyVersion
    for rows.Next() {
        var v model.PolicyVersion
        if err := rows.Scan(&v.PolicyID, &v.OS, &v.Version, &v.Hash, &v.UpdatedAt); err == nil { out = append(out, v) }
    }
    return out, nil
}
