package postgres

import (
    "crypto/rand"
    "crypto/subtle"
    "database/sql"
    "encoding/hex"
    "fmt"
    "net/http"
    "strings"
    "time"

    _ "github.com/jackc/pgx/v5/stdlib"

    "vt-audit/server/pkg/model"
)

// Store implements storage.Store for PostgreSQL.
// It keeps two schemas in a single database: audit and policy.
type Store struct{ db *sql.DB }

func Open(dsn string) (*Store, error) {
    // dsn example: postgres://user:pass@host:5432/dbname
    db, err := sql.Open("pgx", dsn)
    if err != nil { return nil, err }
    return &Store{db: db}, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) InitAgentSchema() error {
    // Create schemas and tables if not exist
    stmts := []string{
        `CREATE SCHEMA IF NOT EXISTS audit`,
        `CREATE TABLE IF NOT EXISTS audit.agents (
            agent_id     TEXT PRIMARY KEY,
            agent_secret TEXT NOT NULL,
            hostname     TEXT,
            os           TEXT,
            fingerprint  TEXT UNIQUE,
            enrolled_at  BIGINT,
            last_seen    BIGINT
        )`,
        `CREATE TABLE IF NOT EXISTS audit.results_flat (
            id           BIGSERIAL PRIMARY KEY,
            agent_id     TEXT NOT NULL,
            hostname     TEXT,
            os           TEXT,
            run_id       TEXT,
            received_at  BIGINT,
            policy_title TEXT,
            status       TEXT,
            expected     TEXT,
            reason       TEXT,
            fix          TEXT
        )`,
        `CREATE INDEX IF NOT EXISTS idx_results_flat_agent_time ON audit.results_flat(agent_id, received_at)`,
        // Compatibility views so legacy queries without schema still work if needed
        `CREATE OR REPLACE VIEW public.results_flat AS SELECT * FROM audit.results_flat`,
        `CREATE OR REPLACE VIEW public.agents AS SELECT * FROM audit.agents`,
    }
    for _, q := range stmts {
        if _, err := s.db.Exec(q); err != nil { return err }
    }
    return nil
}

func (s *Store) InitPolicySchema() error {
    stmts := []string{
        `CREATE SCHEMA IF NOT EXISTS policy`,
        `CREATE TABLE IF NOT EXISTS policy.policy_versions (
            policy_id  TEXT NOT NULL,
            os         TEXT NOT NULL,
            version    INTEGER NOT NULL,
            config     TEXT NOT NULL,
            hash       TEXT NOT NULL,
            yaml_src   TEXT,
            updated_at BIGINT NOT NULL,
            PRIMARY KEY(policy_id, os, version)
        )`,
        `CREATE TABLE IF NOT EXISTS policy.policy_heads (
            os         TEXT PRIMARY KEY,
            policy_id  TEXT NOT NULL,
            version    INTEGER NOT NULL,
            updated_at BIGINT NOT NULL
        )`,
        `CREATE OR REPLACE VIEW public.policy_versions AS SELECT * FROM policy.policy_versions`,
        `CREATE OR REPLACE VIEW public.policy_heads AS SELECT * FROM policy.policy_heads`,
    }
    for _, q := range stmts {
        if _, err := s.db.Exec(q); err != nil { return err }
    }
    return nil
}

func (s *Store) InsertPolicyVersion(policyID, osName string, version int, cfgJSON []byte, hash string, yamlText string) error {
    _, err := s.db.Exec(`INSERT INTO policy.policy_versions(policy_id, os, version, config, hash, yaml_src, updated_at)
VALUES($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT(policy_id,os,version) DO UPDATE SET config=EXCLUDED.config, hash=EXCLUDED.hash, yaml_src=EXCLUDED.yaml_src, updated_at=EXCLUDED.updated_at`,
        policyID, osName, version, string(cfgJSON), hash, yamlText, time.Now().Unix())
    return err
}
func (s *Store) SetActivePolicy(osName, policyID string, version int) error {
    _, err := s.db.Exec(`INSERT INTO policy.policy_heads(os, policy_id, version, updated_at)
VALUES($1,$2,$3,$4)
ON CONFLICT(os) DO UPDATE SET policy_id=EXCLUDED.policy_id, version=EXCLUDED.version, updated_at=EXCLUDED.updated_at`,
        osName, policyID, version, time.Now().Unix())
    return err
}
func (s *Store) LoadActivePolicy(osName string) (*model.ActivePolicy, error) {
    row := s.db.QueryRow(`SELECT h.policy_id, v.os, v.version, v.config, v.hash
FROM policy.policy_heads h
JOIN policy.policy_versions v ON v.policy_id=h.policy_id AND v.os=$1 AND v.version=h.version
WHERE h.os=$2`, osName, osName)
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
    err := s.db.QueryRow(`SELECT yaml_src FROM policy.policy_versions WHERE policy_id=$1 AND os='windows' AND version=$2`, policyID, version).Scan(&y)
    if err == sql.ErrNoRows { return "", nil }
    return y, err
}

func (s *Store) UpsertAgent(hostname, osName, fingerprint string) (string, string, error) {
    now := time.Now().Unix()
    aid := ""
    if fingerprint != "" {
        _ = s.db.QueryRow(`SELECT agent_id FROM audit.agents WHERE fingerprint=$1`, fingerprint).Scan(&aid)
    }
    if aid == "" { aid = fmt.Sprintf("ag_%d", time.Now().UnixMilli()) }
    sec := "s_" + randHex(16)
    if _, err := s.db.Exec(`INSERT INTO audit.agents(agent_id, agent_secret, hostname, os, fingerprint, enrolled_at, last_seen)
VALUES($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT(agent_id) DO UPDATE SET agent_secret=EXCLUDED.agent_secret, hostname=EXCLUDED.hostname, os=EXCLUDED.os, last_seen=EXCLUDED.last_seen`,
        aid, sec, hostname, osName, fingerprint, now, now); err != nil {
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
    if err := s.db.QueryRow(`SELECT agent_secret FROM audit.agents WHERE agent_id=$1`, aid).Scan(&dbSec); err != nil {
        return "", struct{}{}, false
    }
    if subtle.ConstantTimeCompare([]byte(dbSec), []byte(sec)) != 1 { return "", struct{}{}, false }
    _, _ = s.db.Exec(`UPDATE audit.agents SET last_seen=$1 WHERE agent_id=$2`, time.Now().Unix(), aid)
    return aid, struct{}{}, true
}

func (s *Store) ReplaceLatestResults(aid string, payload model.ResultsPayload) error {
    tx, err := s.db.Begin()
    if err != nil { return err }
    defer func(){ if err != nil { _ = tx.Rollback() } }()

    if _, err = tx.Exec(`DELETE FROM audit.results_flat WHERE agent_id=$1`, aid); err != nil { return err }

    stmt, err := tx.Prepare(`INSERT INTO audit.results_flat(agent_id, hostname, os, run_id, received_at, policy_title, status, expected, reason, fix)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`)
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

func (s *Store) LatestResults(host, q string, from, to *int64) ([]model.ResultRow, error) {
    where := []string{}
    args := []any{}
    idx := 1
    add := func(cond string, val any) {
        where = append(where, fmt.Sprintf(cond, idx))
        args = append(args, val)
        idx++
    }
    if host != "" { add("LOWER(rf.hostname) LIKE $%d", "%"+strings.ToLower(host)+"%") }
    if q != "" { where = append(where, fmt.Sprintf("(LOWER(rf.policy_title) LIKE $%d OR LOWER(rf.reason) LIKE $%d)", idx, idx+1)); args = append(args, "%"+strings.ToLower(q)+"%", "%"+strings.ToLower(q)+"%"); idx += 2 }
    if from != nil { add("rf.received_at >= $%d", *from) }
    if to != nil { add("rf.received_at < $%d", *to) }

    query := `WITH latest AS (
              SELECT agent_id, MAX(received_at) AS ts
              FROM audit.results_flat
              GROUP BY agent_id)
            SELECT rf.received_at, rf.hostname, rf.policy_title, rf.status, rf.expected, rf.reason, rf.fix
            FROM audit.results_flat rf
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
    rows, err := s.db.Query(`SELECT policy_id, os, version, hash, updated_at FROM policy.policy_versions WHERE os='windows' ORDER BY version DESC`)
    if err != nil { return nil, err }
    defer rows.Close()
    var out []model.PolicyVersion
    for rows.Next() {
        var v model.PolicyVersion
        if err := rows.Scan(&v.PolicyID, &v.OS, &v.Version, &v.Hash, &v.UpdatedAt); err == nil { out = append(out, v) }
    }
    return out, nil
}

func randHex(n int) string { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }

