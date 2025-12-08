package postgres

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
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
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) DB() *sql.DB { return s.db }

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
	if err := row.Scan(&pid, &osnm, &ver, &cfg, &hash); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	// For v2+ policies, rebuild Config from policy_rules to ensure proper structure
	if ver > 1 {
		rules, err := s.GetPolicyRules(pid, ver)
		if err != nil {
			return nil, fmt.Errorf("failed to load policy rules: %v", err)
		}

		// Convert database rules to agent-compatible format
		policies := make([]map[string]interface{}, 0, len(rules))
		for _, rule := range rules {
			// Parse expected field from "equals: 1" to {"equals": "1"}
			expected := map[string]interface{}{}
			if rule.Expected != "" {
				parts := strings.SplitN(rule.Expected, ":", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.TrimSpace(parts[1])
					expected[key] = value
				}
			}

			policy := map[string]interface{}{
				"id":          rule.RuleID,
				"title":       rule.Title,
				"description": rule.Description,
				"severity":    rule.Severity,
				"tags":        strings.Split(rule.Tags, ","),
				"query": map[string]interface{}{
					"type": "powershell",
					"cmd":  rule.Check,
				},
				"expect": expected, // Use "expect" not "expected"
				"fix":    rule.Fix,
			}
			// Clean up tags
			if tags, ok := policy["tags"].([]string); ok && len(tags) == 1 && tags[0] == "" {
				policy["tags"] = []string{}
			}
			policies = append(policies, policy)
		}

		// Rebuild config JSON with proper structure
		newConfig := struct {
			Version  int                      `json:"version"`
			Policies []map[string]interface{} `json:"policies"`
		}{
			Version:  ver,
			Policies: policies,
		}

		if newCfg, err := json.Marshal(newConfig); err == nil {
			cfg = string(newCfg)
		}
	}

	return &model.ActivePolicy{PolicyID: pid, OS: osnm, Version: ver, Hash: hash, Config: []byte(cfg)}, nil
}
func (s *Store) GetPolicyYAML(policyID string, version int) (string, error) {
	var y string
	err := s.db.QueryRow(`SELECT yaml_src FROM policy.policy_versions WHERE policy_id=$1 AND os='windows' AND version=$2`, policyID, version).Scan(&y)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return y, err
}

func (s *Store) UpsertAgent(hostname, osName, fingerprint string) (string, string, error) {
	now := time.Now().Unix()
	aid := ""
	if fingerprint != "" {
		_ = s.db.QueryRow(`SELECT agent_id FROM audit.agents WHERE fingerprint=$1`, fingerprint).Scan(&aid)
	}
	if aid == "" {
		aid = fmt.Sprintf("ag_%d", time.Now().UnixMilli())
	}
	// For mTLS agents, use hostname as CN and fingerprint as serial
	certCN := hostname
	certSerial := fingerprint
	if certSerial == "" {
		certSerial = "mtls:" + hostname
	}
	// agent_secret is NULL for mTLS agents (no Bearer token needed)
	if _, err := s.db.Exec(`INSERT INTO audit.agents(agent_id, agent_secret, hostname, os, fingerprint, cert_cn, cert_serial, enrolled_at, last_seen)
VALUES($1, NULL, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT(agent_id) DO UPDATE SET hostname=EXCLUDED.hostname, os=EXCLUDED.os, last_seen=EXCLUDED.last_seen`,
		aid, hostname, osName, fingerprint, certCN, certSerial, now, now); err != nil {
		return "", "", err
	}
	return aid, "", nil
}

func (s *Store) AuthAgent(r *http.Request) (string, struct{}, bool) {
	// Debug: log all relevant headers
	log.Printf("🔐 AuthAgent DEBUG: Headers - X-Client-CN: %q, X-Client-Subject: %q, X-Client-Verify: %q, Auth: %q",
		r.Header.Get("X-Client-CN"),
		r.Header.Get("X-Client-Subject"),
		r.Header.Get("X-Client-Verify"),
		r.Header.Get("Authorization"))

	// Allow test mode
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Test-Mode")), "true") {
		return "test-agent", struct{}{}, true
	}

	// First try mTLS certificate authentication
	if clientCN := clientCommonNameFromRequest(r); clientCN != "" {
		log.Printf("🔐 AuthAgent DEBUG: Found client CN: %q", clientCN)
		// Look up agent by hostname/common name
		var aid string
		err := s.db.QueryRow(`SELECT agent_id FROM audit.agents WHERE hostname=$1`, clientCN).Scan(&aid)
		if err == nil {
			log.Printf("🔐 AuthAgent DEBUG: Found existing agent: %s", aid)
			_, _ = s.db.Exec(`UPDATE audit.agents SET last_seen=$1 WHERE agent_id=$2`, time.Now(), aid)
			return aid, struct{}{}, true
		}
		log.Printf("🔐 AuthAgent DEBUG: Agent not found in DB, creating new one. Error: %v", err)
		// If not found in database, create new agent entry automatically
		aid, _, err = s.UpsertAgent(clientCN, "windows", "mtls:"+clientCN)
		if err == nil {
			log.Printf("🔐 AuthAgent DEBUG: Created new agent: %s", aid)
			return aid, struct{}{}, true
		}
		log.Printf("🔐 AuthAgent DEBUG: Failed to create agent: %v", err)
	} else {
		log.Printf("🔐 AuthAgent DEBUG: No client CN found")
	}

	// Fallback to Bearer token authentication for backward compatibility
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", struct{}{}, false
	}
	parts := strings.SplitN(h[len("Bearer "):], ":", 2)
	if len(parts) != 2 {
		return "", struct{}{}, false
	}
	aid, sec := parts[0], parts[1]

	// Handle test credentials
	if aid == "test" && sec == "test" {
		return "test-agent", struct{}{}, true
	}

	var dbSec string
	if err := s.db.QueryRow(`SELECT agent_secret FROM audit.agents WHERE agent_id=$1`, aid).Scan(&dbSec); err != nil {
		return "", struct{}{}, false
	}
	if subtle.ConstantTimeCompare([]byte(dbSec), []byte(sec)) != 1 {
		return "", struct{}{}, false
	}
	_, _ = s.db.Exec(`UPDATE audit.agents SET last_seen=$1 WHERE agent_id=$2`, time.Now(), aid)
	return aid, struct{}{}, true
}

// clientCommonNameFromRequest extracts the client certificate common name
func clientCommonNameFromRequest(r *http.Request) string {
	// Try direct TLS certificate
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if cn := strings.TrimSpace(r.TLS.PeerCertificates[0].Subject.CommonName); cn != "" {
			return cn
		}
	}
	// Try nginx forwarded headers
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

// extractCommonName parses CN= from certificate subject string
func extractCommonName(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if len(part) >= 3 && strings.EqualFold(part[:3], "CN=") {
			return strings.TrimSpace(part[3:])
		}
	}
	return ""
}

func (s *Store) ReplaceLatestResults(aid string, payload model.ResultsPayload) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.Exec(`DELETE FROM audit.results_flat WHERE agent_id=$1`, aid); err != nil {
		return err
	}

	stmt, err := tx.Prepare(`INSERT INTO audit.results_flat(agent_id, hostname, os, run_id, received_at, policy_title, status, expected, reason, fix)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().Unix() // Convert to Unix timestamp (bigint)
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

	// If host is specified, filter by exact hostname match
	if host != "" {
		add("cr.hostname = $%d", host)
	}

	// Filter by status if specified (q parameter used for status filtering)
	if q != "" {
		add("UPPER(cr.status) = $%d", strings.ToUpper(q))
	}

	if from != nil {
		add("EXTRACT(EPOCH FROM r.received_at)::bigint >= $%d", *from)
	}
	if to != nil {
		add("EXTRACT(EPOCH FROM r.received_at)::bigint < $%d", *to)
	}

	// Query latest results from results_flat table
	query := `
	SELECT received_at, hostname, policy_title, status, expected, reason, fix
	FROM audit.results_flat`

	if len(where) > 0 {
		whereStr := strings.Join(where, " AND ")
		whereStr = strings.ReplaceAll(whereStr, "cr.", "")
		query += " WHERE " + whereStr
	}
	query += " ORDER BY received_at DESC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
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

func (s *Store) HostsSummary(from, to *int64) ([]model.HostSummaryRow, error) {
	args := []interface{}{}
	where := ""
	if from != nil {
		where += " AND received_at >= $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, *from)
	}
	if to != nil {
		where += " AND received_at < $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, *to)
	}

	query := `
		SELECT 
			max(received_at) as latest_time,
			hostname,
			'' as policy,
			count(case when status = 'PASS' then 1 end) as pass_count,
			count(*) as total_count
		FROM audit.results_flat 
		WHERE 1=1 ` + where + `
		GROUP BY hostname 
		ORDER BY latest_time DESC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.HostSummaryRow
	for rows.Next() {
		var r model.HostSummaryRow
		var timestamp int64
		if err := rows.Scan(&timestamp, &r.Host, &r.Policy, &r.PassCount, &r.TotalCount); err == nil {
			r.Time = time.Unix(timestamp, 0).Format("2006-01-02 15:04:05")
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *Store) HostsSummaryPaginated(search string, page, limit int, sortBy, sortOrder string, from, to *int64) ([]model.HostSummaryRow, int, error) {
	args := []interface{}{}
	where := "WHERE 1=1"

	// Add search filter
	if search != "" {
		where += " AND hostname ILIKE $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, "%"+search+"%")
	}

	// Add time filters
	if from != nil {
		where += " AND received_at >= $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, *from)
	}
	if to != nil {
		where += " AND received_at < $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, *to)
	}

	// Build ORDER BY clause
	orderBy := "ORDER BY latest_time DESC"
	if sortBy != "" {
		validSorts := map[string]string{
			"time":   "MAX(received_at)",
			"host":   "hostname",
			"policy": "hostname", // fallback to hostname since policy is empty
			"passed": "COUNT(CASE WHEN status = 'PASS' THEN 1 END)",
			"failed": "(COUNT(*) - COUNT(CASE WHEN status = 'PASS' THEN 1 END))",
			"total":  "COUNT(*)",
		}
		if dbColumn, ok := validSorts[sortBy]; ok {
			direction := "DESC"
			if sortOrder == "asc" {
				direction = "ASC"
			}
			orderBy = fmt.Sprintf("ORDER BY %s %s", dbColumn, direction)
		}
	}

	// Count total records from results_flat
	countQuery := `SELECT COUNT(DISTINCT hostname) FROM audit.results_flat ` + where

	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Add pagination
	offset := (page - 1) * limit
	args = append(args, limit, offset)
	limitOffset := fmt.Sprintf("LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	// Main query with pagination from results_flat
	query := `
		SELECT 
			MAX(received_at) as latest_time,
			hostname,
			'' as policy,
			COUNT(CASE WHEN status = 'PASS' THEN 1 END) as pass_count,
			COUNT(*) as total_count
		FROM audit.results_flat ` + where + `
		GROUP BY hostname 
		` + orderBy + ` 
		` + limitOffset

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []model.HostSummaryRow
	for rows.Next() {
		var r model.HostSummaryRow
		var timestamp float64
		if err := rows.Scan(&timestamp, &r.Host, &r.Policy, &r.PassCount, &r.TotalCount); err == nil {
			r.Time = time.Unix(int64(timestamp), 0).Format("2006-01-02 15:04:05")
			out = append(out, r)
		} else {
			log.Printf("🔥 ERROR scanning row: %v", err)
		}
	}
	return out, total, nil
}

func (s *Store) PolicyHistory() ([]model.PolicyVersion, error) {
	rows, err := s.db.Query(`SELECT policy_id, os, version, hash, updated_at FROM policy.policy_versions WHERE os='windows' ORDER BY version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.PolicyVersion
	for rows.Next() {
		var v model.PolicyVersion
		if err := rows.Scan(&v.PolicyID, &v.OS, &v.Version, &v.Hash, &v.UpdatedAt); err == nil {
			out = append(out, v)
		}
	}
	return out, nil
}

func (s *Store) GetPolicyRules(policyID string, version int) ([]model.PolicyRule, error) {
	rows, err := s.db.Query(`
		SELECT id, policy_id, rule_id, title, description, severity, check_cmd, expected, fix, tags, created_at, updated_at 
		FROM policy.policy_rules 
		WHERE policy_id = $1 AND version = $2 
		ORDER BY rule_id`, policyID, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []model.PolicyRule
	for rows.Next() {
		var r model.PolicyRule
		if err := rows.Scan(&r.ID, &r.PolicyID, &r.RuleID, &r.Title, &r.Description,
			&r.Severity, &r.Check, &r.Expected, &r.Fix, &r.Tags, &r.CreatedAt, &r.UpdatedAt); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func (s *Store) CreatePolicyRule(policyID string, version int, rule model.PolicyRuleRequest) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		INSERT INTO policy.policy_rules 
		(policy_id, version, rule_id, title, description, severity, check_cmd, expected, fix, tags, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		policyID, version, rule.RuleID, rule.Title, rule.Description, rule.Severity,
		rule.Check, rule.Expected, rule.Fix, rule.Tags, now, now)
	return err
}

func (s *Store) UpdatePolicyRule(policyID string, version int, ruleID string, rule model.PolicyRuleRequest) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		UPDATE policy.policy_rules 
		SET title = $4, description = $5, severity = $6, check_cmd = $7, expected = $8, fix = $9, tags = $10, updated_at = $11
		WHERE policy_id = $1 AND version = $2 AND rule_id = $3`,
		policyID, version, ruleID, rule.Title, rule.Description, rule.Severity,
		rule.Check, rule.Expected, rule.Fix, rule.Tags, now)
	return err
}

func (s *Store) DeletePolicyRule(policyID string, version int, ruleID string) error {
	_, err := s.db.Exec(`DELETE FROM policy.policy_rules WHERE policy_id = $1 AND version = $2 AND rule_id = $3`,
		policyID, version, ruleID)
	return err
}

func (s *Store) GetAllPolicyVersions(osName string) ([]model.PolicyVersion, error) {
	rows, err := s.db.Query(`SELECT policy_id, os, version, hash, EXTRACT(epoch FROM updated_at)::bigint FROM policy.policy_versions WHERE os = $1 ORDER BY policy_id, version DESC`, osName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []model.PolicyVersion
	for rows.Next() {
		var v model.PolicyVersion
		if err := rows.Scan(&v.PolicyID, &v.OS, &v.Version, &v.Hash, &v.UpdatedAt); err == nil {
			versions = append(versions, v)
		}
	}
	return versions, nil
}

func (s *Store) HostsTotalStats() (model.HostsTotalStats, error) {
	var stats model.HostsTotalStats

	log.Printf("🔥 DEBUG: HostsTotalStats - Querying from audit.results_flat")

	// Get host compliance statistics from results_flat
	query := `
		WITH host_stats AS (
			SELECT 
				hostname,
				SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed_count
			FROM audit.results_flat
			GROUP BY hostname
		)
		SELECT 
			COALESCE(COUNT(*), 0) as total_hosts,
			COALESCE(SUM(CASE WHEN failed_count = 0 THEN 1 ELSE 0 END), 0) as compliant_hosts,
			COALESCE(SUM(CASE WHEN failed_count > 0 THEN 1 ELSE 0 END), 0) as uncompliant_hosts
		FROM host_stats`

	row := s.db.QueryRow(query)
	err := row.Scan(&stats.TotalHosts, &stats.CompliantHosts, &stats.UncompliantHosts)
	if err != nil {
		return stats, err
	}

	log.Printf("🔥 DEBUG: HostsTotalStats - Result: Total=%d, Compliant=%d, Uncompliant=%d",
		stats.TotalHosts, stats.CompliantHosts, stats.UncompliantHosts)

	return stats, nil
}

func randHex(n int) string { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }
