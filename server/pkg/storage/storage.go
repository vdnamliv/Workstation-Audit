package storage

import (
	"database/sql"
	"net/http"

	"vt-audit/server/pkg/model"
)

// Store describes the persistence required by HTTP layers.
type Store interface {
	// Low-level DB for custom queries in dashboard handlers.
	DB() *sql.DB

	// Init schemas
	InitAgentSchema() error
	InitPolicySchema() error

	// Agents and results
	UpsertAgent(hostname, osName, fingerprint string) (agentID, agentSecret string, err error)
	AuthAgent(r *http.Request) (agentID string, meta struct{}, ok bool)
	ReplaceLatestResults(agentID string, payload model.ResultsPayload) error

	// Policy versioning
	InsertPolicyVersion(policyID, osName string, version int, cfgJSON []byte, hash string, yamlText string) error
	SetActivePolicy(osName, policyID string, version int) error
	LoadActivePolicy(osName string) (*model.ActivePolicy, error)
	GetPolicyYAML(policyID string, version int) (string, error)

	// Composite queries for dashboard (driver specific inside)
	LatestResults(host, q string, from, to *int64) ([]model.ResultRow, error)
	HostsSummary(from, to *int64) ([]model.HostSummaryRow, error)
	PolicyHistory() ([]model.PolicyVersion, error)

	// Policy Rules CRUD operations
	GetPolicyRules(policyID string, version int) ([]model.PolicyRule, error)
	CreatePolicyRule(policyID string, version int, rule model.PolicyRuleRequest) error
	UpdatePolicyRule(policyID string, version int, ruleID string, rule model.PolicyRuleRequest) error
	DeletePolicyRule(policyID string, version int, ruleID string) error
	GetAllPolicyVersions(osName string) ([]model.PolicyVersion, error)
}
