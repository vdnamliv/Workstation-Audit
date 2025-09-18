package model

import (
	"encoding/json"
	"time"
)

// Config keeps runtime settings for services.
type Config struct {
	Addr     string // backward compat (single server)
	CertFile string
	KeyFile  string
	RulesDir string
	DBPath   string
	AdminKey string
	PGDSN    string // reserved for future

	// New fields for split services
	AgentAddr     string // listen address for agent API
	DashboardAddr string // listen address for dashboard API
	Mode          string // all|agent|dashboard

	// mTLS issuing
	MTLSCAFile    string        // signer/root used for client certs
	MTLSCAKeyFile string        // private key for signing client certs
	MTLSCertTTL   time.Duration // validity duration for issued client certs
}

// ResultsPayload is sent from agent to API server.
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

// ActivePolicy is a snapshot of the effective policy version served to agents.
type ActivePolicy struct {
	PolicyID string          `json:"policy_id"`
	OS       string          `json:"os"`
	Version  int             `json:"version"`
	Hash     string          `json:"hash"`
	Config   json.RawMessage `json:"config"` // {"version":X,"policies":[...]}
}

// ResultRow is a flattened latest-result row for dashboard views.
type ResultRow struct {
	ReceivedAt int64
	Hostname   string
	Policy     string
	Status     string
	Expected   string
	Reason     string
	Fix        string
}

// PolicyVersion model for history views.
type PolicyVersion struct {
	PolicyID  string
	OS        string
	Version   int
	Hash      string
	UpdatedAt int64
}
