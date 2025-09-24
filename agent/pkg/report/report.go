package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Result struct {
	RuleID    string `json:"rule_id,omitempty"`   // stable rule ID
	PolicyID  string `json:"policy_id,omitempty"` // optional: gắn rule với policy
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`   // PASS / FAIL / WARN
	Expected  string `json:"expected"`
	Reason    string `json:"reason"`
	Fix       string `json:"fix"`
}

// PostResults gửi kết quả audit về server qua mTLS.
// AgentID KHÔNG gửi từ client nữa, server sẽ extract từ cert CN/SAN.
func PostResults(httpClient *http.Client, serverURL, osName, hostname string, results []Result) error {
	payload := struct {
		RunID    string   `json:"run_id"`
		OS       string   `json:"os"`
		Hostname string   `json:"hostname"`
		Results  []Result `json:"results"`
	}{
		RunID:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		OS:       osName,
		Hostname: hostname,
		Results:  results,
	}

	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", serverURL+"/results", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("POST /results failed: %s", resp.Status)
	}
	return nil
}
