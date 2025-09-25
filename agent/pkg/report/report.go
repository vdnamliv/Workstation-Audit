package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Result struct {
	RuleID   string `json:"rule_id,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Expected string `json:"expected"`
	Reason   string `json:"reason"`
	Fix      string `json:"fix"`
}

// PostResults submits audit findings to the server over mTLS.
func PostResults(httpClient *http.Client, serverURL, osName, hostname, authHeader string, results []Result) error {
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
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

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
