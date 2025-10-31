package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Result struct {
	RuleID   string `json:"id,omitempty"` // Server expects "id" not "rule_id"
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
	// Always use hostname-based agentID to ensure unique agents per machine
	agentID := "agent-" + hostname

	payload := map[string]interface{}{
		"agent_id": agentID,
		"run_id":   time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"os":       osName,
		"hostname": hostname,
		"results":  results,
	}

	b, _ := json.Marshal(payload)

	// Debug logging
	fmt.Printf("DEBUG: PostResults - agent_id=%s, results_count=%d\n", agentID, len(results))
	if len(results) > 0 {
		fmt.Printf("DEBUG: First result - Title: '%s', Status: %s\n", results[0].Title, results[0].Status)
	}
	fmt.Printf("DEBUG: PostResults - payload size=%d bytes\n", len(b))
	fmt.Printf("DEBUG: PostResults - URL=%s\n", serverURL+"/results")
	fmt.Printf("DEBUG: PostResults - authHeader=%s\n", authHeader)

	req, _ := http.NewRequest("POST", serverURL+"/results", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	fmt.Printf("DEBUG: PostResults - Making request...\n")
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("DEBUG: PostResults - HTTP error: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	fmt.Printf("DEBUG: PostResults - Response status: %s\n", resp.Status)
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("DEBUG: PostResults - Response body: %s\n", string(body))
		return fmt.Errorf("POST /results failed: %s", resp.Status)
	}

	fmt.Printf("DEBUG: PostResults - Success!\n")
	return nil
}
