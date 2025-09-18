package enroll

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"
)

// Request để bạn mở rộng sau (fingerprint…)
type Request struct {
	Fingerprint string `json:"fingerprint,omitempty"`
}

type enrollResp struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
	Poll        int    `json:"poll_interval_sec"`
}

// Enroll: POST /enroll -> trả agent_id/secret/poll (giống agent.go cũ).
func Enroll(httpClient *http.Client, serverURL string, req Request) (string, string, int, error) {
	hostname, _ := os.Hostname()
	body, _ := json.Marshal(map[string]string{
		"hostname":    hostname,
		"os":          detectOS(),
		"arch":        runtime.GOARCH,
		"version":     "agent-1.0.0",
		"fingerprint": req.Fingerprint,
	})
	r, err := http.NewRequest("POST", serverURL+"/enroll", bytes.NewReader(body))
	if err != nil {
		return "", "", 0, err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(r)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", "", 0, fmt.Errorf("enroll failed: %s", resp.Status)
	}
	var out enrollResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", 0, err
	}
	return out.AgentID, out.AgentSecret, out.Poll, nil
}

func detectOS() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "darwin":
		return "macos"
	}
	return "unknown"
}

// PostResults: POST /results giữ kiểu tương thích server cũ.
func PostResults(httpClient *http.Client, serverURL, agentID, agentSecret, osName, hostname string, results []Result) error {
	payload := struct {
		AgentID  string   `json:"agent_id"`
		RunID    string   `json:"run_id"`
		OS       string   `json:"os"`
		Hostname string   `json:"hostname"`
		Results  []Result `json:"results"`
	}{
		AgentID:  agentID,
		RunID:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		OS:       osName,
		Hostname: hostname,
		Results:  results,
	}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", serverURL+"/results", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+agentID+":"+agentSecret)
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

// Result là shape server nhận (title/severity/status/expected/reason/fix).
type Result struct {
	PolicyID string `json:"policy_id,omitempty"`
	ID       string `json:"id,omitempty"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`   // PASS/FAIL
	Expected string `json:"expected"` // formatExpect
	Reason   string `json:"reason"`   // pass_text/fail_text hoặc message evaluator
	Fix      string `json:"fix"`      // fix từ YAML (server chỉ lưu nếu FAIL)
}
