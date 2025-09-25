package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const credentialsFile = "agent_credentials.json"

type Credentials struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
}

func (c Credentials) Valid() bool {
	return strings.TrimSpace(c.AgentID) != "" && strings.TrimSpace(c.AgentSecret) != ""
}

func credentialsPath() string {
	return filepath.Join("data", credentialsFile)
}

func loadCredentials() (Credentials, error) {
	path := credentialsPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		return Credentials{}, err
	}
	var creds Credentials
	if err := json.Unmarshal(raw, &creds); err != nil {
		return Credentials{}, err
	}
	if !creds.Valid() {
		return Credentials{}, errors.New("invalid credentials file")
	}
	return creds, nil
}

func saveCredentials(creds Credentials) error {
	if err := os.MkdirAll(filepath.Dir(credentialsPath()), 0o755); err != nil {
		return err
	}
	payload, _ := json.MarshalIndent(creds, "", "  ")
	return os.WriteFile(credentialsPath(), payload, 0o600)
}

// EnsureCredentials loads cached agent credentials or enrolls the agent to obtain fresh ones.
func EnsureCredentials(ctx context.Context, client *http.Client, serverURL, hostname string) (Credentials, error) {
	if creds, err := loadCredentials(); err == nil && creds.Valid() {
		return creds, nil
	}

	enrollURL := strings.TrimRight(serverURL, "/") + "/enroll"
	payload := map[string]any{
		"hostname": hostname,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"version":  runtime.Version(),
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return Credentials{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return Credentials{}, errors.New("enroll failed: " + resp.Status)
	}

	var out struct {
		AgentID     string `json:"agent_id"`
		AgentSecret string `json:"agent_secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Credentials{}, err
	}

	creds := Credentials{AgentID: strings.TrimSpace(out.AgentID), AgentSecret: strings.TrimSpace(out.AgentSecret)}
	if !creds.Valid() {
		return Credentials{}, errors.New("enroll response missing credentials")
	}

	if err := saveCredentials(creds); err != nil {
		return Credentials{}, err
	}
	return creds, nil
}
