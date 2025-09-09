package policy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

// Bundle: kết quả /policies hoặc file YAML local -> tối giản
type Bundle struct {
	Version  int                       `json:"version"`
	Policies []map[string]interface{}  `json:"policies"`
}

// Fetch policies từ server (Bearer).
func Fetch(httpClient *http.Client, serverURL, osName, agentID, agentSecret string) (Bundle, error) {
	url := fmt.Sprintf("%s/policies?os=%s", serverURL, osName)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+agentID+":"+agentSecret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return Bundle{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return Bundle{}, fmt.Errorf("GET /policies failed: %s", resp.Status)
	}
	var b Bundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// LoadFromFile: đọc windows.yml local (giữ nguyên cấu trúc rule gốc)
func LoadFromFile(path string) (Bundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, err
	}
	var rules []map[string]interface{}
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		return Bundle{}, err
	}
	return Bundle{Version: 1, Policies: rules}, nil
}
