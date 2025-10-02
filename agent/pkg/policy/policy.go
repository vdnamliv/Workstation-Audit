package policy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

// Bundle bundles policy data fetched from the server or read from disk.
type Bundle struct {
	Version  int                      `json:"version"`
	Policies []map[string]interface{} `json:"policies"`
}

// Fetch retrieves policies from the server using mTLS and bearer auth.
func Fetch(httpClient *http.Client, serverURL, osName, authHeader string) (Bundle, error) {
	url := fmt.Sprintf("%s/policies?os=%s", serverURL, osName)
	fmt.Printf("DEBUG: Policy.Fetch - URL: %s\n", url)
	req, _ := http.NewRequest("GET", url, nil)

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		// If using test credentials, add test mode header
		if authHeader == "Bearer test:test" {
			req.Header.Set("X-Test-Mode", "true")
		}
	}

	fmt.Printf("DEBUG: Policy.Fetch - Making request...\n")
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("DEBUG: Policy.Fetch - Request failed: %v\n", err)
		return Bundle{}, err
	}
	defer resp.Body.Close()

	fmt.Printf("DEBUG: Policy.Fetch - Response status: %s\n", resp.Status)
	if resp.StatusCode/100 != 2 {
		return Bundle{}, fmt.Errorf("GET /policies failed: %s", resp.Status)
	}

	var b Bundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		fmt.Printf("DEBUG: Policy.Fetch - JSON decode failed: %v\n", err)
		return Bundle{}, err
	}
	fmt.Printf("DEBUG: Policy.Fetch - Success! Received policy v%d with %d policies\n", b.Version, len(b.Policies))
	return b, nil
}

// LoadFromFile reads a local windows.yml bundle.
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
