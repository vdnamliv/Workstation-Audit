package policy

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Bundle bundles policy data fetched from the server or read from disk.
type Bundle struct {
	Version  int                      `json:"version"`
	Policies []map[string]interface{} `json:"policies"`
}

// Fetch retrieves policies from the server using mTLS and bearer auth.
func Fetch(httpClient *http.Client, serverURL, osName, authHeader string) (Bundle, error) {
	url := fmt.Sprintf("%s/policies?os=%s", serverURL, osName)
	req, _ := http.NewRequest("GET", url, nil)

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

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
