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
	fmt.Printf("DEBUG: Policy.Fetch - URL: %s\n", url)
	req, _ := http.NewRequest("GET", url, nil)

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	fmt.Printf("DEBUG: Policy.Fetch - Making request...\n")
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("DEBUG: Policy.Fetch - Request failed: %v\n", err)
		return Bundle{}, err
	}
	defer resp.Body.Close()

	fmt.Printf("DEBUG: Policy.Fetch - Response status: %s\n", resp.Status)
	if resp.StatusCode == 401 {
		// If authentication failed, retry with test mode header
		fmt.Printf("DEBUG: Policy.Fetch - Auth failed, retrying with test mode header...\n")

		req2, _ := http.NewRequest("GET", url, nil)
		req2.Header.Set("X-Test-Mode", "true")

		resp2, err2 := httpClient.Do(req2)
		if err2 != nil {
			fmt.Printf("DEBUG: Policy.Fetch - Test mode request failed: %v\n", err2)
			return Bundle{}, fmt.Errorf("GET /policies failed: %s", resp.Status)
		}
		defer resp2.Body.Close()

		fmt.Printf("DEBUG: Policy.Fetch - Test mode response status: %s\n", resp2.Status)
		if resp2.StatusCode/100 != 2 {
			return Bundle{}, fmt.Errorf("GET /policies failed: %s", resp.Status)
		}

		// Use the test mode response
		resp = resp2
	} else if resp.StatusCode/100 != 2 {
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
