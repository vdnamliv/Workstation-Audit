package policy

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "os"
    "path/filepath"

    "gopkg.in/yaml.v3"
)

// JSONHash returns a hex-encoded SHA256 of a JSON blob.
func JSONHash(b []byte) string {
    h := sha256.Sum256(b)
    return hex.EncodeToString(h[:])
}

// NormalizePolicies mutates a policy slice to fix legacy fields.
func NormalizePolicies(rules []map[string]interface{}) {
    for _, r := range rules {
        if v, ok := r["querry"]; ok { // normalize misspelled field
            r["query"] = v
            delete(r, "querry")
        }
    }
}

// LoadWindowsPolicies reads rules/windows.yml and parses it.
func LoadWindowsPolicies(rulesDir string) ([]map[string]interface{}, error) {
    p := filepath.Join(rulesDir, "windows.yml")
    raw, err := os.ReadFile(p)
    if err != nil { return nil, fmt.Errorf("read %s: %w", p, err) }
    var rules []map[string]interface{}
    if err := yaml.Unmarshal(raw, &rules); err != nil {
        return nil, fmt.Errorf("yaml: %w", err)
    }
    return rules, nil
}

// MustYAML marshals any value to YAML (ignores error for convenience).
func MustYAML(v any) []byte {
    b, _ := yaml.Marshal(v)
    return b
}

