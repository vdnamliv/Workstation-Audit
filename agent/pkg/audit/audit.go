package audit

import (
	"fmt"
	"strings"

	"vt-audit/agent/pkg/enroll"
	"vt-audit/agent/pkg/evaluator"
	"vt-audit/agent/pkg/collector"
)

// Execute: chạy toàn bộ policy bundle cho OS "windows"
func Execute(bundle struct {
	Version  int
	Policies []map[string]interface{}
}, osName string) ([]enroll.Result, error) {
	if strings.ToLower(osName) != "windows" {
		return nil, fmt.Errorf("unsupported OS in this build: %s", osName)
	}
	out := make([]enroll.Result, 0, len(bundle.Policies))

	for _, rule := range bundle.Policies {
		// map fields an toàn
		id := str(rule["id"])
		title := str(rule["title"])
		sev := str(rule["severity"])
		rationale := str(rule["rationale"])
		fix := str(rule["fix"])
		passText := str(rule["pass_text"])
		failText := str(rule["fail_text"])

		expect, _ := rule["expect"].(map[string]interface{})
		// query: server đã normalize "querry" -> "query"; nhưng ta vẫn fallback
		q := mapStringString(rule["query"])
		if len(q) == 0 {
			q = mapStringString(rule["querry"])
		}

		// dispatch collector Windows (reuse)
		actual := windows.CollectWindows(q)

		// evaluate (reuse)
		ok, machineReason := evaluator.Evaluate(actual, expect)
		reason := machineReason
		if ok && passText != "" {
			reason = passText
		}
		if !ok && failText != "" {
			reason = failText
		}

		out = append(out, enroll.Result{
			PolicyID: id,
			ID:       id,
			Title:    title,
			Severity: sev,
			Status:   map[bool]string{true: "PASS", false: "FAIL"}[ok],
			Expected: formatExpect(expect),
			Reason:   joinReason(rationale, reason),
			Fix:      fix,
		})
	}
	return out, nil
}

/* ---------- helpers ---------- */

func formatExpect(m map[string]interface{}) string {
	if v, ok := m["equals"]; ok {
		return fmt.Sprintf("%v", v) // chỉ trả giá trị
	}
	if v, ok := m["in"]; ok {
		return fmt.Sprintf("%v", v) // mảng giá trị
	}
	if v, ok := m["contains"]; ok {
		return fmt.Sprintf("%v", v)
	}
	if v, ok := m["regex"]; ok {
		return fmt.Sprintf("%v", v) // chỉ biểu thức regex
	}
	// fallback: nếu expect có dạng map lạ, in raw
	return fmt.Sprintf("%v", m)
}

func joinReason(rationale, reason string) string {
	rationale = strings.TrimSpace(rationale)
	reason = strings.TrimSpace(reason)
	if rationale == "" { return reason }
	if reason == ""    { return rationale }
	return rationale + " | " + reason
}

func str(v any) string {
	if v == nil { return "" }
	return fmt.Sprintf("%v", v)
}

func mapStringString(v any) map[string]string {
	out := map[string]string{}
	m, _ := v.(map[string]interface{})
	for k, vv := range m {
		out[k] = str(vv)
	}
	return out
}
