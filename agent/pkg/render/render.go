package render

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"vt-audit/agent/pkg/enroll"
)

// HTML: render kết quả local audit thành HTML đơn giản (auditor mode)
func HTML(results []enroll.Result) (string, error) {
	var buf bytes.Buffer
	buf.WriteString(`<html><head><meta charset="utf-8"><style>
	body{font-family:Arial,Helvetica,sans-serif}
	table{border-collapse:collapse;width:100%}
	th,td{border:1px solid #ddd;padding:8px}
	th{background:#f4f4f4} .PASS{background:#d4edda}.FAIL{background:#f8d7da}
	pre{white-space:pre-wrap;margin:0}
	</style></head><body><h3>VT Agent - Audit Report</h3><table>
	<tr><th>ID</th><th>Policy</th><th>Severity</th><th>Status</th><th>Expected</th><th>Reason</th><th>Fix</th></tr>`)
	for _, r := range results {
		cls := "PASS"
		if strings.ToUpper(r.Status) != "PASS" {
			cls = "FAIL"
		}
		buf.WriteString(fmt.Sprintf(
			`<tr class="%s"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><pre>%s</pre></td><td><pre>%s</pre></td><td><pre>%s</pre></td></tr>`,
			cls, esc(r.ID), esc(r.Title), esc(r.Severity), esc(r.Status), esc(r.Expected), esc(r.Reason), esc(r.Fix),
		))
	}
	buf.WriteString(`</table></body></html>`)
	return buf.String(), nil
}

// RunAndInherit: tiện ích chạy lệnh (dùng cho sc.exe trong main)
func RunAndInherit(cmdline string) error {
	cmd := exec.Command("cmd", "/C", cmdline)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func esc(s string) string {
	r := strings.ReplaceAll(s, "&", "&amp;")
	r = strings.ReplaceAll(r, "<", "&lt;")
	r = strings.ReplaceAll(r, ">", "&gt;")
	return r
}
