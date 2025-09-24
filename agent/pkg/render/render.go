package render

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/xuri/excelize/v2"
	"vt-audit/agent/pkg/report"
)

// HTML: render kết quả local audit thành HTML
func HTML(results []report.Result) (string, error) {
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
			cls, esc(r.Title), esc(r.Severity), esc(r.Status), esc(r.Expected), esc(r.Reason), esc(r.Fix),
		))
	}
	buf.WriteString(`</table></body></html>`)
	return buf.String(), nil
}

// Excel: render kết quả local audit thành file XLSX
func Excel(results []report.Result) ([]byte, error) {
	f := excelize.NewFile()
	defer func() { _ = f.Close() }()

	sheetName := "Audit"

	idx, err := f.NewSheet(sheetName)
	if err != nil {
		return nil, err
	}
	f.SetActiveSheet(idx)

	headers := []string{"Policy", "Status", "Expected", "Reason", "Fix"}
	for i, h := range headers {
		cell, err := excelize.CoordinatesToCellName(i+1, 1)
		if err != nil {
			return nil, err
		}
		if err := f.SetCellValue(sheetName, cell, h); err != nil {
			return nil, err
		}
	}

	for r, rr := range results {
		row := r + 2
		values := []any{rr.Title, rr.Status, rr.Expected, rr.Reason, rr.Fix}
		for c, v := range values {
			cell, err := excelize.CoordinatesToCellName(c+1, row)
			if err != nil {
				return nil, err
			}
			if err := f.SetCellValue(sheetName, cell, v); err != nil {
				return nil, err
			}
		}
	}

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
