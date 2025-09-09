package render

import (
    "vt-audit/agent/pkg/enroll"
    "github.com/xuri/excelize/v2"
)

type ResultRow struct {
    Policy   string
    Status   string
    Expected string
    Reason   string
    Fix      string
}

func Excel(results []enroll.Result) ([]byte, error) {
    f := excelize.NewFile()
    defer func() { _ = f.Close() }()

    sheetName := "Audit"

    // Tạo sheet mới và lấy chỉ số (int) để set active
    idx, err := f.NewSheet(sheetName)
    if err != nil {
        return nil, err
    }
    f.SetActiveSheet(idx)

    // (Tùy chọn) Xóa Sheet1 mặc định để gọn file
    // _ = f.DeleteSheet("Sheet1")

    // header
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

    // rows
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
