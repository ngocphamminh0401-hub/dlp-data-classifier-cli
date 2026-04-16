package extractor

import (
	"bytes"

	"github.com/tealeg/xlsx"
)

// ExtractXLSX flattens spreadsheet cells into newline-delimited text.
func ExtractXLSX(path string) ([]byte, error) {
	wb, err := xlsx.OpenFile(path)
	if err != nil {
		return nil, wrapErr(path, "open_xlsx", err)
	}

	var out bytes.Buffer
	for _, sh := range wb.Sheets {
		for _, row := range sh.Rows {
			for _, cell := range row.Cells {
				s := cell.String()
				if s == "" {
					continue
				}
				if out.Len() > 0 {
					out.WriteByte('\n')
				}
				out.WriteString(s)
			}
		}
	}

	return out.Bytes(), nil
}
