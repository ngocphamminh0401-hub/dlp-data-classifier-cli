package extractor

import (
	"bytes"
	"io"

	pdf "github.com/ledongthuc/pdf"
)

// ExtractPDF extracts text layer content from a PDF file.
func ExtractPDF(path string) ([]byte, error) {
	f, r, err := pdf.Open(path)
	if err != nil {
		return nil, wrapErr(path, "open_pdf", err)
	}
	defer f.Close()

	reader, err := r.GetPlainText()
	if err != nil {
		return nil, wrapErr(path, "plain_text", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return nil, wrapErr(path, "read_text", err)
	}
	return buf.Bytes(), nil
}
