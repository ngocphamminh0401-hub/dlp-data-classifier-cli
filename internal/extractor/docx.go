package extractor

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
)

// ExtractDOCX extracts visible text from word/document.xml.
func ExtractDOCX(path string) ([]byte, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, wrapErr(path, "open_docx", err)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.Name != "word/document.xml" {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return nil, wrapErr(path, "open_document_xml", err)
		}

		dec := xml.NewDecoder(rc)
		var out bytes.Buffer
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = rc.Close()
				return nil, wrapErr(path, "decode_document_xml", err)
			}
			ch, ok := tok.(xml.CharData)
			if !ok {
				continue
			}
			text := bytes.TrimSpace(ch)
			if len(text) == 0 {
				continue
			}
			if out.Len() > 0 {
				out.WriteByte('\n')
			}
			out.Write(text)
		}

		_ = rc.Close()
		return out.Bytes(), nil
	}

	return []byte{}, nil
}
