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
			switch t := tok.(type) {
			case xml.StartElement:
				// Word thường tách một câu thành nhiều <w:t> riêng biệt (do
				// format, spell-check, revision mark...) trong CÙNG một
				// đoạn văn <w:p>. Chỉ chèn xuống dòng ở ranh giới đoạn/dòng
				// thật (<w:p>, <w:br>, <w:tab>) — nếu chèn \n giữa mọi
				// <w:t> như trước đây, các cụm bị Word tách run (vd: "Mã
				// OTP của quý khách là: " + "746441") sẽ bị regex coi là 2
				// dòng riêng biệt và không match được.
				switch t.Name.Local {
				case "p":
					if out.Len() > 0 {
						out.WriteByte('\n')
					}
				case "br", "cr":
					out.WriteByte('\n')
				case "tab":
					out.WriteByte('\t')
				}
			case xml.CharData:
				// KHÔNG TrimSpace: <w:t xml:space="preserve"> cố ý giữ
				// khoảng trắng đầu/cuối để nối liền với run kế tiếp (vd:
				// "Mã OTP của quý khách là: " nối "746441"). Trim ở đây sẽ
				// làm mất khoảng trắng phân cách giữa 2 run.
				out.Write(t)
			}
		}

		_ = rc.Close()
		return out.Bytes(), nil
	}

	return []byte{}, nil
}
