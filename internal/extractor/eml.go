package extractor

import (
	"bytes"
	"io"
	"net/mail"
	"os"
)

// ExtractEML extracts RFC822 header/body text from .eml files.
func ExtractEML(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, wrapErr(path, "open_eml", err)
	}
	defer f.Close()

	msg, err := mail.ReadMessage(f)
	if err != nil {
		return nil, wrapErr(path, "parse_eml", err)
	}

	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, wrapErr(path, "read_eml_body", err)
	}

	var out bytes.Buffer
	for k, vals := range msg.Header {
		for _, v := range vals {
			out.WriteString(k)
			out.WriteString(": ")
			out.WriteString(v)
			out.WriteByte('\n')
		}
	}
	if out.Len() > 0 {
		out.WriteByte('\n')
	}
	out.Write(body)
	return out.Bytes(), nil
}
