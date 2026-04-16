package extractor

import (
	"bytes"
	"io"
	"os"
	"strings"

	"golang.org/x/net/html"
)

// ExtractHTML tokenizes HTML and returns visible text.
func ExtractHTML(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, wrapErr(path, "open_html", err)
	}
	defer f.Close()

	z := html.NewTokenizer(f)
	var out bytes.Buffer
	skipDepth := 0

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if z.Err() == io.EOF {
				return out.Bytes(), nil
			}
			return nil, wrapErr(path, "tokenize_html", z.Err())
		case html.StartTagToken:
			tn, _ := z.TagName()
			tag := strings.ToLower(string(tn))
			if tag == "script" || tag == "style" {
				skipDepth++
			}
		case html.EndTagToken:
			tn, _ := z.TagName()
			tag := strings.ToLower(string(tn))
			if (tag == "script" || tag == "style") && skipDepth > 0 {
				skipDepth--
			}
		case html.TextToken:
			if skipDepth > 0 {
				continue
			}
			text := strings.TrimSpace(string(z.Text()))
			if text == "" {
				continue
			}
			if out.Len() > 0 {
				out.WriteByte('\n')
			}
			out.WriteString(text)
		}
	}
}
