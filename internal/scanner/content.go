package scanner

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

const (
	encUTF8       = "utf8"
	encUTF16LE    = "utf16le"
	encUTF16BE    = "utf16be"
	encWindows1252 = "windows1252"
)

func shouldSkipBinary(path string, head []byte) bool {
	ext := strings.ToLower(filepath.Ext(path))

	if ext == ".pdf" || ext == ".zip" || ext == ".doc" || ext == ".docx" || ext == ".xls" || ext == ".xlsx" {
		return true
	}

	magic := [][]byte{
		[]byte("%PDF"),
		[]byte("PK\x03\x04"),
		[]byte("\x7fELF"),
		[]byte("MZ"),
		[]byte("\x89PNG\r\n\x1a\n"),
		[]byte("GIF87a"),
		[]byte("GIF89a"),
		[]byte("\xff\xd8\xff"),
	}

	for _, sig := range magic {
		if len(head) >= len(sig) && bytes.Equal(head[:len(sig)], sig) {
			return true
		}
	}

	nullCount := 0
	for _, b := range head {
		if b == 0 {
			nullCount++
		}
	}
	return len(head) > 0 && nullCount > len(head)/20
}

func detectEncoding(head []byte) string {
	if len(head) >= 3 && bytes.Equal(head[:3], []byte{0xEF, 0xBB, 0xBF}) {
		return encUTF8
	}
	if len(head) >= 2 {
		if head[0] == 0xFF && head[1] == 0xFE {
			return encUTF16LE
		}
		if head[0] == 0xFE && head[1] == 0xFF {
			return encUTF16BE
		}
	}
	if utf8.Valid(head) {
		return encUTF8
	}

	oddZero := 0
	evenZero := 0
	for i := 0; i < len(head) && i < 512; i++ {
		if head[i] != 0 {
			continue
		}
		if i%2 == 0 {
			evenZero++
		} else {
			oddZero++
		}
	}

	if oddZero > 8 && oddZero > evenZero*2 {
		return encUTF16LE
	}
	if evenZero > 8 && evenZero > oddZero*2 {
		return encUTF16BE
	}
	return encWindows1252
}

func decodeContent(raw []byte) ([]byte, error) {
	enc := detectEncoding(raw)

	switch enc {
	case encUTF8:
		if len(raw) >= 3 && bytes.Equal(raw[:3], []byte{0xEF, 0xBB, 0xBF}) {
			return raw[3:], nil
		}
		return raw, nil
	case encUTF16LE:
		decoded, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(raw)
		if err != nil {
			return nil, err
		}
		return bytes.TrimPrefix(decoded, []byte{0xEF, 0xBB, 0xBF}), nil
	case encUTF16BE:
		decoded, err := unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM).NewDecoder().Bytes(raw)
		if err != nil {
			return nil, err
		}
		return bytes.TrimPrefix(decoded, []byte{0xEF, 0xBB, 0xBF}), nil
	default:
		return charmap.Windows1252.NewDecoder().Bytes(raw)
	}
}

func newDecodedReader(f *os.File) (io.Reader, error) {
	head, err := readHead(f, 4096)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	switch detectEncoding(head) {
	case encUTF16LE:
		return transform.NewReader(f, unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()), nil
	case encUTF16BE:
		return transform.NewReader(f, unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM).NewDecoder()), nil
	case encWindows1252:
		return transform.NewReader(f, charmap.Windows1252.NewDecoder()), nil
	default:
		return f, nil
	}
}
