package extractor

import "os"

// ExtractText reads plaintext-like files and returns raw bytes.
func ExtractText(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, wrapErr(path, "read", err)
	}
	return b, nil
}
