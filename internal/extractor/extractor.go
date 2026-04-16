package extractor

import (
	"fmt"
	"path/filepath"
	"strings"
)

// CanExtract reports whether file extension is supported by the extractor pipeline.
func CanExtract(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".txt", ".log", ".csv", ".json", ".md", ".yaml", ".yml", ".go", ".java", ".js", ".ts", ".env", ".ini", ".cfg", ".conf", ".xml", ".pdf", ".docx", ".xlsx", ".html", ".htm", ".eml":
		return true
	default:
		return false
	}
}

// Extract returns normalized UTF-8 text for supported file types.
func Extract(path string) ([]byte, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".pdf":
		return ExtractPDF(path)
	case ".docx":
		return ExtractDOCX(path)
	case ".xlsx":
		return ExtractXLSX(path)
	case ".html", ".htm":
		return ExtractHTML(path)
	case ".eml":
		return ExtractEML(path)
	default:
		return ExtractText(path)
	}
}

func wrapErr(path, stage string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("extract %s (%s): %w", path, stage, err)
}
