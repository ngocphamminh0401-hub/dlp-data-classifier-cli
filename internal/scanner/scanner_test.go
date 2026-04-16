package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShouldSkipBinaryMagic(t *testing.T) {
	if !shouldSkipBinary("sample.bin", []byte("%PDF-1.7")) {
		t.Fatalf("expected PDF magic to be skipped")
	}
	if shouldSkipBinary("sample.txt", []byte("hello world")) {
		t.Fatalf("expected plain text not to be skipped")
	}
}

func TestDecodeContentUTF16LE(t *testing.T) {
	raw := []byte{0xFF, 0xFE, 'C', 0x00, 'C', 0x00, 'C', 0x00, 'D', 0x00}
	decoded, err := decodeContent(raw)
	if err != nil {
		t.Fatalf("decodeContent failed: %v", err)
	}
	if string(decoded) != "CCCD" {
		t.Fatalf("unexpected decode output: %q", string(decoded))
	}
}

func TestScanFileChunkBoundary(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "boundary.txt")

	// Force token to cross chunk boundary: "pass" ends in chunk-1, "word" starts in chunk-2.
	content := strings.Repeat("x", 59) + "\n" + "pass" + "word=Str0ngPassw0rd\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cfg := DefaultConfig()
	cfg.RulesDir = filepath.Join("..", "..", "rules")
	cfg.ChunkSize = 64
	cfg.ChunkOverlap = 32
	cfg.MmapThreshold = 1

	sc := New(cfg)
	result, err := sc.ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}

	if result.Level != LevelSecret {
		t.Fatalf("expected level SECRET, got %s", result.LevelName)
	}
	if len(result.Matches) == 0 {
		t.Fatalf("expected at least one match")
	}
}
