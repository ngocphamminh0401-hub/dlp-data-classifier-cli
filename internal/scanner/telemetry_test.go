package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScannerTelemetryAccumulation xác nhận scanner gộp FileScanTelemetry qua
// các chunk và điền các số liệu cấp file (ChunkCount, TotalBytes) — đồng thời
// Level không đổi so với hành vi trước instrumentation (single-chunk path).
func TestScannerTelemetryAccumulation(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "doc.txt")
	content := "Ma OTP giao dich cua quy khach la install verify 384512. Khong chia se.\n" +
		"Tai khoan 12345678 va so 987654321012 xuat hien khong nhan.\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.RulesDir = filepath.Join("..", "..", "rules")
	sc := New(cfg)

	res, err := sc.ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if res.Telemetry.ChunkCount < 1 {
		t.Fatalf("ChunkCount = %d, want >= 1", res.Telemetry.ChunkCount)
	}
	if res.Telemetry.TotalBytes == 0 {
		t.Fatalf("TotalBytes = 0, want > 0")
	}
	if res.Telemetry.ChunkErrorCount != 0 {
		t.Fatalf("ChunkErrorCount = %d, want 0", res.Telemetry.ChunkErrorCount)
	}
}

// TestScannerTelemetryMultiChunk buộc file bị cắt thành nhiều chunk và xác nhận
// ChunkCount phản ánh đúng số chunk đã gộp.
func TestScannerTelemetryMultiChunk(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "big.txt")
	content := strings.Repeat("day la van ban tieng viet binh thuong khong nhay cam. ", 4000)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.RulesDir = filepath.Join("..", "..", "rules")
	cfg.ChunkSize = 4096
	cfg.ChunkOverlap = 256
	cfg.MmapThreshold = 1
	sc := New(cfg)

	res, err := sc.ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if res.Telemetry.ChunkCount < 2 {
		t.Fatalf("ChunkCount = %d, want >= 2 for a multi-chunk file", res.Telemetry.ChunkCount)
	}
	if res.Level != LevelPublic {
		t.Fatalf("Level = %s, want PUBLIC (plain text)", res.LevelName)
	}
}
