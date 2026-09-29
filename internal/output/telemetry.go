// telemetry.go — JSONL append-only writer cho FileScanTelemetry (Pha 1).
//
// Mỗi dòng là số liệu near-miss của MỘT file, khóa theo `path` (file_id) — để
// truy vấn hàng loạt ở Pha 2 (fit lớp prior), KHÔNG dùng cho routing runtime.
package output

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/vnpt/dlp-classifier/internal/engine"
)

// TelemetryRecord là một dòng trong file telemetry JSONL.
type TelemetryRecord struct {
	Timestamp time.Time `json:"ts"`
	Path      string    `json:"path"`
	Level     string    `json:"level"`
	Status    string    `json:"status"`

	engine.FileScanTelemetry
}

// TelemetryLogger ghi TelemetryRecord vào file JSONL thread-safe.
type TelemetryLogger struct {
	mu   sync.Mutex
	file *os.File
}

// NewTelemetryLogger mở file telemetry log (tạo mới hoặc append).
func NewTelemetryLogger(path string) (*TelemetryLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	return &TelemetryLogger{file: f}, nil
}

// Write ghi một TelemetryRecord vào file JSONL.
func (t *TelemetryLogger) Write(rec TelemetryRecord) error {
	rec.Timestamp = time.Now().UTC()
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, err = t.file.Write(append(data, '\n'))
	return err
}

// Close đóng file telemetry log.
func (t *TelemetryLogger) Close() error { return t.file.Close() }
