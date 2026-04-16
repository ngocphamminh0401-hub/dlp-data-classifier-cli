// Package output — JSONL append-only audit log writer.
package output

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// AuditEvent là một dòng trong file audit log JSONL.
type AuditEvent struct {
	Timestamp  time.Time `json:"ts"`
	Path       string    `json:"path"`
	Level      string    `json:"level"`
	RuleID     string    `json:"rule"`
	Offset     int64     `json:"offset"`
	Confidence float64   `json:"confidence"`
	WorkerID   int       `json:"worker_id,omitempty"`
}

// AuditLogger ghi sự kiện vào file JSONL thread-safe.
type AuditLogger struct {
	mu   sync.Mutex
	file *os.File
}

// NewAuditLogger mở file audit log (tạo mới hoặc append).
func NewAuditLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	return &AuditLogger{file: f}, nil
}

// Write ghi một AuditEvent vào file JSONL.
func (a *AuditLogger) Write(event AuditEvent) error {
	event.Timestamp = time.Now().UTC()
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err = a.file.Write(append(data, '\n'))
	return err
}

// Close đóng file audit log.
func (a *AuditLogger) Close() error { return a.file.Close() }
