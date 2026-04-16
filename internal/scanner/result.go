// Package scanner — kết quả scan và enum cấp độ phân loại.
package scanner

import (
	"time"

	"github.com/vnpt/dlp-classifier/internal/models"
)

// Level biểu diễn cấp độ phân loại dữ liệu theo khung 4 cấp của VNPT.
type Level int

const (
	LevelPublic       Level = 0
	LevelInternal     Level = 1
	LevelConfidential Level = 2
	LevelSecret       Level = 3
)

func (l Level) String() string {
	return [...]string{"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}[l]
}

// ScanStatus là trạng thái xử lý file dưới dạng mã số nhẹ.
type ScanStatus int32

const (
	StatusUnknown          ScanStatus = 0
	StatusOK               ScanStatus = 1
	StatusError            ScanStatus = 2
	StatusTimeout          ScanStatus = 3
	StatusEncrypted        ScanStatus = 4
	StatusSkippedBinary    ScanStatus = 5
	StatusSkippedTooLarge  ScanStatus = 6
	StatusSkippedDirectory ScanStatus = 7
)

func (s ScanStatus) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusError:
		return "ERROR"
	case StatusTimeout:
		return "TIMEOUT"
	case StatusEncrypted:
		return "ENCRYPTED"
	case StatusSkippedBinary:
		return "SKIPPED_BINARY"
	case StatusSkippedTooLarge:
		return "SKIPPED_TOO_LARGE"
	case StatusSkippedDirectory:
		return "SKIPPED_DIRECTORY"
	default:
		return "UNKNOWN"
	}
}

// Match là payload an toàn sau khi đã che dữ liệu nhạy cảm.
type Match = models.PublicMatch

// ScanResult là kết quả tổng hợp cho một file.
type ScanResult struct {
	Path        string        `json:"path"`
	StatusCode  ScanStatus    `json:"status_code"`
	Level       Level         `json:"level_code"`
	LevelName   string        `json:"level"`
	Duration    time.Duration `json:"scan_duration_ms"`
	Matches     []Match       `json:"matches"`
	Error       string        `json:"error,omitempty"`
}
