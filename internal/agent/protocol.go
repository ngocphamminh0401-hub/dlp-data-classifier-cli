// Package agent — Interaction protocol cho DLP scanner agent.
//
// # Kiến trúc dual-transport
//
// Agent hỗ trợ hai transport độc lập, cùng expose một bộ action:
//
//	Unix Domain Socket  — JSON framed bằng 4-byte length prefix (localhost only)
//	gRPC (HTTP/2)       — Protocol Buffers, hỗ trợ TLS mutual auth
//
// # Wire format (Unix socket)
//
//	┌─────────────────────┬──────────────────────────────┐
//	│  4 bytes (uint32 BE)│       JSON payload           │
//	│   payload length    │  Request hoặc Response       │
//	└─────────────────────┴──────────────────────────────┘
//
// # Message flow
//
//	Client ──► Request  { id, action, path, options }
//	Agent  ──► Response { id, status, result }          (scan_file: 1 response)
//	Agent  ──► Response { id, status:"streaming", result } × N  (scan_directory)
//	Agent  ──► Response { id, status:"stream_end" }     (kết thúc stream)
//
// # Actions
//
//	scan_file       Scan một file đơn     → 1 Response(ok)
//	scan_directory  Scan cả thư mục       → N Response(streaming) + 1 Response(stream_end)
//	ping            Kiểm tra liveness     → 1 Response(ok)
//	status          Lấy thống kê agent    → 1 Response(ok) có trường Info
//	shutdown        Dừng agent gracefully → 1 Response(ok) rồi agent tắt
package agent

import (
	"time"

	"github.com/vnpt/dlp-classifier/internal/scanner"
)

// MaxMessageBytes là kích thước tối đa của một message (request hoặc response).
// Bảo vệ chống lại client độc hại gửi payload khổng lồ.
const MaxMessageBytes = 32 * 1024 * 1024 // 32 MB

// ─── Action ──────────────────────────────────────────────────────────────────

// Action xác định thao tác mà client yêu cầu.
type Action string

const (
	// ActionScanFile scan một file đơn theo path. Trả về đúng 1 Response.
	ActionScanFile Action = "scan_file"

	// ActionScanDirectory scan toàn bộ file trong thư mục.
	// Agent stream nhiều Response(streaming), kết thúc bằng Response(stream_end).
	ActionScanDirectory Action = "scan_directory"

	// ActionPing kiểm tra xem agent có còn hoạt động không.
	ActionPing Action = "ping"

	// ActionStatus lấy thông tin runtime của agent (uptime, số scan, ...).
	ActionStatus Action = "status"

	// ActionShutdown yêu cầu agent dừng gracefully.
	ActionShutdown Action = "shutdown"
)

// ─── ResponseStatus ───────────────────────────────────────────────────────────

// ResponseStatus phản ánh kết quả xử lý của một Response message.
type ResponseStatus string

const (
	// StatusOK yêu cầu hoàn thành thành công. Result có thể có hoặc không.
	StatusOK ResponseStatus = "ok"

	// StatusError yêu cầu thất bại. Xem trường Error để biết chi tiết.
	StatusError ResponseStatus = "error"

	// StatusStreaming là kết quả trung gian trong scan_directory stream.
	// Client cần tiếp tục đọc cho đến khi nhận StatusStreamEnd.
	StatusStreaming ResponseStatus = "streaming"

	// StatusStreamEnd đánh dấu kết thúc của một scan_directory stream.
	// Result == nil; client không cần đọc thêm cho request ID này.
	StatusStreamEnd ResponseStatus = "stream_end"
)

// ─── ScanOptions ─────────────────────────────────────────────────────────────

// ScanOptions chứa các tham số scan tùy chọn cho từng request.
// Giá trị zero nghĩa là "dùng cấu hình mặc định của server".
type ScanOptions struct {
	// MinConfidence ghi đè ngưỡng confidence (0.0–1.0).
	MinConfidence float64 `json:"min_confidence,omitempty"`

	// Level lọc kết quả từ cấp này trở lên: INTERNAL | CONFIDENTIAL | SECRET.
	Level string `json:"level,omitempty"`

	// Recursive bật duyệt đệ quy thư mục con (chỉ áp dụng cho scan_directory).
	Recursive bool `json:"recursive,omitempty"`

	// RulesDir ghi đè thư mục rules của server cho request này.
	RulesDir string `json:"rules_dir,omitempty"`

	// MaxFileSizeMB giới hạn kích thước file tối đa (MB). 0 = dùng mặc định server.
	MaxFileSizeMB int64 `json:"max_file_size_mb,omitempty"`
}

// ─── Request ─────────────────────────────────────────────────────────────────

// Request là message mà client gửi đến agent.
//
// Ví dụ scan_file:
//
//	{
//	  "id":     "a3f2c1d0-...",
//	  "action": "scan_file",
//	  "path":   "/data/contracts/hdlv_2025.docx",
//	  "options": { "min_confidence": 0.75 }
//	}
//
// Ví dụ scan_directory:
//
//	{
//	  "id":     "b9e4a2c1-...",
//	  "action": "scan_directory",
//	  "path":   "/data/reports",
//	  "options": { "recursive": true, "level": "CONFIDENTIAL" }
//	}
type Request struct {
	// ID là định danh duy nhất do client tạo (UUID v4 khuyến nghị).
	// Agent echo lại ID trong mọi Response để client ghép request–response.
	ID string `json:"id"`

	// Action xác định thao tác cần thực hiện.
	Action Action `json:"action"`

	// Path là đường dẫn file hoặc thư mục cần scan.
	// Bắt buộc với scan_file và scan_directory.
	Path string `json:"path,omitempty"`

	// Options là các tham số tùy chọn cho request này.
	Options ScanOptions `json:"options,omitempty"`
}

// ─── Response ─────────────────────────────────────────────────────────────────

// Response là message mà agent trả về cho client.
//
// Ví dụ scan_file thành công:
//
//	{
//	  "id":     "a3f2c1d0-...",
//	  "status": "ok",
//	  "result": { "path": "...", "level": "CONFIDENTIAL", "level_code": 2, ... }
//	}
//
// Ví dụ lỗi:
//
//	{ "id": "...", "status": "error", "error": "path is required" }
//
// Ví dụ stream kết thúc:
//
//	{ "id": "b9e4a2c1-...", "status": "stream_end" }
type Response struct {
	// ID tương ứng với Request.ID.
	ID string `json:"id"`

	// Status phản ánh kết quả xử lý.
	Status ResponseStatus `json:"status"`

	// Result chứa kết quả scan (nil nếu không có, vd: ping, stream_end).
	Result *scanner.ScanResult `json:"result,omitempty"`

	// Info chứa thông tin agent (chỉ có với action=status).
	Info *AgentInfo `json:"info,omitempty"`

	// Error mô tả lỗi khi Status == StatusError.
	Error string `json:"error,omitempty"`
}

// ─── AgentInfo ────────────────────────────────────────────────────────────────

// AgentInfo là thông tin runtime trả về từ action "status".
type AgentInfo struct {
	// Version của agent binary.
	Version string `json:"version"`

	// StartedAt là thời điểm agent khởi động.
	StartedAt time.Time `json:"started_at"`

	// Uptime là thời gian agent đã hoạt động dạng human-readable.
	Uptime string `json:"uptime"`

	// ActiveConns là số kết nối Unix socket đang mở.
	ActiveConns int64 `json:"active_connections"`

	// TotalScans là tổng số file đã scan kể từ khi khởi động.
	TotalScans int64 `json:"total_scans"`
}
