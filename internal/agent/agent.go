// agent.go — Agent server: quản lý lifecycle và dispatch request đến scanner engine.
//
// Server có thể chạy đồng thời hai transport:
//   - Unix Domain Socket (serveUnix)  — được implement trong unix_socket.go
//   - gRPC over TCP     (serveGRPC)   — được implement trong grpc.go
//
// Cả hai transport dùng chung phương thức dispatch() để xử lý logic scan,
// đảm bảo hành vi nhất quán giữa hai giao thức.
//
// Khởi động:
//
//	srv := agent.New(agent.DefaultConfig())
//	if err := srv.Start(); err != nil {
//	    log.Fatal(err)
//	}
//
// Tắt graceful từ goroutine khác:
//
//	srv.Shutdown()
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/vnpt/dlp-classifier/internal/scanner"
	"github.com/vnpt/dlp-classifier/internal/walker"
)

const agentVersion = "1.0.0"

// ─── Config ───────────────────────────────────────────────────────────────────

// Config chứa toàn bộ cấu hình của agent server.
type Config struct {
	// SocketPath là đường dẫn Unix domain socket.
	// Đặt thành "" để tắt Unix transport.
	SocketPath string

	// GRPCAddr là địa chỉ lắng nghe gRPC, dạng "host:port".
	// Đặt thành "" để tắt gRPC transport.
	GRPCAddr string

	// TLSCertFile và TLSKeyFile kích hoạt TLS cho gRPC.
	// Nếu cả hai rỗng, gRPC chạy plaintext (chỉ phù hợp localhost).
	TLSCertFile string
	TLSKeyFile  string

	// ScanCfg là cấu hình cơ sở cho scanner engine.
	// Mỗi request có thể ghi đè một phần qua ScanOptions.
	ScanCfg scanner.Config
}

// DefaultConfig trả về cấu hình mặc định hợp lý.
func DefaultConfig() Config {
	return Config{
		SocketPath: "/tmp/dlp.sock",
		GRPCAddr:   ":50051",
		ScanCfg:    scanner.DefaultConfig(),
	}
}

// ─── Server ───────────────────────────────────────────────────────────────────

// Server quản lý lifecycle của agent và điều phối các scan request.
type Server struct {
	cfg       Config
	startedAt time.Time

	// activeConn đếm số kết nối Unix socket đang mở (dùng atomic để thread-safe).
	activeConn atomic.Int64

	// totalScans đếm tổng số file đã scan từ lúc server khởi động.
	totalScans atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
}

// New tạo Server mới với cấu hình đã cho.
func New(cfg Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:       cfg,
		startedAt: time.Now(),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start khởi động tất cả transport đã cấu hình và block cho đến khi shutdown.
// Trả về lỗi transport đầu tiên xảy ra, hoặc nil khi shutdown sạch.
func (s *Server) Start() error {
	if s.cfg.SocketPath == "" && s.cfg.GRPCAddr == "" {
		return fmt.Errorf("agent: phải cấu hình ít nhất một transport (SocketPath hoặc GRPCAddr)")
	}

	errCh := make(chan error, 2)

	if s.cfg.SocketPath != "" {
		go func() {
			if err := s.serveUnix(); err != nil && s.ctx.Err() == nil {
				errCh <- fmt.Errorf("unix socket: %w", err)
			}
		}()
		slog.Info("agent unix socket sẵn sàng", "path", s.cfg.SocketPath)
	}

	if s.cfg.GRPCAddr != "" {
		go func() {
			if err := s.serveGRPC(); err != nil && s.ctx.Err() == nil {
				errCh <- fmt.Errorf("grpc: %w", err)
			}
		}()
		slog.Info("agent gRPC sẵn sàng", "addr", s.cfg.GRPCAddr)
	}

	select {
	case <-s.ctx.Done():
		return nil
	case err := <-errCh:
		s.Shutdown()
		return err
	}
}

// Shutdown dừng agent gracefully: huỷ context và xoá file socket.
func (s *Server) Shutdown() {
	s.cancel()
	if s.cfg.SocketPath != "" {
		_ = os.Remove(s.cfg.SocketPath)
	}
}

// ─── Dispatch ─────────────────────────────────────────────────────────────────

// dispatch định tuyến một Request đến handler tương ứng và ghi Response
// qua hàm send được cung cấp bởi transport layer.
//
// Với scan_directory, send được gọi nhiều lần:
//   - N lần với Status=StatusStreaming (một lần mỗi file)
//   - 1 lần với Status=StatusStreamEnd (kết thúc stream, Result=nil)
//
// Transport layer chịu trách nhiệm thread-safety của send.
func (s *Server) dispatch(req *Request, send func(*Response) error) {
	switch req.Action {

	// ── ping ──────────────────────────────────────────────────────────────
	case ActionPing:
		_ = send(&Response{ID: req.ID, Status: StatusOK})

	// ── status ────────────────────────────────────────────────────────────
	case ActionStatus:
		info := &AgentInfo{
			Version:     agentVersion,
			StartedAt:   s.startedAt,
			Uptime:      time.Since(s.startedAt).Round(time.Second).String(),
			ActiveConns: s.activeConn.Load(),
			TotalScans:  s.totalScans.Load(),
		}
		_ = send(&Response{ID: req.ID, Status: StatusOK, Info: info})

	// ── scan_file ─────────────────────────────────────────────────────────
	case ActionScanFile:
		if req.Path == "" {
			_ = send(errResp(req.ID, "path là bắt buộc với action scan_file"))
			return
		}
		sc := s.newScanner(req.Options)
		paths := make(chan string, 1)
		paths <- req.Path
		close(paths)

		sc.ScanPaths(s.ctx, paths)
		for result := range sc.Results() {
			r := result // tránh capture biến vòng lặp
			s.totalScans.Add(1)
			if err := send(&Response{ID: req.ID, Status: StatusOK, Result: &r}); err != nil {
				slog.Debug("agent: ghi response thất bại", "id", req.ID, "err", err)
				return
			}
		}

	// ── scan_directory ───────────────────────────────────────────────────
	case ActionScanDirectory:
		if req.Path == "" {
			_ = send(errResp(req.ID, "path là bắt buộc với action scan_directory"))
			return
		}
		sc := s.newScanner(req.Options)
		paths, err := s.walkDir(req.Path, req.Options.Recursive)
		if err != nil {
			_ = send(errResp(req.ID, err.Error()))
			return
		}

		sc.ScanPaths(s.ctx, paths)
		for result := range sc.Results() {
			r := result
			s.totalScans.Add(1)
			if err := send(&Response{ID: req.ID, Status: StatusStreaming, Result: &r}); err != nil {
				slog.Debug("agent: ghi streaming response thất bại", "id", req.ID, "err", err)
				return
			}
		}
		// Gửi stream_end dù có lỗi giữa chừng hay không, để client biết stream đã kết thúc.
		_ = send(&Response{ID: req.ID, Status: StatusStreamEnd})

	// ── shutdown ──────────────────────────────────────────────────────────
	case ActionShutdown:
		_ = send(&Response{ID: req.ID, Status: StatusOK})
		go s.Shutdown() // async: flush response trước khi tắt

	// ── unknown ───────────────────────────────────────────────────────────
	default:
		_ = send(errResp(req.ID, fmt.Sprintf("action không hợp lệ: %q", req.Action)))
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// newScanner tạo scanner.Scanner mới, áp dụng override từ ScanOptions của request.
// Mỗi request nhận một Scanner riêng biệt để tránh race condition.
func (s *Server) newScanner(opts ScanOptions) *scanner.Scanner {
	cfg := s.cfg.ScanCfg // copy struct
	if opts.MinConfidence > 0 {
		cfg.MinConfidence = opts.MinConfidence
	}
	if opts.RulesDir != "" {
		cfg.RulesDir = opts.RulesDir
	}
	if opts.MaxFileSizeMB > 0 {
		cfg.MaxFileSizeB = opts.MaxFileSizeMB * 1024 * 1024
	}
	return scanner.New(cfg)
}

// walkDir trả về channel chứa đường dẫn tất cả file trong dir.
// Nếu recursive=false, chỉ liệt kê file trực tiếp trong dir (không duyệt con).
// Channel được đóng khi walk hoàn thành hoặc context bị huỷ.
func (s *Server) walkDir(dir string, recursive bool) (<-chan string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("không thể truy cập thư mục %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%q không phải thư mục", dir)
	}

	wcfg := walker.DefaultConfig()
	if s.cfg.ScanCfg.MaxWorkers > 0 {
		wcfg.BufferSize = s.cfg.ScanCfg.MaxWorkers * 4
	}
	wcfg.MaxFileSizeB = s.cfg.ScanCfg.MaxFileSizeB

	w := walker.New(wcfg)
	return w.Walk(s.ctx, dir, recursive), nil
}

// errResp là helper tạo Response lỗi.
func errResp(id, msg string) *Response {
	return &Response{ID: id, Status: StatusError, Error: msg}
}
