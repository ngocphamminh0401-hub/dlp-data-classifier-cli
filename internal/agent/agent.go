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
	"sync"
	"sync/atomic"
	"time"

	"github.com/vnpt/dlp-classifier/internal/engine"
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

	// eng là rule engine được compile một lần khi khởi động và tái sử dụng
	// qua mọi request. engMu bảo vệ việc swap pointer khi hot-reload rules.
	eng    *engine.Engine
	engMu  sync.RWMutex
	engErr error // lỗi load engine lần đầu (nil = thành công)

	ctx    context.Context
	cancel context.CancelFunc
}

// New tạo Server mới với cấu hình đã cho.
// Engine được compile ngay tại đây — LoadRuleSet + regex + Aho-Corasick chạy
// một lần duy nhất; mọi request sau sẽ tái sử dụng engine đã build sẵn.
func New(cfg Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		cfg:       cfg,
		startedAt: time.Now(),
		ctx:       ctx,
		cancel:    cancel,
	}

	engCfg := engine.EngineConfig{
		MinConfidence:    cfg.ScanCfg.MinConfidence,
		ContextWindow:    cfg.ScanCfg.ContextWindow,
		FastFail:         cfg.ScanCfg.FastFail,
		// Xem lý do tắt entropy check tại internal/scanner/scanner.go (New()).
		EntropyThreshold: 0,
	}
	eng, err := engine.CompileFromDir(cfg.ScanCfg.RulesDir, engCfg)
	s.eng = eng
	s.engErr = err
	if err != nil {
		slog.Warn("agent: không thể load engine — scan sẽ thất bại cho đến khi reload", "err", err)
	}
	return s
}

// ReloadRules tải lại toàn bộ rules từ disk và swap engine đang chạy sang engine mới.
// An toàn khi gọi concurrently: request đang chạy tiếp tục dùng engine cũ đến hết,
// request mới sau khi swap sẽ dùng engine mới.
func (s *Server) ReloadRules() error {
	engCfg := engine.EngineConfig{
		MinConfidence:    s.cfg.ScanCfg.MinConfidence,
		ContextWindow:    s.cfg.ScanCfg.ContextWindow,
		FastFail:         s.cfg.ScanCfg.FastFail,
		// Xem lý do tắt entropy check tại internal/scanner/scanner.go (New()).
		EntropyThreshold: 0,
	}
	eng, err := engine.CompileFromDir(s.cfg.ScanCfg.RulesDir, engCfg)
	if err != nil {
		return fmt.Errorf("reload rules: %w", err)
	}
	s.engMu.Lock()
	s.eng = eng
	s.engErr = nil
	s.engMu.Unlock()
	slog.Info("agent: rules reloaded thành công", "rules_dir", s.cfg.ScanCfg.RulesDir)
	return nil
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
// ctx là context của connection (Unix) hoặc request (gRPC).
// Khi ctx bị cancel (client ngắt kết nối, server shutdown), scan dừng sớm.
//
// Với scan_directory, send được gọi nhiều lần:
//   - N lần với Status=StatusStreaming (một lần mỗi file)
//   - 1 lần với Status=StatusStreamEnd (kết thúc stream, Result=nil)
//
// Transport layer chịu trách nhiệm thread-safety của send.
func (s *Server) dispatch(ctx context.Context, req *Request, send func(*Response) error) {
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

		sc.ScanPaths(ctx, paths) // ctx của connection — cancel khi client ngắt
		for result := range sc.Results() {
			r := result
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

		sc.ScanPaths(ctx, paths) // ctx của connection — cancel khi client ngắt
		for result := range sc.Results() {
			r := result
			s.totalScans.Add(1)
			if err := send(&Response{ID: req.ID, Status: StatusStreaming, Result: &r}); err != nil {
				slog.Debug("agent: ghi streaming response thất bại", "id", req.ID, "err", err)
				return
			}
		}
		// Gửi stream_end để client biết stream đã kết thúc (kể cả khi bị cancel).
		_ = send(&Response{ID: req.ID, Status: StatusStreamEnd})

	// ── reload_rules ──────────────────────────────────────────────────────
	case ActionReloadRules:
		if err := s.ReloadRules(); err != nil {
			_ = send(errResp(req.ID, err.Error()))
			return
		}
		_ = send(&Response{ID: req.ID, Status: StatusOK})

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

// newScanner tạo scanner.Scanner cho một request.
//
// Trường hợp thông thường (không override rules/confidence): tái sử dụng engine
// đã cache — không đọc disk, không compile regex, không build Aho-Corasick.
//
// Trường hợp cần engine khác (override RulesDir hoặc MinConfidence khác mặc định):
// fall back về scanner.New() để load engine mới. Đây là trường hợp hiếm.
func (s *Server) newScanner(opts ScanOptions) *scanner.Scanner {
	cfg := s.cfg.ScanCfg // copy struct

	if opts.MaxFileSizeMB > 0 {
		cfg.MaxFileSizeB = opts.MaxFileSizeMB * 1024 * 1024
	}

	needsNewEngine := (opts.RulesDir != "" && opts.RulesDir != s.cfg.ScanCfg.RulesDir) ||
		(opts.MinConfidence > 0 && opts.MinConfidence != s.cfg.ScanCfg.MinConfidence)

	if needsNewEngine {
		if opts.RulesDir != "" {
			cfg.RulesDir = opts.RulesDir
		}
		if opts.MinConfidence > 0 {
			cfg.MinConfidence = opts.MinConfidence
		}
		return scanner.New(cfg) // hiếm: phải load rules mới
	}

	s.engMu.RLock()
	eng := s.eng
	s.engMu.RUnlock()

	if eng == nil {
		return scanner.New(cfg) // fallback nếu engine init lúc startup bị lỗi
	}
	return scanner.NewWithEngine(eng, cfg) // fast path: reuse cached engine
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
