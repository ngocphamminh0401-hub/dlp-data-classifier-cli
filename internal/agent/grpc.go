// grpc.go — gRPC transport cho DLP agent.
//
// # Yêu cầu trước khi build
//
// File này import package proto được sinh ra từ proto/scanner.proto.
// Chạy lệnh sau để sinh code trước khi build:
//
//	make proto
//	# hoặc thủ công:
//	protoc --go_out=. --go-grpc_out=. proto/scanner.proto
//
// # RPC mapping
//
//	ScanFile(ScanRequest)            → ScanResponse          (unary)
//	ScanDirectory(ScanRequest)       → stream ScanResponse   (server-streaming)
//	Ping(PingRequest)                → PingResponse          (unary)
//	GetStatus(StatusRequest)         → AgentStatus           (unary)
//
// # TLS
//
// Nếu Config.TLSCertFile và Config.TLSKeyFile được đặt, server dùng TLS.
// Nếu không, server chạy plaintext (chỉ phù hợp cho localhost / môi trường test).
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	pb "github.com/vnpt/dlp-classifier/proto"
	"github.com/vnpt/dlp-classifier/internal/scanner"
)

// ─── gRPC server ──────────────────────────────────────────────────────────────

// grpcHandler implement pb.ScannerServiceServer, bridge vào agent.Server.
type grpcHandler struct {
	pb.UnimplementedScannerServiceServer
	srv *Server
}

// serveGRPC khởi động gRPC listener và block cho đến khi context bị huỷ.
func (s *Server) serveGRPC() error {
	ln, err := net.Listen("tcp", s.cfg.GRPCAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.GRPCAddr, err)
	}

	var opts []grpc.ServerOption
	if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("load TLS: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
		slog.Info("agent gRPC TLS enabled", "cert", s.cfg.TLSCertFile)
	} else {
		slog.Warn("agent: gRPC chạy không có TLS — chỉ dùng cho localhost/dev")
	}

	grpcSrv := grpc.NewServer(opts...)
	pb.RegisterScannerServiceServer(grpcSrv, &grpcHandler{srv: s})

	// Dừng gRPC khi context bị huỷ.
	go func() {
		<-s.ctx.Done()
		grpcSrv.GracefulStop()
	}()

	return grpcSrv.Serve(ln)
}

// ─── Unary: ScanFile ──────────────────────────────────────────────────────────

// ScanFile scan một file đơn và trả về kết quả trong một RPC call.
func (g *grpcHandler) ScanFile(ctx context.Context, req *pb.ScanRequest) (*pb.ScanResponse, error) {
	if req.Path == "" {
		return nil, status.Error(codes.InvalidArgument, "path là bắt buộc")
	}

	opts := protoOptsToScanOptions(req)
	sc := g.srv.newScanner(opts)

	paths := make(chan string, 1)
	paths <- req.Path
	close(paths)

	sc.ScanPaths(ctx, paths)
	for result := range sc.Results() {
		g.srv.totalScans.Add(1)
		return toProtoResponse(result), nil
	}
	return nil, status.Errorf(codes.NotFound, "không có kết quả cho %q", req.Path)
}

// ─── Server-streaming: ScanDirectory ─────────────────────────────────────────

// ScanDirectory scan toàn bộ file trong thư mục và stream từng ScanResponse về client.
// Stream kết thúc khi tất cả file đã được scan hoặc context bị huỷ.
func (g *grpcHandler) ScanDirectory(req *pb.ScanRequest, stream pb.ScannerService_ScanDirectoryServer) error {
	if req.Path == "" {
		return status.Error(codes.InvalidArgument, "path là bắt buộc")
	}

	opts := protoOptsToScanOptions(req)
	opts.Recursive = req.Recursive

	sc := g.srv.newScanner(opts)
	paths, err := g.srv.walkDir(req.Path, req.Recursive)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}

	sc.ScanPaths(stream.Context(), paths)
	for result := range sc.Results() {
		g.srv.totalScans.Add(1)
		if err := stream.Send(toProtoResponse(result)); err != nil {
			return status.Errorf(codes.Unavailable, "stream send: %v", err)
		}
	}
	return nil
}

// ─── Unary: Ping ──────────────────────────────────────────────────────────────

// Ping kiểm tra liveness của agent và trả về version.
func (g *grpcHandler) Ping(_ context.Context, _ *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{Version: agentVersion}, nil
}

// ─── Unary: GetStatus ─────────────────────────────────────────────────────────

// GetStatus trả về thông tin runtime của agent.
func (g *grpcHandler) GetStatus(_ context.Context, _ *pb.StatusRequest) (*pb.AgentStatus, error) {
	return &pb.AgentStatus{
		Version:     agentVersion,
		StartedAt:   g.srv.startedAt.Format(time.RFC3339),
		Uptime:      time.Since(g.srv.startedAt).Round(time.Second).String(),
		ActiveConns: g.srv.activeConn.Load(),
		TotalScans:  g.srv.totalScans.Load(),
	}, nil
}

// ─── Conversion helpers ───────────────────────────────────────────────────────

// protoOptsToScanOptions chuyển đổi các trường cấu hình từ ScanRequest proto
// sang ScanOptions để newScanner() có thể áp dụng.
func protoOptsToScanOptions(req *pb.ScanRequest) ScanOptions {
	return ScanOptions{
		MinConfidence: req.MinConfidence,
		RulesDir:      req.RulesDir,
		MaxFileSizeMB: req.MaxFileSizeMb,
	}
}

// toProtoResponse chuyển đổi scanner.ScanResult sang pb.ScanResponse.
func toProtoResponse(r scanner.ScanResult) *pb.ScanResponse {
	resp := &pb.ScanResponse{
		Path:       r.Path,
		Level:      toProtoLevel(r.Level),
		Status:     toProtoStatus(r.StatusCode),
		DurationMs: uint32(r.Duration.Milliseconds()),
		MatchCount: uint32(len(r.Matches)),
		ErrorCode:  toErrorCode(r.StatusCode),
	}
	for _, m := range r.Matches {
		resp.Findings = append(resp.Findings, &pb.Finding{
			RuleId:     m.RuleID,
			Offset:     uint64(m.Offset),
			Length:     uint32(m.Length),
			Confidence: float32(m.Confidence),
		})
	}
	return resp
}

func toProtoLevel(l scanner.Level) pb.ClassificationLevel {
	switch l {
	case scanner.LevelInternal:
		return pb.ClassificationLevel_CLASSIFICATION_LEVEL_INTERNAL
	case scanner.LevelConfidential:
		return pb.ClassificationLevel_CLASSIFICATION_LEVEL_CONFIDENTIAL
	case scanner.LevelSecret:
		return pb.ClassificationLevel_CLASSIFICATION_LEVEL_SECRET
	default:
		return pb.ClassificationLevel_CLASSIFICATION_LEVEL_PUBLIC
	}
}

func toProtoStatus(s scanner.ScanStatus) pb.ScanStatus {
	switch s {
	case scanner.StatusOK:
		return pb.ScanStatus_SCAN_STATUS_OK
	case scanner.StatusTimeout:
		return pb.ScanStatus_SCAN_STATUS_TIMEOUT
	case scanner.StatusEncrypted:
		return pb.ScanStatus_SCAN_STATUS_ENCRYPTED
	case scanner.StatusSkippedBinary:
		return pb.ScanStatus_SCAN_STATUS_SKIPPED_BINARY
	case scanner.StatusSkippedTooLarge:
		return pb.ScanStatus_SCAN_STATUS_SKIPPED_TOO_LARGE
	case scanner.StatusSkippedDirectory:
		return pb.ScanStatus_SCAN_STATUS_SKIPPED_DIRECTORY
	case scanner.StatusError:
		return pb.ScanStatus_SCAN_STATUS_ERROR
	default:
		return pb.ScanStatus_SCAN_STATUS_UNKNOWN
	}
}

func toErrorCode(s scanner.ScanStatus) uint32 {
	if s == scanner.StatusOK || s == scanner.StatusSkippedBinary || s == scanner.StatusSkippedTooLarge || s == scanner.StatusSkippedDirectory {
		return 0
	}
	return uint32(s)
}
