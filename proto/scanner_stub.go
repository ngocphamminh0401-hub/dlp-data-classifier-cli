package proto

import (
	"context"

	"google.golang.org/grpc"
)

type ScanRequest struct {
	Path          string
	Format        string
	MinConfidence float64
	Recursive     bool
	RulesDir      string
	MaxFileSizeMb int64
}

type ClassificationLevel int32

const (
	ClassificationLevel_CLASSIFICATION_LEVEL_PUBLIC       ClassificationLevel = 0
	ClassificationLevel_CLASSIFICATION_LEVEL_INTERNAL     ClassificationLevel = 1
	ClassificationLevel_CLASSIFICATION_LEVEL_CONFIDENTIAL ClassificationLevel = 2
	ClassificationLevel_CLASSIFICATION_LEVEL_SECRET       ClassificationLevel = 3
)

type ScanStatus int32

const (
	ScanStatus_SCAN_STATUS_UNKNOWN           ScanStatus = 0
	ScanStatus_SCAN_STATUS_OK                ScanStatus = 1
	ScanStatus_SCAN_STATUS_ERROR             ScanStatus = 2
	ScanStatus_SCAN_STATUS_TIMEOUT           ScanStatus = 3
	ScanStatus_SCAN_STATUS_ENCRYPTED         ScanStatus = 4
	ScanStatus_SCAN_STATUS_SKIPPED_BINARY    ScanStatus = 5
	ScanStatus_SCAN_STATUS_SKIPPED_TOO_LARGE ScanStatus = 6
	ScanStatus_SCAN_STATUS_SKIPPED_DIRECTORY ScanStatus = 7
)

type Finding struct {
	RuleId     string
	Offset     uint64
	Length     uint32
	Confidence float32
}

type ScanResponse struct {
	Path       string
	Level      ClassificationLevel
	Status     ScanStatus
	DurationMs uint32
	MatchCount uint32
	Findings   []*Finding
	ErrorCode  uint32
}

type PingRequest struct{}

type PingResponse struct {
	Version string
}

type StatusRequest struct{}

type AgentStatus struct {
	Version     string
	StartedAt   string
	Uptime      string
	ActiveConns int64
	TotalScans  int64
}

type ScannerService_ScanDirectoryServer interface {
	Send(*ScanResponse) error
	Context() context.Context
}

type ScannerServiceServer interface {
	ScanFile(context.Context, *ScanRequest) (*ScanResponse, error)
	ScanDirectory(*ScanRequest, ScannerService_ScanDirectoryServer) error
	Ping(context.Context, *PingRequest) (*PingResponse, error)
	GetStatus(context.Context, *StatusRequest) (*AgentStatus, error)
}

type UnimplementedScannerServiceServer struct{}

func (UnimplementedScannerServiceServer) ScanFile(context.Context, *ScanRequest) (*ScanResponse, error) {
	return nil, nil
}

func (UnimplementedScannerServiceServer) ScanDirectory(*ScanRequest, ScannerService_ScanDirectoryServer) error {
	return nil
}

func (UnimplementedScannerServiceServer) Ping(context.Context, *PingRequest) (*PingResponse, error) {
	return nil, nil
}

func (UnimplementedScannerServiceServer) GetStatus(context.Context, *StatusRequest) (*AgentStatus, error) {
	return nil, nil
}

func RegisterScannerServiceServer(s grpc.ServiceRegistrar, srv ScannerServiceServer) {
	_ = s
	_ = srv
}
