package ipc

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vnpt/dlp-classifier/internal/scanner"
)

func TestUnixProtoIPCIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix domain socket integration test skipped on windows")
	}

	tmp := t.TempDir()
	socketPath := filepath.Join(tmp, "dlp-scanner.sock")
	sample := filepath.Join(tmp, "secret.env")

	if err := os.WriteFile(sample, []byte("password=StrongPass123"), 0o600); err != nil {
		t.Fatalf("write sample file: %v", err)
	}

	scanCfg := scanner.DefaultConfig()
	scanCfg.RulesDir = filepath.Join("..", "..", "rules")
	scanCfg.ChunkTimeout = 0

	srv := NewServer(Config{SocketPath: socketPath, ScanConfig: scanCfg})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket was not created")
		}
		time.Sleep(20 * time.Millisecond)
	}

	cli, err := Dial(socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	resp, err := cli.Scan(Request{JobID: "job-1", FilePath: sample})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if resp.JobID != "job-1" {
		t.Fatalf("unexpected job id: %s", resp.JobID)
	}
	if resp.Err != "" {
		t.Fatalf("unexpected scan error: %s", resp.Err)
	}
	if resp.Level < int(scanner.LevelSecret) {
		t.Fatalf("expected secret level or higher, got %d", resp.Level)
	}
	if len(resp.Matches) == 0 {
		t.Fatalf("expected at least one match")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not stop in time")
	}
}
