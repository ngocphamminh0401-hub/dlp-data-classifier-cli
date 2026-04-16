package ipc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/vnpt/dlp-classifier/internal/scanner"
)

const (
	defaultSocketPath = "/var/run/dlp-scanner.sock"
	heartbeatTick     = 5 * time.Second
	heartbeatTimeout  = 500 * time.Millisecond
)

type Config struct {
	SocketPath string
	ScanConfig scanner.Config
}

func DefaultConfig() Config {
	return Config{SocketPath: defaultSocketPath, ScanConfig: scanner.DefaultConfig()}
}

type Server struct {
	cfg Config
}

func NewServer(cfg Config) *Server {
	if cfg.SocketPath == "" {
		cfg.SocketPath = defaultSocketPath
	}
	return &Server{cfg: cfg}
}

func (s *Server) Start(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	registerShutdownSignals(sigCh)
	defer stopSignalNotify(sigCh)

	go func() {
		select {
		case <-ctx.Done():
		case <-sigCh:
			cancel()
		}
	}()

	_ = os.Remove(s.cfg.SocketPath)
	ln, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen unix socket: %w", err)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(s.cfg.SocketPath)
	}()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return fmt.Errorf("accept: %w", err)
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			s.handleConn(ctx, c)
		}(conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	var writeMu sync.Mutex
	hbDone := make(chan struct{})
	go s.heartbeatWriter(ctx, conn, &writeMu, hbDone)
	defer close(hbDone)

	for {
		if ctx.Err() != nil {
			return
		}

		payload, err := readFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}

		msg, err := UnmarshalEnvelope(payload)
		if err != nil {
			_ = s.writeMessage(conn, &writeMu, Envelope{Type: TypeResult, Response: &Response{Err: err.Error()}})
			continue
		}

		switch msg.Type {
		case TypePing:
			_ = s.writeMessage(conn, &writeMu, Envelope{Type: TypePong})
		case TypePong:
			continue
		case TypeScan:
			if msg.Request == nil {
				_ = s.writeMessage(conn, &writeMu, Envelope{Type: TypeResult, Response: &Response{Err: "missing request payload"}})
				continue
			}
			resp := s.executeScan(*msg.Request)
			_ = s.writeMessage(conn, &writeMu, Envelope{Type: TypeResult, Response: &resp})
		default:
			_ = s.writeMessage(conn, &writeMu, Envelope{Type: TypeResult, Response: &Response{Err: "unsupported message type"}})
		}
	}
}

func (s *Server) executeScan(req Request) Response {
	if req.FilePath == "" {
		return Response{JobID: req.JobID, Err: "file path is required"}
	}

	scanCfg := s.cfg.ScanConfig
	if req.Options.MinConfidence > 0 {
		scanCfg.MinConfidence = req.Options.MinConfidence
	}
	if req.Options.RulesDir != "" {
		scanCfg.RulesDir = req.Options.RulesDir
	}
	if req.Options.MaxFileSizeMB > 0 {
		scanCfg.MaxFileSizeB = req.Options.MaxFileSizeMB * 1024 * 1024
	}

	sc := scanner.New(scanCfg)
	result, err := sc.ScanFile(req.FilePath)
	return toResponse(req.JobID, result, err)
}

func (s *Server) heartbeatWriter(ctx context.Context, conn net.Conn, writeMu *sync.Mutex, done <-chan struct{}) {
	ticker := time.NewTicker(heartbeatTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			_ = s.writeMessage(conn, writeMu, Envelope{Type: TypePing})
		}
	}
}

func (s *Server) writeMessage(conn net.Conn, writeMu *sync.Mutex, env Envelope) error {
	payload, err := MarshalEnvelope(env)
	if err != nil {
		return err
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(heartbeatTimeout))
	err = writeFrame(conn, payload)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}
