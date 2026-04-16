// Package scanner — Scanner Core: worker pool, stream/mmap strategy, result aggregation.
package scanner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/vnpt/dlp-classifier/internal/engine"
	"github.com/vnpt/dlp-classifier/internal/extractor"
	"github.com/vnpt/dlp-classifier/internal/models"
)

var (
	ErrFileTimeout  = errors.New("scan file timeout")
	ErrChunkTimeout = errors.New("scan chunk timeout")
)

// Config cấu hình cho Scanner.
type Config struct {
	MaxWorkers    int
	MaxFileSizeB  int64
	BatchSize     int
	MmapThreshold int64
	ChunkSize     int
	ChunkOverlap  int
	ContextWindow int
	FastFail      bool
	FileTimeout   time.Duration
	ChunkTimeout  time.Duration
	RulesDir      string
	MinConfidence float64
	AuditLogPath  string
}

// DefaultConfig trả về cấu hình mặc định.
func DefaultConfig() Config {
	return Config{
		MaxWorkers:    defaultWorkerCount(),
		MaxFileSizeB:  50 * 1024 * 1024,
		BatchSize:     2_000_000,
		MmapThreshold: 1 * 1024 * 1024,
		ChunkSize:     64 * 1024,
		ChunkOverlap:  512,
		ContextWindow: 200,
		FastFail:      false,
		FileTimeout:   2 * time.Minute,
		ChunkTimeout:  0,
		RulesDir:      "./rules",
		MinConfidence: 0.60,
	}
}

// Scanner điều phối toàn bộ pipeline quét.
type Scanner struct {
	cfg     Config
	sem     chan struct{}
	results chan ScanResult
	wg      sync.WaitGroup
	eng     *engine.Engine
	initErr error
	bufPool sync.Pool
	mapPool sync.Pool
}

func defaultWorkerCount() int {
	n := runtime.NumCPU() - 1
	if n < 1 {
		n = 1
	}
	if n > 8 {
		n = 8
	}
	return n
}

// New tạo Scanner mới với cấu hình đã cho.
func New(cfg Config) *Scanner {
	if cfg.MaxWorkers <= 0 {
		cfg.MaxWorkers = defaultWorkerCount()
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = 64 * 1024
	}
	if cfg.ChunkOverlap <= 0 {
		cfg.ChunkOverlap = 512
	}
	if cfg.ContextWindow <= 0 {
		cfg.ContextWindow = 200
	}
	if cfg.RulesDir == "" {
		cfg.RulesDir = "./rules"
	}

	rs, err := engine.LoadRuleSet(cfg.RulesDir)
	var eng *engine.Engine
	if err == nil {
		eng = engine.New(rs, engine.EngineConfig{
			MinConfidence:    cfg.MinConfidence,
			ContextWindow:    cfg.ContextWindow,
			FastFail:         cfg.FastFail,
			EntropyThreshold: 4.5,
		})
	}

	s := &Scanner{
		cfg:     cfg,
		sem:     make(chan struct{}, cfg.MaxWorkers),
		results: make(chan ScanResult, cfg.MaxWorkers*2),
		eng:     eng,
		initErr: err,
	}
	s.bufPool.New = func() any {
		return make([]byte, 0, cfg.ChunkSize+cfg.ChunkOverlap)
	}
	s.mapPool.New = func() any {
		return make(map[string]struct{}, 64)
	}
	return s
}

// ScanPaths nhận danh sách đường dẫn và gửi ScanResult vào channel.
// Caller chịu trách nhiệm đọc kết quả từ Results().
func (s *Scanner) ScanPaths(ctx context.Context, paths <-chan string) {
	go func() {
		defer close(s.results)
		for path := range paths {
			select {
			case <-ctx.Done():
				return
			case s.sem <- struct{}{}:
			}
			s.wg.Add(1)
			go func(p string) {
				defer func() {
					<-s.sem
					s.wg.Done()
				}()

				result, err := s.ScanFile(p)
				if err != nil {
					result.Error = err.Error()
					if result.StatusCode == StatusUnknown || result.StatusCode == StatusOK {
						result.StatusCode = statusFromError(err)
					}
				}
				s.results <- result
			}(path)
		}
		s.wg.Wait()
	}()
}

// Results trả về channel đọc ScanResult.
func (s *Scanner) Results() <-chan ScanResult { return s.results }

// ScanFile quét một file và trả về kết quả phân loại.
func (s *Scanner) ScanFile(path string) (ScanResult, error) {
	start := time.Now()
	result := ScanResult{Path: path, StatusCode: StatusOK, Level: LevelPublic, LevelName: LevelPublic.String()}
	deadline := fileDeadline(start, s.cfg.FileTimeout)

	if s.initErr != nil {
		result.Duration = time.Since(start)
		return result, fmt.Errorf("scanner init failed: %w", s.initErr)
	}
	if s.eng == nil {
		result.Duration = time.Since(start)
		return result, fmt.Errorf("scanner engine is not initialized")
	}

	fi, err := os.Stat(path)
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}
	if fi.IsDir() {
		result.StatusCode = StatusSkippedDirectory
		result.Duration = time.Since(start)
		return result, nil
	}
	if s.cfg.MaxFileSizeB > 0 && fi.Size() > s.cfg.MaxFileSizeB {
		result.StatusCode = StatusSkippedTooLarge
		result.Duration = time.Since(start)
		return result, nil
	}
	if expired(deadline) {
		result.StatusCode = StatusTimeout
		result.Duration = time.Since(start)
		return result, ErrFileTimeout
	}

	if extractor.CanExtract(path) {
		text, err := extractor.Extract(path)
		if err != nil {
			result.Duration = time.Since(start)
			return result, err
		}
		if err := s.scanBuffer(text, &result, deadline); err != nil {
			result.Duration = time.Since(start)
			return result, err
		}
		result.Duration = time.Since(start)
		return result, nil
	}

	f, err := os.Open(path)
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}
	defer f.Close()

	head, err := readHead(f, 4096)
	if err != nil {
		result.Duration = time.Since(start)
		return result, err
	}
	if shouldSkipBinary(path, head) {
		result.StatusCode = StatusSkippedBinary
		result.Duration = time.Since(start)
		return result, nil
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		result.Duration = time.Since(start)
		return result, err
	}

	if fi.Size() > s.cfg.MmapThreshold {
		if err := s.scanMMAP(f, &result, deadline); err != nil {
			if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
				result.Duration = time.Since(start)
				return result, seekErr
			}
			if err := s.scanStream(f, &result, deadline); err != nil {
				result.Duration = time.Since(start)
				return result, err
			}
		}
	} else {
		raw, err := io.ReadAll(f)
		if err != nil {
			result.Duration = time.Since(start)
			return result, err
		}
		decoded, err := decodeContent(raw)
		if err != nil {
			result.Duration = time.Since(start)
			return result, err
		}
		if err := s.scanBuffer(decoded, &result, deadline); err != nil {
			result.Duration = time.Since(start)
			return result, err
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (s *Scanner) scanStream(f *os.File, result *ScanResult, deadline time.Time) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	reader, err := newDecodedReader(f)
	if err != nil {
		return err
	}

	buf := make([]byte, s.cfg.ChunkSize)
	carry := make([]byte, 0, s.cfg.ChunkOverlap)
	dedup := s.getDedupMap()
	defer s.putDedupMap(dedup)
	var streamOffset int64

	for {
		if expired(deadline) {
			return ErrFileTimeout
		}
		n, readErr := reader.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			var fastFailed bool
			streamOffset, carry, fastFailed, err = s.scanChunkWithCarry(chunk, streamOffset, carry, result, dedup)
			if err != nil {
				return err
			}
			if fastFailed {
				return nil
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	return nil
}

func (s *Scanner) scanChunkWithCarry(chunk []byte, streamOffset int64, carry []byte, result *ScanResult, dedup map[string]struct{}) (int64, []byte, bool, error) {
	need := len(carry) + len(chunk)
	combined := s.getBuffer(need)
	defer s.putBuffer(combined)
	combined = combined[:need]
	copy(combined, carry)
	copy(combined[len(carry):], chunk)

	baseOffset := streamOffset - int64(len(carry))
	out, err := s.scanWithChunkTimeout(combined, baseOffset)
	if err != nil {
		return streamOffset, carry, false, err
	}
	s.applyScanOutput(out, result, dedup)

	if len(combined) > s.cfg.ChunkOverlap {
		carry = append(carry[:0], combined[len(combined)-s.cfg.ChunkOverlap:]...)
	} else {
		carry = append(carry[:0], combined...)
	}

	return streamOffset + int64(len(chunk)), carry, out.FastFailed, nil
}

func (s *Scanner) scanBuffer(decoded []byte, result *ScanResult, deadline time.Time) error {
	if expired(deadline) {
		return ErrFileTimeout
	}
	if len(decoded) <= s.cfg.ChunkSize {
		out, err := s.scanWithChunkTimeout(decoded, 0)
		if err != nil {
			return err
		}
		s.applyScanOutput(out, result, nil)
		return nil
	}

	dedup := s.getDedupMap()
	defer s.putDedupMap(dedup)
	carry := make([]byte, 0, s.cfg.ChunkOverlap)
	var offset int64

	for start := 0; start < len(decoded); start += s.cfg.ChunkSize {
		if expired(deadline) {
			return ErrFileTimeout
		}
		end := start + s.cfg.ChunkSize
		if end > len(decoded) {
			end = len(decoded)
		}
		var fastFailed bool
		var err error
		offset, carry, fastFailed, err = s.scanChunkWithCarry(decoded[start:end], offset, carry, result, dedup)
		if err != nil {
			return err
		}
		if fastFailed {
			return nil
		}
	}
	return nil
}

func (s *Scanner) scanWithChunkTimeout(chunk []byte, baseOffset int64) (engine.ScanOutput, error) {
	if s.cfg.ChunkTimeout <= 0 {
		return s.eng.Scan(chunk, baseOffset), nil
	}

	outCh := make(chan engine.ScanOutput, 1)
	go func() {
		outCh <- s.eng.Scan(chunk, baseOffset)
	}()

	select {
	case out := <-outCh:
		return out, nil
	case <-time.After(s.cfg.ChunkTimeout):
		return engine.ScanOutput{}, ErrChunkTimeout
	}
}

func (s *Scanner) getBuffer(minCap int) []byte {
	b := s.bufPool.Get().([]byte)
	if cap(b) < minCap {
		return make([]byte, 0, minCap)
	}
	return b[:0]
}

func (s *Scanner) putBuffer(b []byte) {
	if cap(b) > 4*(s.cfg.ChunkSize+s.cfg.ChunkOverlap) {
		return
	}
	s.bufPool.Put(b[:0])
}

func (s *Scanner) getDedupMap() map[string]struct{} {
	return s.mapPool.Get().(map[string]struct{})
}

func (s *Scanner) putDedupMap(m map[string]struct{}) {
	for k := range m {
		delete(m, k)
	}
	s.mapPool.Put(m)
}

func fileDeadline(start time.Time, timeout time.Duration) time.Time {
	if timeout <= 0 {
		return time.Time{}
	}
	return start.Add(timeout)
}

func expired(deadline time.Time) bool {
	return !deadline.IsZero() && time.Now().After(deadline)
}

func (s *Scanner) applyScanOutput(out engine.ScanOutput, result *ScanResult, dedup map[string]struct{}) {
	if lvl := mapLevel(out.FinalLevel); lvl > result.Level {
		result.Level = lvl
		result.LevelName = lvl.String()
	}

	for _, m := range out.Matches {
		if dedup != nil {
			k := dedupKey(m)
			if _, ok := dedup[k]; ok {
				continue
			}
			dedup[k] = struct{}{}
		}

		result.Matches = append(result.Matches, Match{
			RuleID:     m.RuleID,
			Offset:     m.Offset,
			Length:     m.Length,
			Confidence: m.Confidence,
		})

		internalMatch := models.ScanMatch{
			RuleID:     m.RuleID,
			RuleName:   m.RuleName,
			Category:   m.Category,
			ByteOffset: m.Offset,
			Length:     m.Length,
			Value:      m.Value,
			Context:    m.Context,
			Confidence: m.Confidence,
		}
		result.Matches[len(result.Matches)-1] = internalMatch.ToPublic()

		lvl := mapLevel(m.Level)
		if lvl > result.Level {
			result.Level = lvl
			result.LevelName = lvl.String()
		}
	}
}

func statusFromError(err error) ScanStatus {
	if err == nil {
		return StatusOK
	}
	if errors.Is(err, ErrFileTimeout) || errors.Is(err, ErrChunkTimeout) {
		return StatusTimeout
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "encrypt") || strings.Contains(lower, "password") {
		return StatusEncrypted
	}
	return StatusError
}

func dedupKey(m engine.RuleMatch) string {
	return fmt.Sprintf("%s:%d:%d", m.RuleID, m.Offset, m.Length)
}

func mapLevel(level engine.ClassificationLevel) Level {
	switch level {
	case engine.Internal:
		return LevelInternal
	case engine.Confidential:
		return LevelConfidential
	case engine.Secret:
		return LevelSecret
	default:
		return LevelPublic
	}
}

func readHead(f *os.File, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	r := bufio.NewReaderSize(f, n)
	head, err := r.Peek(n)
	if err != nil && err != bufio.ErrBufferFull && err != io.EOF {
		return nil, err
	}
	out := make([]byte, len(head))
	copy(out, head)
	return out, nil
}
