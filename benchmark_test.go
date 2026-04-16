// benchmark_test.go — benchmark Scanner Core trên testdata.
// Chạy: go test -bench=BenchmarkScan -benchmem -benchtime=30s
package main

import (
	"path/filepath"

	"github.com/vnpt/dlp-classifier/internal/engine"
	"github.com/vnpt/dlp-classifier/internal/scanner"
	"testing"
)

// BenchmarkScanFiles đo throughput quét file trên testdata.
func BenchmarkScanFiles(b *testing.B) {
	files := []string{
		filepath.Join("testdata", "positive", "confidential_vn_id_001.txt"),
		filepath.Join("testdata", "positive", "secret_credit_card_001.txt"),
		filepath.Join("testdata", "positive", "confidential_email_001.csv"),
		filepath.Join("testdata", "positive", "secret_token_001.log"),
		filepath.Join("testdata", "positive", "secret_credit_card_002.pdf"),
		filepath.Join("testdata", "positive", "confidential_vn_id_002.docx"),
		filepath.Join("testdata", "negative", "clean_document_001.txt"),
		filepath.Join("testdata", "negative", "clean_part_number_001.pdf"),
		filepath.Join("testdata", "negative", "clean_uuid_001.docx"),
	}

	cfg := scanner.DefaultConfig()
	cfg.RulesDir = filepath.Join("rules")
	cfg.ChunkTimeout = 0 // benchmark thuần engine throughput

	sc := scanner.New(cfg)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		path := files[i%len(files)]
		res, err := sc.ScanFile(path)
		if err != nil {
			b.Fatalf("scan %s: %v", path, err)
		}
		if len(res.Matches) < 0 {
			b.Fatalf("impossible branch to keep compiler from eliminating call")
		}
	}
}

// BenchmarkAhoCorasick đo tốc độ keyword matching.
func BenchmarkAhoCorasick(b *testing.B) {
	rs, err := engine.LoadRuleSet(filepath.Join("rules"))
	if err != nil {
		b.Fatalf("load rules: %v", err)
	}
	idx := engine.BuildKeywordIndex(rs)

	text := []byte("CCCD 034098765432; thẻ tín dụng Visa 4111 1111 1111 1111; CVV 123; access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		hits := idx.Scan(text)
		if len(hits) == 0 {
			b.Fatalf("expected at least one keyword hit")
		}
	}
}

// BenchmarkShannonEntropy đo tốc độ tính entropy.
func BenchmarkShannonEntropy(b *testing.B) {
	data := make([]byte, 4096)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = engine.ShannonEntropy(data)
	}
}
