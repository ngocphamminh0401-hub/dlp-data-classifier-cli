package walker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestWalkRecursiveSkipsConfiguredDirs(t *testing.T) {
	root := t.TempDir()

	mustMkdir(t, filepath.Join(root, "keep"))
	mustMkdir(t, filepath.Join(root, ".git"))
	mustWriteFile(t, filepath.Join(root, "a.txt"), "a")
	mustWriteFile(t, filepath.Join(root, "keep", "b.txt"), "b")
	mustWriteFile(t, filepath.Join(root, ".git", "ignored.txt"), "ignore")

	w := New(DefaultConfig())
	seen := make(map[string]struct{})
	for p := range w.Walk(context.Background(), root, true) {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatalf("filepath.Rel: %v", err)
		}
		seen[filepath.ToSlash(rel)] = struct{}{}
	}

	if _, ok := seen["a.txt"]; !ok {
		t.Fatalf("missing root file")
	}
	if _, ok := seen["keep/b.txt"]; !ok {
		t.Fatalf("missing nested file")
	}
	if _, ok := seen[".git/ignored.txt"]; ok {
		t.Fatalf("file in skipped directory should not be emitted")
	}
}

func TestWalkNonRecursive(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "nested"))
	mustWriteFile(t, filepath.Join(root, "top.txt"), "t")
	mustWriteFile(t, filepath.Join(root, "nested", "deep.txt"), "d")

	w := New(DefaultConfig())
	count := 0
	for range w.Walk(context.Background(), root, false) {
		count++
	}
	if count != 1 {
		t.Fatalf("expected 1 top-level file, got %d", count)
	}
}

func TestWalkHonorsMaxFileSize(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "small.txt"), "small")
	mustWriteFile(t, filepath.Join(root, "large.txt"), "this-is-large")

	cfg := DefaultConfig()
	cfg.MaxFileSizeB = 8
	w := New(cfg)

	var files []string
	for p := range w.Walk(context.Background(), root, false) {
		files = append(files, filepath.Base(p))
	}

	if len(files) != 1 || files[0] != "small.txt" {
		t.Fatalf("expected only small.txt, got %v", files)
	}
}

func BenchmarkWalkRecursive(b *testing.B) {
	root := b.TempDir()
	for d := 0; d < 10; d++ {
		dir := filepath.Join(root, fmt.Sprintf("d%02d", d))
		mustMkdirB(b, dir)
		for i := 0; i < 200; i++ {
			mustWriteFileB(b, filepath.Join(dir, fmt.Sprintf("f%04d.txt", i)), "benchmark-data")
		}
	}

	w := New(DefaultConfig())
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		count := 0
		for range w.Walk(context.Background(), root, true) {
			count++
		}
		if count != 2000 {
			b.Fatalf("expected 2000 files, got %d", count)
		}
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustMkdirB(b *testing.B, path string) {
	b.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		b.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFileB(b *testing.B, path, content string) {
	b.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		b.Fatalf("write %s: %v", path, err)
	}
}
