//go:build ignore

// Throwaway: tìm mọi file dưới root chứa cụm "quy chế bảo mật" (hồ sơ bệnh
// án) hoặc biến thể, in ra: đường dẫn, level ground-truth (suy từ tên thư
// mục cha "<domain>__<level>"), level scan thực tế, rule đã khớp.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnpt/dlp-classifier/internal/extractor"
	"github.com/vnpt/dlp-classifier/internal/scanner"
)

func main() {
	root := os.Args[1]
	var matches []string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".docx" && ext != ".pdf" {
			return nil
		}
		b, err := extractor.Extract(path)
		if err != nil {
			return nil
		}
		lower := strings.ToLower(string(b))
		if strings.Contains(lower, "quy chế bảo mật") || strings.Contains(lower, "quy định bảo mật") {
			matches = append(matches, path)
		}
		return nil
	})

	fmt.Printf("Tìm thấy %d file\n", len(matches))

	cfg := scanner.DefaultConfig()
	sc := scanner.New(cfg)
	pathCh := make(chan string, len(matches))
	for _, p := range matches {
		pathCh <- p
	}
	close(pathCh)
	sc.ScanPaths(context.Background(), pathCh)

	for r := range sc.Results() {
		if r.Error != "" {
			fmt.Println(r.Path, "ERROR", r.Error)
			continue
		}
		dir := filepath.Base(filepath.Dir(r.Path))
		var rules []string
		for _, m := range r.Matches {
			rules = append(rules, m.RuleID)
		}
		fmt.Printf("%s | GT_DIR=%s | GOT=%s | RULES=%s\n", r.Path, dir, r.LevelName, strings.Join(rules, ","))
	}
}
