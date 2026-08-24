//go:build ignore

// Script quét 1 thư mục bất kỳ (không cần ground truth) và liệt kê file theo
// từng mức phân loại mà scanner gán (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED).
//
// Chạy:
//
//	go run scripts/scan_by_level.go --dir "D:\path\to\folder"
//	go run scripts/scan_by_level.go --dir "D:\path\to\folder" --recursive=false
//	go run scripts/scan_by_level.go --dir "D:\path\to\folder" --level RESTRICTED
//	go run scripts/scan_by_level.go --dir "D:\path\to\folder" --rules-only
//	go run scripts/scan_by_level.go --dir "D:\path\to\folder" --out result.txt
//	go run scripts/scan_by_level.go --dir "D:\path\to\folder" --flat --out result.txt
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/vnpt/dlp-classifier/internal/scanner"
)

func main() {
	dir := flag.String("dir", "", "Thư mục cần quét")
	recursive := flag.Bool("recursive", true, "Quét cả thư mục con")
	levelFilter := flag.String("level", "", "Chỉ in 1 mức cụ thể: PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED")
	rulesOnly := flag.Bool("rules-only", false, "Chỉ in tên rule đã khớp thay vì đường dẫn đầy đủ")
	flat := flag.Bool("flat", false, "In 1 bảng phẳng: tên file, đường dẫn, level (mỗi dòng 1 file, không nhóm theo level)")
	workers := flag.Int("workers", 0, "Số worker (mặc định numCPU, tối đa 8)")
	outPath := flag.String("out", "", "Ghi kết quả ra file (đồng thời vẫn in ra màn hình)")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "cần truyền --dir")
		os.Exit(1)
	}
	if *workers <= 0 {
		*workers = runtime.NumCPU()
		if *workers > 8 {
			*workers = 8
		}
	}

	paths, err := collectFiles(*dir, *recursive)
	if err != nil {
		fmt.Fprintln(os.Stderr, "collect files:", err)
		os.Exit(1)
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "không tìm thấy file nào trong", *dir)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Đang quét %d file từ %s\n", len(paths), *dir)

	cfg := scanner.DefaultConfig()
	cfg.MaxWorkers = *workers
	sc := scanner.New(cfg)

	pathCh := make(chan string, len(paths))
	for _, p := range paths {
		pathCh <- p
	}
	close(pathCh)

	sc.ScanPaths(context.Background(), pathCh)

	byLevel := map[string][]scanner.ScanResult{
		"PUBLIC":       nil,
		"INTERNAL":     nil,
		"CONFIDENTIAL": nil,
		"RESTRICTED":   nil,
	}
	var errored []scanner.ScanResult

	for r := range sc.Results() {
		if r.Error != "" {
			errored = append(errored, r)
			continue
		}
		byLevel[r.LevelName] = append(byLevel[r.LevelName], r)
	}

	levels := []string{"RESTRICTED", "CONFIDENTIAL", "INTERNAL", "PUBLIC"}
	total := len(paths)

	var out io.Writer = os.Stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tạo file out:", err)
			os.Exit(1)
		}
		defer f.Close()
		out = io.MultiWriter(os.Stdout, f)
	}

	fmt.Fprintf(out, "\n=== TỔNG QUAN (%d file, thư mục %s) ===\n", total, *dir)
	w := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "LEVEL\tSỐ FILE\tTỶ LỆ")
	for _, lvl := range levels {
		n := len(byLevel[lvl])
		fmt.Fprintf(w, "%s\t%d\t%.1f%%\n", lvl, n, pct(n, total))
	}
	if len(errored) > 0 {
		fmt.Fprintf(w, "LỖI SCAN\t%d\t%.1f%%\n", len(errored), pct(len(errored), total))
	}
	w.Flush()

	if *flat {
		var all []scanner.ScanResult
		for _, lvl := range levels {
			if *levelFilter != "" && !strings.EqualFold(*levelFilter, lvl) {
				continue
			}
			all = append(all, byLevel[lvl]...)
		}
		sort.Slice(all, func(i, j int) bool { return all[i].Path < all[j].Path })
		fmt.Fprintf(out, "\n=== DANH SÁCH FILE (%d file) ===\n", len(all))
		w := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
		if *rulesOnly {
			fmt.Fprintln(w, "TÊN FILE\tLEVEL\tRULES\tĐƯỜNG DẪN")
			for _, r := range all {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", filepath.Base(r.Path), r.LevelName, ruleList(r), r.Path)
			}
		} else {
			fmt.Fprintln(w, "TÊN FILE\tLEVEL\tĐƯỜNG DẪN")
			for _, r := range all {
				fmt.Fprintf(w, "%s\t%s\t%s\n", filepath.Base(r.Path), r.LevelName, r.Path)
			}
		}
		w.Flush()
	} else {
		for _, lvl := range levels {
			if *levelFilter != "" && !strings.EqualFold(*levelFilter, lvl) {
				continue
			}
			results := byLevel[lvl]
			fmt.Fprintf(out, "\n=== %s (%d file) ===\n", lvl, len(results))
			if len(results) == 0 {
				fmt.Fprintln(out, "(không có)")
				continue
			}
			sort.Slice(results, func(i, j int) bool { return results[i].Path < results[j].Path })
			w := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
			if *rulesOnly {
				fmt.Fprintln(w, "FILE\tRULES")
				for _, r := range results {
					fmt.Fprintf(w, "%s\t%s\n", filepath.Base(r.Path), ruleList(r))
				}
			} else {
				fmt.Fprintln(w, "FILE")
				for _, r := range results {
					fmt.Fprintln(w, r.Path)
				}
			}
			w.Flush()
		}
	}

	if len(errored) > 0 {
		fmt.Fprintf(out, "\n=== LỖI SCAN (%d file) ===\n", len(errored))
		for _, r := range errored {
			fmt.Fprintf(out, "%s: %s\n", r.Path, r.Error)
		}
	}

	if *outPath != "" {
		fmt.Fprintf(os.Stderr, "\nĐã ghi kết quả ra: %s\n", *outPath)
	}
}

func ruleList(r scanner.ScanResult) string {
	seen := map[string]bool{}
	var ids []string
	for _, m := range r.Matches {
		if !seen[m.RuleID] {
			seen[m.RuleID] = true
			ids = append(ids, m.RuleID)
		}
	}
	if len(ids) == 0 {
		return "(không match rule nào)"
	}
	sort.Strings(ids)
	return strings.Join(ids, ", ")
}

func collectFiles(root string, recursive bool) ([]string, error) {
	var files []string
	if !recursive {
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() {
				files = append(files, filepath.Join(root, e.Name()))
			}
		}
		return files, nil
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}
