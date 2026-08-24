//go:build ignore

// Script đánh giá full confusion matrix trên toàn bộ dataset gendata
// (4 domain x 4 level = 16 thư mục dạng "<domain>__<level>").
// Mục tiêu: đo OVER-classification (file mức thấp bị chấm cao hơn), khác
// eval_restricted.go chỉ đo FN trên 1 thư mục toàn RESTRICTED.
//
// Chạy:
//
//	go run scripts/eval_confusion.go --root "D:\gendata\data\raw"
//	go run scripts/eval_confusion.go --root "D:\gendata\data\raw" --over-only
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/vnpt/dlp-classifier/internal/scanner"
)

var levelOrder = map[string]int{
	"public":       0,
	"internal":     1,
	"confidential": 2,
	"top_secret":   3,
}

var levelToScanner = map[string]string{
	"public":       "PUBLIC",
	"internal":     "INTERNAL",
	"confidential": "CONFIDENTIAL",
	"top_secret":   "RESTRICTED",
}

type entry struct {
	absPath  string
	relPath  string
	domain   string
	expected string // public|internal|confidential|top_secret
}

func main() {
	root := flag.String("root", "D:/gendata/data/raw", "Thư mục gốc chứa các folder <domain>__<level>")
	overOnly := flag.Bool("over-only", false, "Chỉ liệt kê file bị OVER-classify (chấm cao hơn ground truth)")
	underOnly := flag.Bool("under-only", false, "Chỉ liệt kê file bị UNDER-classify (chấm thấp hơn ground truth)")
	workers := flag.Int("workers", 0, "Worker count (default: numCPU, tối đa 8)")
	domainFilter := flag.String("domain", "", "Chỉ đánh giá 1 domain (finance_banking|healthcare|hr|insurance)")
	flag.Parse()

	if *workers <= 0 {
		*workers = runtime.NumCPU()
		if *workers > 8 {
			*workers = 8
		}
	}

	entries, err := collectEntries(*root, *domainFilter)
	if err != nil {
		fmt.Fprintln(os.Stderr, "collect:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Loaded %d files\n", len(entries))

	cfg := scanner.DefaultConfig()
	cfg.MaxWorkers = *workers
	sc := scanner.New(cfg)

	paths := make(chan string, len(entries))
	byPath := make(map[string]entry, len(entries))
	for _, e := range entries {
		paths <- e.absPath
		byPath[e.absPath] = e
	}
	close(paths)

	sc.ScanPaths(context.Background(), paths)

	// confusion[expected][got] = count
	confusion := map[string]map[string]int{}
	for lvl := range levelOrder {
		confusion[lvl] = map[string]int{}
	}

	type resultRow struct {
		relPath, domain, expected, got string
		diff                           int
	}
	var overRows, underRows []resultRow

	for r := range sc.Results() {
		e, ok := byPath[r.Path]
		if !ok {
			continue
		}
		got := strings.ToUpper(r.LevelName)
		expectedScanner := levelToScanner[e.expected]
		confusion[e.expected][got]++

		gotIdx := scannerLevelIdx(got)
		expIdx := levelOrder[e.expected]
		if gotIdx > expIdx {
			overRows = append(overRows, resultRow{e.relPath, e.domain, expectedScanner, got, gotIdx - expIdx})
		} else if gotIdx < expIdx {
			underRows = append(underRows, resultRow{e.relPath, e.domain, expectedScanner, got, expIdx - gotIdx})
		}
	}

	// --- in confusion matrix ---
	fmt.Println("\n=== CONFUSION MATRIX (hàng = ground truth, cột = kết quả scan) ===")
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "EXPECTED\\GOT\tPUBLIC\tINTERNAL\tCONFIDENTIAL\tRESTRICTED\tTotal\tAccuracy")
	levels := []string{"public", "internal", "confidential", "top_secret"}
	totalCorrect, totalAll := 0, 0
	for _, lvl := range levels {
		row := confusion[lvl]
		total := 0
		for _, c := range row {
			total += c
		}
		correct := row[levelToScanner[lvl]]
		totalCorrect += correct
		totalAll += total
		acc := 0.0
		if total > 0 {
			acc = float64(correct) / float64(total) * 100
		}
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%.1f%%\n",
			strings.ToUpper(lvl), row["PUBLIC"], row["INTERNAL"], row["CONFIDENTIAL"], row["RESTRICTED"], total, acc)
	}
	w.Flush()
	fmt.Printf("\nTổng: %d/%d đúng (%.1f%%)\n", totalCorrect, totalAll, float64(totalCorrect)/float64(totalAll)*100)
	fmt.Printf("OVER-classify (chấm cao hơn ground truth):  %d file (%.1f%%)\n", len(overRows), float64(len(overRows))/float64(totalAll)*100)
	fmt.Printf("UNDER-classify (chấm thấp hơn ground truth): %d file (%.1f%%)\n", len(underRows), float64(len(underRows))/float64(totalAll)*100)

	printRows := func(title string, rows []resultRow) {
		fmt.Printf("\n=== %s (%d file) ===\n", title, len(rows))
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].diff != rows[j].diff {
				return rows[i].diff > rows[j].diff
			}
			return rows[i].relPath < rows[j].relPath
		})
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "FILE\tDOMAIN\tEXPECTED\tGOT")
		limit := len(rows)
		if limit > 200 {
			limit = 200
		}
		for _, r := range rows[:limit] {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.relPath, r.domain, r.expected, r.got)
		}
		w.Flush()
		if len(rows) > limit {
			fmt.Printf("... còn %d file nữa (dùng --domain để lọc bớt)\n", len(rows)-limit)
		}
	}

	if !*underOnly {
		printRows("OVER-CLASSIFY — file bị chấm CAO hơn ground truth", overRows)
	}
	if !*overOnly {
		printRows("UNDER-CLASSIFY — file bị chấm THẤP hơn ground truth", underRows)
	}
}

func scannerLevelIdx(level string) int {
	switch level {
	case "PUBLIC":
		return 0
	case "INTERNAL":
		return 1
	case "CONFIDENTIAL":
		return 2
	case "RESTRICTED":
		return 3
	default:
		return -1
	}
}

func collectEntries(root, domainFilter string) ([]entry, error) {
	dirs, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var entries []entry
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		name := d.Name() // vd: finance_banking__top_secret
		parts := strings.SplitN(name, "__", 2)
		if len(parts) != 2 {
			continue
		}
		domain, level := parts[0], parts[1]
		if domainFilter != "" && domain != domainFilter {
			continue
		}
		if _, ok := levelOrder[level]; !ok {
			continue
		}
		dirPath := filepath.Join(root, name)
		fis, err := os.ReadDir(dirPath)
		if err != nil {
			continue
		}
		for _, fi := range fis {
			if fi.IsDir() || strings.HasSuffix(fi.Name(), ".jsonl") {
				continue
			}
			entries = append(entries, entry{
				absPath:  filepath.Join(dirPath, fi.Name()),
				relPath:  filepath.Join(name, fi.Name()),
				domain:   domain,
				expected: level,
			})
		}
	}
	return entries, nil
}
