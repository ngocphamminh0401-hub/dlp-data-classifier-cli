//go:build ignore

// Script đánh giá độ chính xác trên dataset D:/file test/dataset
// dựa theo nhãn thư mục L1_PUBLIC / L2_INTERNAL / L3_CONFIDENTIAL / L4_RESTRICTED / EDGE_CASES.
//
// Chạy:
//
//	go run scripts/eval_dataset.go --dataset "D:/file test/dataset"
//	go run scripts/eval_dataset.go --dataset "D:/file test/dataset" --wrong-only
//	go run scripts/eval_dataset.go --dataset "D:/file test/dataset" --edge
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/vnpt/dlp-classifier/internal/scanner"
)

// --- mapping nhãn thư mục → level scanner ---

// folderToExpected ánh xạ tên thư mục sang nhãn chuẩn (dùng so sánh).
var folderToExpected = map[string]string{
	"L1_PUBLIC":        "PUBLIC",
	"L2_INTERNAL":      "INTERNAL",
	"L3_CONFIDENTIAL":  "CONFIDENTIAL",
	"L4_RESTRICTED":    "RESTRICTED",
}

// scannerLevel chuẩn hoá output scanner về cùng không gian nhãn.
func normScanner(level string) string {
	if level == "RESTRICTED" {
		return "RESTRICTED"
	}
	return level
}

// --- structs ---

type entry struct {
	absPath  string
	relPath  string
	expected string // PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
	isEdge   bool
}

type evalResult struct {
	relPath  string
	expected string
	got      string
	correct  bool
	isEdge   bool
	duration time.Duration
	errMsg   string
}

// --- main ---

func main() {
	datasetDir := flag.String("dataset", "D:/file test/dataset", "Path to dataset root")
	wrongOnly := flag.Bool("wrong-only", false, "Only print misclassified files")
	includeEdge := flag.Bool("edge", false, "Include EDGE_CASES folder in evaluation")
	outputCSV := flag.String("out-csv", "", "Write detailed results to CSV file")
	workers := flag.Int("workers", 0, "Worker count (default: num CPU)")
	flag.Parse()

	if *workers <= 0 {
		*workers = runtime.NumCPU()
		if *workers > 8 {
			*workers = 8
		}
	}

	entries, err := collectEntries(*datasetDir, *includeEdge)
	if err != nil {
		fmt.Fprintln(os.Stderr, "collect entries:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Loaded %d files for evaluation\n", len(entries))

	results := runEval(entries, *workers)

	// --- in kết quả ---
	printResults(results, *wrongOnly)

	if *outputCSV != "" {
		if err := writeCSV(*outputCSV, results); err != nil {
			fmt.Fprintln(os.Stderr, "write csv:", err)
		} else {
			fmt.Fprintf(os.Stderr, "\nDetailed results saved to: %s\n", *outputCSV)
		}
	}
}

// --- collect ---

func collectEntries(datasetDir string, includeEdge bool) ([]entry, error) {
	var entries []entry

	for folder, expected := range folderToExpected {
		dir := filepath.Join(datasetDir, folder)
		fis, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", dir, err)
		}
		for _, fi := range fis {
			if fi.IsDir() {
				continue
			}
			abs := filepath.Join(dir, fi.Name())
			rel := filepath.Join(folder, fi.Name())
			entries = append(entries, entry{
				absPath:  abs,
				relPath:  rel,
				expected: expected,
				isEdge:   false,
			})
		}
	}

	if includeEdge {
		edgeDir := filepath.Join(datasetDir, "EDGE_CASES")
		fis, err := os.ReadDir(edgeDir)
		if err == nil {
			// EDGE_CASES không có nhãn chính xác nên bỏ qua metrics, chỉ in kết quả
			for _, fi := range fis {
				if fi.IsDir() {
					continue
				}
				abs := filepath.Join(edgeDir, fi.Name())
				rel := filepath.Join("EDGE_CASES", fi.Name())
				entries = append(entries, entry{
					absPath:  abs,
					relPath:  rel,
					expected: "?",
					isEdge:   true,
				})
			}
		}
	}

	return entries, nil
}

// --- eval ---

func runEval(entries []entry, numWorkers int) []evalResult {
	cfg := scanner.DefaultConfig()
	cfg.MaxWorkers = numWorkers
	sc := scanner.New(cfg)

	paths := make(chan string, len(entries))
	pathToEntry := make(map[string]entry, len(entries))
	for _, e := range entries {
		paths <- e.absPath
		pathToEntry[e.absPath] = e
	}
	close(paths)

	sc.ScanPaths(context.Background(), paths)

	var mu sync.Mutex
	results := make([]evalResult, 0, len(entries))

	for r := range sc.Results() {
		e, ok := pathToEntry[r.Path]
		if !ok {
			continue
		}
		got := normScanner(r.LevelName)
		correct := strings.EqualFold(got, e.expected)
		if e.isEdge {
			correct = false // edge cases không tính đúng/sai
		}
		er := evalResult{
			relPath:  e.relPath,
			expected: e.expected,
			got:      got,
			correct:  correct,
			isEdge:   e.isEdge,
			duration: r.Duration,
			errMsg:   r.Error,
		}
		mu.Lock()
		results = append(results, er)
		mu.Unlock()
	}

	return results
}

// --- print ---

func printResults(results []evalResult, wrongOnly bool) {
	levels := []string{"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}

	// Tổng
	var total, correct, edgeTotal int
	labelDist := map[string]int{}   // phân bố nhãn đúng
	errorFiles := []evalResult{}

	for _, r := range results {
		if r.isEdge {
			edgeTotal++
			continue
		}
		total++
		labelDist[r.expected]++
		if r.correct {
			correct++
		} else {
			errorFiles = append(errorFiles, r)
		}
	}

	// --- bảng file sai ---
	fmt.Println("\n╔══════════════════════════════════════════════════════╗")
	fmt.Println("║           FILES PHÂN LOẠI SAI (misclassified)        ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")

	if len(errorFiles) == 0 {
		fmt.Println("  Không có file nào bị phân loại sai!")
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "FILE\tNHÃN ĐÚNG\tDỰ ĐOÁN\tLỖI")
		for _, r := range errorFiles {
			errStr := r.errMsg
			if errStr == "" {
				errStr = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.relPath, r.expected, r.got, errStr)
		}
		tw.Flush()
	}

	// --- confusion matrix ---
	fmt.Println("\n╔══════════════════════════════════════════════════════╗")
	fmt.Println("║                  CONFUSION MATRIX                    ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")

	// matrix[expected][predicted]
	matrix := map[string]map[string]int{}
	for _, lv := range levels {
		matrix[lv] = map[string]int{}
	}
	for _, r := range results {
		if r.isEdge {
			continue
		}
		matrix[r.expected][r.got]++
	}

	tw2 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	header := "Actual \\ Predicted\t" + strings.Join(levels, "\t")
	fmt.Fprintln(tw2, header)
	for _, actual := range levels {
		row := actual
		for _, pred := range levels {
			row += fmt.Sprintf("\t%d", matrix[actual][pred])
		}
		fmt.Fprintln(tw2, row)
	}
	tw2.Flush()

	// --- metrics per class ---
	fmt.Println("\n╔══════════════════════════════════════════════════════╗")
	fmt.Println("║              METRICS THEO TỪNG CLASS                 ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")

	tw3 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw3, "LEVEL\t#SAMPLES\tTP\tFP\tFN\tPRECISION\tRECALL\tF1")
	var totalF1 float64
	classCount := 0
	for _, lv := range levels {
		n := labelDist[lv]
		tp := matrix[lv][lv]
		fp := 0
		for _, actual := range levels {
			if actual != lv {
				fp += matrix[actual][lv]
			}
		}
		fn := n - tp
		prec, rec, f1 := 0.0, 0.0, 0.0
		if tp+fp > 0 {
			prec = float64(tp) / float64(tp+fp)
		}
		if tp+fn > 0 {
			rec = float64(tp) / float64(tp+fn)
		}
		if prec+rec > 0 {
			f1 = 2 * prec * rec / (prec + rec)
		}
		if n > 0 {
			totalF1 += f1
			classCount++
		}
		fmt.Fprintf(tw3, "%s\t%d\t%d\t%d\t%d\t%.1f%%\t%.1f%%\t%.1f%%\n",
			lv, n, tp, fp, fn, prec*100, rec*100, f1*100)
	}
	tw3.Flush()

	macroF1 := 0.0
	if classCount > 0 {
		macroF1 = totalF1 / float64(classCount)
	}
	accuracy := 0.0
	if total > 0 {
		accuracy = float64(correct) / float64(total) * 100
	}

	// --- phân tích lỗi theo hướng ---
	fmt.Println("\n╔══════════════════════════════════════════════════════╗")
	fmt.Println("║              PHÂN TÍCH HƯỚNG LỖI                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	type errPattern struct{ from, to string }
	errCount := map[errPattern]int{}
	for _, r := range errorFiles {
		errCount[errPattern{r.expected, r.got}]++
	}
	tw4 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw4, "HƯỚNG LỖI (Đúng → Dự đoán)\tSỐ FILE\tGHI CHÚ")
	for _, from := range levels {
		for _, to := range levels {
			if from == to {
				continue
			}
			n := errCount[errPattern{from, to}]
			if n == 0 {
				continue
			}
			var note string
			switch {
			case levelRank(to) < levelRank(from):
				note = "⚠ Under-classify (bỏ sót dữ liệu nhạy cảm)"
			case levelRank(to) > levelRank(from):
				note = "ℹ Over-classify (cảnh báo thừa)"
			}
			fmt.Fprintf(tw4, "%s → %s\t%d\t%s\n", from, to, n, note)
		}
	}
	tw4.Flush()

	// --- tổng kết ---
	fmt.Println("\n╔══════════════════════════════════════════════════════╗")
	fmt.Println("║                   TỔNG KẾT                          ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Printf("  Tổng file đánh giá : %d\n", total)
	fmt.Printf("  Đúng               : %d\n", correct)
	fmt.Printf("  Sai                : %d\n", len(errorFiles))
	if edgeTotal > 0 {
		fmt.Printf("  Edge cases (bỏ qua): %d\n", edgeTotal)
	}
	fmt.Printf("  Accuracy           : %.2f%%\n", accuracy)
	fmt.Printf("  Macro F1           : %.2f%%\n", macroF1*100)

	if wrongOnly {
		return
	}
	_ = wrongOnly
}

func levelRank(lv string) int {
	switch lv {
	case "PUBLIC":
		return 1
	case "INTERNAL":
		return 2
	case "CONFIDENTIAL":
		return 3
	case "RESTRICTED":
		return 4
	}
	return 0
}

// --- CSV export ---

func writeCSV(path string, results []evalResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"file", "expected", "predicted", "correct", "is_edge", "duration_ms", "error"})
	for _, r := range results {
		correctStr := "true"
		if !r.correct {
			correctStr = "false"
		}
		_ = w.Write([]string{
			r.relPath,
			r.expected,
			r.got,
			correctStr,
			fmt.Sprintf("%v", r.isEdge),
			fmt.Sprintf("%.2f", float64(r.duration.Milliseconds())),
			r.errMsg,
		})
	}
	w.Flush()
	return w.Error()
}

