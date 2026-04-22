//go:build ignore

// Script đánh giá độ chính xác dựa trên ground_truth.csv.
// Chạy: go run scripts/eval_accuracy.go
package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/vnpt/dlp-classifier/internal/scanner"
)

type groundTruth struct {
	path          string
	expectedLevel string
}

func main() {
	truth, err := loadGroundTruth("testdata/ground_truth.csv")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load ground_truth.csv:", err)
		os.Exit(1)
	}

	cfg := scanner.DefaultConfig()
	sc := scanner.New(cfg)

	paths := make(chan string, len(truth))
	indexByPath := make(map[string]string, len(truth))
	for _, gt := range truth {
		paths <- gt.path
		indexByPath[gt.path] = gt.expectedLevel
	}
	close(paths)

	sc.ScanPaths(context.Background(), paths)

	type result struct {
		path     string
		expected string
		got      string
		ok       bool
	}
	var results []result
	for r := range sc.Results() {
		expected, found := indexByPath[r.Path]
		if !found {
			continue
		}
		got := r.LevelName
		// ground_truth dùng "SECRET", scanner trả về "RESTRICTED" cho cùng level
		if got == "RESTRICTED" {
			got = "SECRET"
		}
		results = append(results, result{
			path:     r.Path,
			expected: expected,
			got:      got,
			ok:       strings.EqualFold(expected, got),
		})
	}

	// In chi tiết các file sai
	fmt.Println("=== SAI (incorrect) ===")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FILE\tEXPECTED\tGOT")
	wrong := 0
	for _, r := range results {
		if !r.ok {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.path, r.expected, r.got)
			wrong++
		}
	}
	w.Flush()

	total := len(results)
	correct := total - wrong
	accuracy := 0.0
	if total > 0 {
		accuracy = float64(correct) / float64(total) * 100
	}

	// Tính precision/recall theo từng class
	levels := []string{"PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"}
	fmt.Println("\n=== METRICS PER CLASS ===")
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "LEVEL\tTP\tFP\tFN\tPRECISION\tRECALL\tF1")
	for _, lv := range levels {
		tp, fp, fn := 0, 0, 0
		for _, r := range results {
			predPos := strings.EqualFold(r.got, lv)
			actualPos := strings.EqualFold(r.expected, lv)
			switch {
			case predPos && actualPos:
				tp++
			case predPos && !actualPos:
				fp++
			case !predPos && actualPos:
				fn++
			}
		}
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
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%.2f%%\t%.2f%%\t%.2f%%\n",
			lv, tp, fp, fn, prec*100, rec*100, f1*100)
	}
	tw.Flush()

	fmt.Printf("\n=== OVERALL ===\n")
	fmt.Printf("Total: %d | Correct: %d | Wrong: %d\n", total, correct, wrong)
	fmt.Printf("Accuracy: %.2f%%\n", accuracy)
}

func loadGroundTruth(path string) ([]groundTruth, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	// Bỏ header
	if _, err := r.Read(); err != nil {
		return nil, err
	}

	var out []groundTruth
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		// columns: path, expected_level, include_eval, notes
		if len(row) < 3 {
			continue
		}
		if strings.TrimSpace(strings.ToLower(row[2])) != "true" {
			continue // bỏ qua file không dùng để eval
		}
		out = append(out, groundTruth{
			path:          strings.TrimSpace(row[0]),
			expectedLevel: strings.TrimSpace(strings.ToUpper(row[1])),
		})
	}
	return out, nil
}
