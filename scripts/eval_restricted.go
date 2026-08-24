//go:build ignore

// Script đánh giá độ chính xác trên 1 thư mục mà TẤT CẢ file đều có nhãn
// ground-truth là RESTRICTED (dataset 1-class, không có nhãn khác).
//
// Vì dataset chỉ có nhãn dương (RESTRICTED), không thể đo FP theo nghĩa
// "bị gán nhầm level" (RESTRICTED đã là level cao nhất). Script này dùng
// hai khái niệm:
//
//   - FN (miss): file được chấm level < RESTRICTED -> rule đang thiếu/yếu,
//     cần mở rộng regex.
//   - FP nghi ngờ (suspect match): với các file ĐÃ đạt đúng RESTRICTED,
//     liệt kê từng match (rule_id + đoạn text quanh vị trí match) để người
//     dùng tự soát rule nào match quá rộng / sai ngữ cảnh (VD: rule
//     "mật" trong contract_escalation khớp cả câu NDA thông thường).
//
// Chạy:
//
//	go run scripts/eval_restricted.go --dir "D:\gendata\data\raw\finance_banking__top_secret"
//	go run scripts/eval_restricted.go --dir "..." --fn-only
//	go run scripts/eval_restricted.go --dir "..." --rule bank_account,cvv
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
	"unicode/utf8"

	"github.com/vnpt/dlp-classifier/internal/extractor"
	"github.com/vnpt/dlp-classifier/internal/scanner"
)

type fileResult struct {
	relPath string
	level   string
	isFN    bool
	matches []matchDetail
	errMsg  string
}

type matchDetail struct {
	ruleID     string
	confidence float64
	snippet    string
}

func main() {
	dir := flag.String("dir", "", "Thư mục chứa file (tất cả đều ground-truth RESTRICTED)")
	fnOnly := flag.Bool("fn-only", false, "Chỉ in danh sách FN (file bị miss)")
	ruleFilter := flag.String("rule", "", "Chỉ in match của các rule_id này (phân cách bởi dấu phẩy), dùng để soi rule cụ thể")
	snippetPad := flag.Int("context", 20, "Số ký tự lấy thêm trước/sau match để làm snippet soát FP")
	workers := flag.Int("workers", 0, "Số worker (mặc định = numCPU, tối đa 8)")
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
	var ruleWanted map[string]bool
	if *ruleFilter != "" {
		ruleWanted = map[string]bool{}
		for _, r := range strings.Split(*ruleFilter, ",") {
			ruleWanted[strings.TrimSpace(r)] = true
		}
	}

	paths, err := collectFiles(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "collect files:", err)
		os.Exit(1)
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "không tìm thấy file nào trong", *dir)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Đang quét %d file từ %s\n", len(paths), *dir)

	results := runEval(*dir, paths, *workers, *snippetPad)

	printReport(results, *fnOnly, ruleWanted)
}

func collectFiles(root string) ([]string, error) {
	var files []string
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

func runEval(root string, paths []string, numWorkers, pad int) []fileResult {
	cfg := scanner.DefaultConfig()
	cfg.MaxWorkers = numWorkers
	sc := scanner.New(cfg)

	pathCh := make(chan string, len(paths))
	for _, p := range paths {
		pathCh <- p
	}
	close(pathCh)

	sc.ScanPaths(context.Background(), pathCh)

	// Offset/Length trong Match trỏ vào TEXT ĐÃ GIẢI MÃ (sau extractor), không
	// phải byte thô của file .docx/.pdf gốc (đó là zip/binary nén) — phải
	// dùng cùng extractor.Extract() với scanner thì snippet mới đúng vị trí.
	fileText := map[string][]byte{}
	for _, p := range paths {
		b, err := extractor.Extract(p)
		if err == nil {
			fileText[p] = b
		}
	}

	var results []fileResult
	for r := range sc.Results() {
		rel, _ := filepath.Rel(root, r.Path)
		fr := fileResult{
			relPath: rel,
			level:   r.LevelName,
			isFN:    r.LevelName != "RESTRICTED",
			errMsg:  r.Error,
		}
		data := fileText[r.Path]
		for _, m := range r.Matches {
			fr.matches = append(fr.matches, matchDetail{
				ruleID:     m.RuleID,
				confidence: m.Confidence,
				snippet:    extractSnippet(data, m.Offset, m.Length, pad),
			})
		}
		sort.Slice(fr.matches, func(i, j int) bool { return fr.matches[i].ruleID < fr.matches[j].ruleID })
		results = append(results, fr)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].relPath < results[j].relPath })
	return results
}

// extractSnippet lấy đoạn text quanh vị trí match (theo byte offset) để review,
// cắt an toàn theo ranh giới rune để không làm hỏng UTF-8.
func extractSnippet(data []byte, offset int64, length, pad int) string {
	if data == nil || offset < 0 || int(offset) > len(data) {
		return ""
	}
	start := int(offset) - pad
	if start < 0 {
		start = 0
	}
	end := int(offset) + length + pad
	if end > len(data) {
		end = len(data)
	}
	for start > 0 && !utf8.RuneStart(data[start]) {
		start--
	}
	for end < len(data) && !utf8.RuneStart(data[end]) {
		end++
	}
	snippet := string(data[start:end])
	snippet = strings.ReplaceAll(snippet, "\n", "\\n")
	snippet = strings.ReplaceAll(snippet, "\r", "")
	return snippet
}

func printReport(results []fileResult, fnOnly bool, ruleWanted map[string]bool) {
	var fns []fileResult
	var errs []fileResult
	tp := 0
	for _, r := range results {
		if r.errMsg != "" {
			errs = append(errs, r)
			continue
		}
		if r.isFN {
			fns = append(fns, r)
		} else {
			tp++
		}
	}

	total := len(results)
	fmt.Printf("\n=== TỔNG QUAN ===\n")
	fmt.Printf("Tổng file:        %d\n", total)
	fmt.Printf("Đúng RESTRICTED:  %d (%.1f%%)\n", tp, pct(tp, total))
	fmt.Printf("FN (bị miss):     %d (%.1f%%)\n", len(fns), pct(len(fns), total))
	if len(errs) > 0 {
		fmt.Printf("Lỗi khi scan:     %d\n", len(errs))
	}

	fmt.Printf("\n=== FN — file bị chấm thấp hơn RESTRICTED (cần bổ sung/regex mạnh hơn) ===\n")
	if len(fns) == 0 {
		fmt.Println("(không có)")
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "FILE\tGOT LEVEL")
		for _, r := range fns {
			fmt.Fprintf(w, "%s\t%s\n", r.relPath, r.level)
		}
		w.Flush()
	}

	if fnOnly {
		return
	}

	fmt.Printf("\n=== FP nghi ngờ — match trên file ĐÃ đạt RESTRICTED, tự soát rule/snippet ===\n")
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "FILE\tRULE_ID\tCONF\tSNIPPET")
	any := false
	for _, r := range results {
		if r.isFN || r.errMsg != "" {
			continue
		}
		for _, m := range r.matches {
			if ruleWanted != nil && !ruleWanted[m.ruleID] {
				continue
			}
			any = true
			fmt.Fprintf(w, "%s\t%s\t%.2f\t%s\n", r.relPath, m.ruleID, m.confidence, truncate(m.snippet, 100))
		}
	}
	if !any {
		fmt.Println("(không có match nào khớp bộ lọc)")
	} else {
		w.Flush()
	}

	if len(errs) > 0 {
		fmt.Printf("\n=== LỖI SCAN ===\n")
		for _, r := range errs {
			fmt.Printf("%s: %s\n", r.relPath, r.errMsg)
		}
	}
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n]) + "…"
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}
