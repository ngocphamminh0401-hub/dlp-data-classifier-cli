package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type groundTruthRow struct {
	Path        string
	Expected    string
	IncludeEval bool
	Notes       string
}

type scanResult struct {
	Path      string `json:"path"`
	LevelName string `json:"level"`
	LevelCode int    `json:"level_code"`
	Error     string `json:"error,omitempty"`
}

type levelMetric struct {
	Label     string
	TP        int
	FP        int
	FN        int
	Support   int
	Precision float64
	Recall    float64
	F1        float64
}

func main() {
	var gtPath string
	var scanPath string
	var outPath string

	flag.StringVar(&gtPath, "ground-truth", "testdata/ground_truth.csv", "Path to ground-truth CSV")
	flag.StringVar(&scanPath, "scan-jsonl", "", "Path to scan result JSONL")
	flag.StringVar(&outPath, "out", "", "Optional path to write markdown report")
	flag.Parse()

	if scanPath == "" {
		fmt.Fprintln(os.Stderr, "missing required --scan-jsonl")
		os.Exit(2)
	}

	gt, err := loadGroundTruth(gtPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pred, err := loadScanResults(scanPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	report := buildReport(gt, pred)
	fmt.Print(report)

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(report), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func loadGroundTruth(path string) (map[string]groundTruthRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ground truth: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read ground truth csv: %w", err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("ground truth is empty: %s", path)
	}

	out := make(map[string]groundTruthRow, len(rows)-1)
	for i := 1; i < len(rows); i++ {
		row := rows[i]
		if len(row) < 3 {
			continue
		}
		include := strings.EqualFold(strings.TrimSpace(row[2]), "true")
		notes := ""
		if len(row) >= 4 {
			notes = row[3]
		}
		normPath := normalizePath(row[0])
		out[normPath] = groundTruthRow{
			Path:        normPath,
			Expected:    normalizeLevel(row[1]),
			IncludeEval: include,
			Notes:       notes,
		}
	}
	return out, nil
}

func loadScanResults(path string) (map[string]scanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open scan jsonl: %w", err)
	}
	defer f.Close()

	out := make(map[string]scanResult)
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var r scanResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("parse jsonl line: %w", err)
		}
		r.Path = normalizePath(r.Path)
		r.LevelName = normalizeLevel(r.LevelName)
		if r.LevelName == "" {
			r.LevelName = levelFromCode(r.LevelCode)
		}
		out[r.Path] = r
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("scan jsonl read: %w", err)
	}
	return out, nil
}

func buildReport(gt map[string]groundTruthRow, pred map[string]scanResult) string {
	labels := []string{"PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"}

	evalPaths := make([]string, 0, len(gt))
	for p, row := range gt {
		if row.IncludeEval {
			evalPaths = append(evalPaths, p)
		}
	}
	sort.Strings(evalPaths)

	binaryTP, binaryFP, binaryFN := 0, 0, 0
	correct := 0
	metrics := make(map[string]*levelMetric, len(labels))
	for _, l := range labels {
		metrics[l] = &levelMetric{Label: l}
	}
	type mismatch struct {
		Path     string
		Expected string
		Pred     string
		Kind     string
	}
	mismatches := make([]mismatch, 0)

	for _, p := range evalPaths {
		row := gt[p]
		exp := row.Expected
		prd := "PUBLIC"
		if r, ok := pred[p]; ok {
			prd = normalizeLevel(r.LevelName)
			if prd == "" {
				prd = "PUBLIC"
			}
		}

		if prd == exp {
			correct++
		} else {
			kind := "label-mismatch"
			expPos := exp != "PUBLIC"
			prdPos := prd != "PUBLIC"
			if expPos && !prdPos {
				kind = "false-negative"
			}
			if !expPos && prdPos {
				kind = "false-positive"
			}
			mismatches = append(mismatches, mismatch{Path: p, Expected: exp, Pred: prd, Kind: kind})
		}

		expPos := exp != "PUBLIC"
		prdPos := prd != "PUBLIC"
		switch {
		case prdPos && expPos:
			binaryTP++
		case prdPos && !expPos:
			binaryFP++
		case !prdPos && expPos:
			binaryFN++
		}

		for _, l := range labels {
			m := metrics[l]
			if exp == l {
				m.Support++
			}
			if prd == l && exp == l {
				m.TP++
			}
			if prd == l && exp != l {
				m.FP++
			}
			if prd != l && exp == l {
				m.FN++
			}
		}
	}

	binaryP := safeDiv(binaryTP, binaryTP+binaryFP)
	binaryR := safeDiv(binaryTP, binaryTP+binaryFN)
	binaryF1 := f1(binaryP, binaryR)
	acc := safeDiv(correct, len(evalPaths))

	var macroP, macroR, macroF1 float64
	for _, l := range labels {
		m := metrics[l]
		m.Precision = safeDiv(m.TP, m.TP+m.FP)
		m.Recall = safeDiv(m.TP, m.TP+m.FN)
		m.F1 = f1(m.Precision, m.Recall)
		macroP += m.Precision
		macroR += m.Recall
		macroF1 += m.F1
	}
	macroP /= float64(len(labels))
	macroR /= float64(len(labels))
	macroF1 /= float64(len(labels))

	var b strings.Builder
	b.WriteString("# Evaluation Metrics\n\n")
	b.WriteString(fmt.Sprintf("- Evaluated files: %d\n", len(evalPaths)))
	b.WriteString(fmt.Sprintf("- Accuracy (exact level): %.4f\n", acc))
	b.WriteString(fmt.Sprintf("- Binary Precision (sensitive vs clean): %.4f\n", binaryP))
	b.WriteString(fmt.Sprintf("- Binary Recall (sensitive vs clean): %.4f\n", binaryR))
	b.WriteString(fmt.Sprintf("- Binary F1 (sensitive vs clean): %.4f\n", binaryF1))
	b.WriteString(fmt.Sprintf("- Macro Precision (4 levels): %.4f\n", macroP))
	b.WriteString(fmt.Sprintf("- Macro Recall (4 levels): %.4f\n", macroR))
	b.WriteString(fmt.Sprintf("- Macro F1 (4 levels): %.4f\n\n", macroF1))

	b.WriteString("## Per-level metrics\n\n")
	b.WriteString("| Level | Support | TP | FP | FN | Precision | Recall | F1 |\n")
	b.WriteString("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")
	for _, l := range labels {
		m := metrics[l]
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %.4f | %.4f | %.4f |\n", m.Label, m.Support, m.TP, m.FP, m.FN, m.Precision, m.Recall, m.F1))
	}

	b.WriteString("\n## Binary confusion\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("| --- | ---: |\n")
	b.WriteString(fmt.Sprintf("| TP | %d |\n", binaryTP))
	b.WriteString(fmt.Sprintf("| FP | %d |\n", binaryFP))
	b.WriteString(fmt.Sprintf("| FN | %d |\n", binaryFN))

	if len(mismatches) > 0 {
		sort.Slice(mismatches, func(i, j int) bool {
			if mismatches[i].Kind == mismatches[j].Kind {
				return mismatches[i].Path < mismatches[j].Path
			}
			return mismatches[i].Kind < mismatches[j].Kind
		})
		b.WriteString("\n## Mismatches\n\n")
		b.WriteString("| Kind | Path | Expected | Predicted |\n")
		b.WriteString("| --- | --- | --- | --- |\n")
		for _, m := range mismatches {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", m.Kind, m.Path, m.Expected, m.Pred))
		}
	}

	return b.String()
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = filepath.ToSlash(p)
	p = strings.TrimPrefix(p, "./")
	idx := strings.Index(p, "testdata/")
	if idx >= 0 {
		p = p[idx:]
	}
	return p
}

func normalizeLevel(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "CLEAN", "PUBLIC")
	s = strings.ReplaceAll(s, "L0", "PUBLIC")
	s = strings.ReplaceAll(s, "L1", "INTERNAL")
	s = strings.ReplaceAll(s, "L2", "CONFIDENTIAL")
	s = strings.ReplaceAll(s, "L3", "SECRET")
	s = strings.ReplaceAll(s, "L4", "SECRET")
	switch s {
	case "PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET":
		return s
	default:
		return ""
	}
}

func levelFromCode(code int) string {
	switch code {
	case 0:
		return "PUBLIC"
	case 1:
		return "INTERNAL"
	case 2:
		return "CONFIDENTIAL"
	case 3:
		return "SECRET"
	default:
		return "PUBLIC"
	}
}

func safeDiv(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func f1(p, r float64) float64 {
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}
