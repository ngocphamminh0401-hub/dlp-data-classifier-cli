package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/vnpt/dlp-classifier/internal/engine"
	"github.com/vnpt/dlp-classifier/internal/output"
	"github.com/vnpt/dlp-classifier/internal/scanner"
	"github.com/vnpt/dlp-classifier/internal/walker"
)

const version = "1.0.0"

type cliOptions struct {
	configPath    string
	path          string
	rulesDir      string
	outputFormat  string
	outputPath    string
	workers       int
	levelFilter   string
	dryRun        bool
	maxFileSize   string
	minConfidence float64
	recursive     bool
	auditLogPath  string
	iterations    int
	updateSource  string
	updateTarget  string
}

func newRootCmd() *cobra.Command {
	opts := &cliOptions{}

	root := &cobra.Command{
		Use:   "dlp",
		Short: "High-performance DLP classifier CLI",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initConfigAndLogger(opts)
		},
	}

	root.PersistentFlags().StringVar(&opts.configPath, "config", "", "Path to config file (default: ~/.dlp/config.yaml)")

	root.AddCommand(newScanCmd(opts))
	root.AddCommand(newValidateRulesCmd(opts))
	root.AddCommand(newBenchmarkCmd(opts))
	root.AddCommand(newUpdateRulesCmd(opts))
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print CLI version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("dlp-cli v%s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		},
	})
	return root
}

func newScanCmd(opts *cliOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan files and emit findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(opts)
		},
	}
	cmd.Flags().StringVar(&opts.path, "path", "", "File or directory path to scan")
	cmd.Flags().StringVar(&opts.rulesDir, "rules", "", "Rules directory")
	cmd.Flags().StringVar(&opts.outputFormat, "output", "", "Output format: json|csv|text")
	cmd.Flags().StringVar(&opts.outputPath, "output-file", "", "Write output to file")
	cmd.Flags().IntVar(&opts.workers, "workers", 0, "Number of workers")
	cmd.Flags().StringVar(&opts.levelFilter, "level-filter", "", "Minimum level: PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "List scan plan without running scanner")
	cmd.Flags().StringVar(&opts.maxFileSize, "max-file-size", "", "Max file size (e.g. 50MB)")
	cmd.Flags().Float64Var(&opts.minConfidence, "min-confidence", 0, "Minimum confidence")
	cmd.Flags().BoolVar(&opts.recursive, "recursive", true, "Scan directories recursively")
	cmd.Flags().StringVar(&opts.auditLogPath, "audit-log", "", "JSONL audit log path")
	_ = cmd.MarkFlagRequired("path")
	return cmd
}

func newValidateRulesCmd(opts *cliOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate-rules",
		Short: "Validate and compile all rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			rulesDir := pickString(opts.rulesDir, viper.GetString("rules.dir"), "./rules")
			rs, err := engine.LoadRuleSet(rulesDir)
			if err != nil {
				return err
			}
			slog.Info("rules validated", "rules_dir", rulesDir, "rule_count", len(rs.Rules), "compound_rule_count", len(rs.CompoundRules))
			fmt.Printf("OK: %d rules, %d compound rules\n", len(rs.Rules), len(rs.CompoundRules))
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.rulesDir, "rules", "", "Rules directory")
	return cmd
}

func newBenchmarkCmd(opts *cliOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Benchmark scanner throughput on a path",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.path == "" {
				return errors.New("--path is required")
			}
			iters := opts.iterations
			if iters <= 0 {
				iters = 3
			}
			start := time.Now()
			var totalFiles int
			for i := 0; i < iters; i++ {
				paths, totalHint, err := streamInputPaths(opts.path, opts.recursive)
				if err != nil {
					return err
				}
				scanOpts := *opts
				scanOpts.dryRun = false
				scanOpts.outputFormat = "json"
				scanOpts.outputPath = ""
				scanned, err := runScanWithPaths(&scanOpts, paths, totalHint, io.Discard)
				if err != nil {
					return err
				}
				totalFiles += scanned
			}
			d := time.Since(start)
			fps := float64(totalFiles) / d.Seconds()
			fmt.Printf("Benchmark: %d files in %s (%.2f files/s)\n", totalFiles, d.Round(time.Millisecond), fps)
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.path, "path", "", "File or directory path to benchmark")
	cmd.Flags().IntVar(&opts.iterations, "iterations", 3, "Benchmark iterations")
	cmd.Flags().BoolVar(&opts.recursive, "recursive", true, "Scan directories recursively")
	return cmd
}

func newUpdateRulesCmd(opts *cliOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-rules",
		Short: "Update rules from a source directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			src := pickString(opts.updateSource, "", "")
			dst := pickString(opts.updateTarget, viper.GetString("rules.dir"), "./rules")
			if src == "" {
				return errors.New("--source is required")
			}
			if err := copyDir(src, dst); err != nil {
				return err
			}
			fmt.Printf("Rules updated: %s -> %s\n", src, dst)
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.updateSource, "source", "", "Source rules directory")
	cmd.Flags().StringVar(&opts.updateTarget, "target", "", "Target rules directory (default from config)")
	return cmd
}

func runScan(opts *cliOptions) error {
	if opts.dryRun {
		files, err := collectFiles(opts.path, opts.recursive)
		if err != nil {
			return err
		}
		fmt.Printf("Dry-run: %d files queued from %s\n", len(files), opts.path)
		for _, f := range files {
			fmt.Println(f)
		}
		return nil
	}

	w, closeFn, err := outputWriter(opts.outputPath)
	if err != nil {
		return err
	}
	defer closeFn()

	paths, totalHint, err := streamInputPaths(opts.path, opts.recursive)
	if err != nil {
		return err
	}
	_, err = runScanWithPaths(opts, paths, totalHint, w)
	return err
}

func runScanWithFiles(opts *cliOptions, files []string, out io.Writer) (int, error) {
	paths := make(chan string, len(files))
	for _, p := range files {
		paths <- p
	}
	close(paths)
	return runScanWithPaths(opts, paths, len(files), out)
}

func runScanWithPaths(opts *cliOptions, paths <-chan string, totalHint int, out io.Writer) (int, error) {
	cfg := scanner.DefaultConfig()
	cfg.MaxWorkers = pickInt(opts.workers, viper.GetInt("scanner.workers"), cfg.MaxWorkers)
	cfg.RulesDir = pickString(opts.rulesDir, viper.GetString("rules.dir"), cfg.RulesDir)
	cfg.AuditLogPath = pickString(opts.auditLogPath, viper.GetString("output.audit_log"), cfg.AuditLogPath)
	cfg.MinConfidence = pickFloat(opts.minConfidence, viper.GetFloat64("rules.min_confidence"), cfg.MinConfidence)

	maxSizeStr := pickString(opts.maxFileSize, viper.GetString("scanner.max_file_size"), "50MB")
	if maxSizeStr != "" {
		sz, err := parseByteSize(maxSizeStr)
		if err != nil {
			return 0, fmt.Errorf("invalid --max-file-size: %w", err)
		}
		cfg.MaxFileSizeB = sz
	}

	format := strings.ToLower(pickString(opts.outputFormat, viper.GetString("output.default_format"), "json"))
	if format == "stdout" {
		format = "text"
	}
	if format != "json" && format != "csv" && format != "text" {
		return 0, fmt.Errorf("unsupported output format: %s", format)
	}

	minLevel, err := parseLevel(pickString(opts.levelFilter, "INTERNAL", "INTERNAL"))
	if err != nil {
		return 0, err
	}

	sc := scanner.New(cfg)
	ctx := context.Background()
	sc.ScanPaths(ctx, paths)

	showProgress := !(format == "text" && out == os.Stdout)
	var bar *progressbar.ProgressBar
	if showProgress && totalHint > 0 {
		bar = progressbar.NewOptions(totalHint,
			progressbar.OptionSetDescription("Scanning"),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetItsString("files/s"),
			progressbar.OptionSetWidth(20),
			progressbar.OptionShowElapsedTimeOnFinish(),
			progressbar.OptionSetPredictTime(true),
			progressbar.OptionClearOnFinish(),
		)
	}

	var audit *output.AuditLogger
	if cfg.AuditLogPath != "" {
		al, err := output.NewAuditLogger(cfg.AuditLogPath)
		if err != nil {
			return 0, err
		}
		audit = al
		defer audit.Close()
	}

	csvW := csv.NewWriter(out)
	if format == "csv" {
		_ = csvW.Write([]string{"path", "status", "level", "rule_id", "offset", "length", "confidence", "error"})
	}

	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)

	count := 0
	levelCounts := map[string]int{
		"PUBLIC":       0,
		"INTERNAL":     0,
		"CONFIDENTIAL": 0,
		"RESTRICTED":   0,
	}
	for r := range sc.Results() {
		if bar != nil {
			_ = bar.Add(1)
		}
		count++
		if r.Level < minLevel {
			continue
		}

		switch format {
		case "json":
			if err := enc.Encode(r); err != nil {
				return 0, err
			}
		case "csv":
			if len(r.Matches) == 0 {
				_ = csvW.Write([]string{r.Path, r.StatusCode.String(), r.LevelName, "", "", "", "", r.Error})
			} else {
				for _, m := range r.Matches {
					_ = csvW.Write([]string{
						r.Path,
						r.StatusCode.String(),
						r.LevelName,
						m.RuleID,
						strconv.FormatInt(m.Offset, 10),
						strconv.Itoa(m.Length),
						fmt.Sprintf("%.4f", m.Confidence),
						r.Error,
					})
				}
			}
		case "text":
			renderTextResult(out, r, 3)
		}

		if audit != nil {
			for _, m := range r.Matches {
				_ = audit.Write(output.AuditEvent{
					Path:       r.Path,
					Level:      r.LevelName,
					RuleID:     m.RuleID,
					Offset:     m.Offset,
					Confidence: m.Confidence,
				})
			}
		}
		levelCounts[r.LevelName]++
	}

	if format == "csv" {
		csvW.Flush()
		if err := csvW.Error(); err != nil {
			return 0, err
		}
	}

	fmt.Fprintf(os.Stderr, "Scanned files: %d\n", count)
	if format == "text" {
		fmt.Fprintln(out, "Summary")
		fmt.Fprintf(out, "  PUBLIC: %d\n", levelCounts["PUBLIC"])
		fmt.Fprintf(out, "  INTERNAL: %d\n", levelCounts["INTERNAL"])
		fmt.Fprintf(out, "  CONFIDENTIAL: %d\n", levelCounts["CONFIDENTIAL"])
		fmt.Fprintf(out, "  RESTRICTED: %d\n", levelCounts["RESTRICTED"])
	}
	return count, nil
}

func renderTextResult(out io.Writer, r scanner.ScanResult, maxMatches int) {
	fmt.Fprintf(out, "[%s/%s] %s\n", r.StatusCode.String(), r.LevelName, r.Path)
	fmt.Fprintf(out, "  matches: %d  duration: %s\n", len(r.Matches), r.Duration.Round(time.Millisecond))
	if r.Error != "" {
		fmt.Fprintf(out, "  error: %s\n", r.Error)
		return
	}
	if len(r.Matches) == 0 {
		fmt.Fprintln(out, "  no findings")
		return
	}
	limit := len(r.Matches)
	if maxMatches > 0 && limit > maxMatches {
		limit = maxMatches
	}
	for i := 0; i < limit; i++ {
		m := r.Matches[i]
		fmt.Fprintf(out, "  - %s conf=%.2f offset=%d len=%d\n", m.RuleID, m.Confidence, m.Offset, m.Length)
	}
	if len(r.Matches) > limit {
		fmt.Fprintf(out, "  ... and %d more matches\n", len(r.Matches)-limit)
	}
}

func initConfigAndLogger(opts *cliOptions) error {
	viper.SetConfigType("yaml")
	if opts.configPath != "" {
		viper.SetConfigFile(opts.configPath)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(filepath.Join(home, ".dlp"))
			viper.SetConfigName("config")
		}
		viper.AddConfigPath(".")
	}
	_ = viper.ReadInConfig()

	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(h))
	return nil
}

func outputWriter(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

func collectFiles(root string, recursive bool) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}

	w := walker.New(walker.DefaultConfig())
	files := make([]string, 0, 1024)
	for path := range w.Walk(context.Background(), root, recursive) {
		files = append(files, path)
	}
	return files, nil
}

func streamInputPaths(root string, recursive bool) (<-chan string, int, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, 0, err
	}
	if !info.IsDir() {
		paths := make(chan string, 1)
		paths <- root
		close(paths)
		return paths, 1, nil
	}

	w := walker.New(walker.DefaultConfig())
	return w.Walk(context.Background(), root, recursive), -1, nil
}

func parseLevel(s string) (scanner.Level, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "PUBLIC":
		return scanner.LevelPublic, nil
	case "INTERNAL":
		return scanner.LevelInternal, nil
	case "CONFIDENTIAL":
		return scanner.LevelConfidential, nil
	case "RESTRICTED", "SECRET":
		return scanner.LevelSecret, nil
	default:
		return scanner.LevelInternal, fmt.Errorf("invalid level-filter: %s", s)
	}
}

func parseByteSize(input string) (int64, error) {
	s := strings.TrimSpace(strings.ToUpper(input))
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	orderedUnits := []struct {
		suffix string
		mul    int64
	}{
		{suffix: "GB", mul: 1024 * 1024 * 1024},
		{suffix: "MB", mul: 1024 * 1024},
		{suffix: "KB", mul: 1024},
		{suffix: "B", mul: 1},
	}
	for _, unit := range orderedUnits {
		mul := unit.mul
		suffix := unit.suffix
		if !strings.HasSuffix(s, suffix) {
			continue
		}
		num := strings.TrimSpace(strings.TrimSuffix(s, suffix))
		v, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return 0, err
		}
		return int64(v * float64(mul)), nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size must end with B|KB|MB|GB or be raw bytes")
	}
	return v, nil
}

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

func pickString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func pickInt(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

func pickFloat(values ...float64) float64 {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}
