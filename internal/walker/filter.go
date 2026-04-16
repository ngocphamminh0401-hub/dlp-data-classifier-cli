package walker

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var defaultSkipDirs = []string{
	".git",
	"node_modules",
	"__pycache__",
	".venv",
	".svn",
	".hg",
	".idea",
	".vscode",
}

// Config controls traversal behavior.
type Config struct {
	// BufferSize controls the output channel capacity.
	BufferSize int

	// MaxFileSizeB pre-filters oversized files when > 0.
	MaxFileSizeB int64

	// FollowSymlinks enables emitting symlink targets when they point to regular files.
	FollowSymlinks bool

	// SkipDirs are directory names skipped during traversal.
	SkipDirs []string

	// AllowedExtensions is optional whitelist (lowercase, with dot). Empty means allow all.
	AllowedExtensions []string
}

// DefaultConfig returns a safe, low-overhead traversal configuration.
func DefaultConfig() Config {
	return Config{
		BufferSize:        1024,
		FollowSymlinks:    false,
		SkipDirs:          append([]string(nil), defaultSkipDirs...),
		AllowedExtensions: nil,
	}
}

type filter struct {
	skipDirs     map[string]struct{}
	allowedExts  map[string]struct{}
	maxFileSizeB int64
	followLinks  bool
}

func newFilter(cfg Config) filter {
	f := filter{
		skipDirs:     make(map[string]struct{}, len(cfg.SkipDirs)),
		allowedExts:  make(map[string]struct{}, len(cfg.AllowedExtensions)),
		maxFileSizeB: cfg.MaxFileSizeB,
		followLinks:  cfg.FollowSymlinks,
	}

	for _, d := range cfg.SkipDirs {
		name := strings.TrimSpace(strings.ToLower(d))
		if name == "" {
			continue
		}
		f.skipDirs[name] = struct{}{}
	}

	for _, ext := range cfg.AllowedExtensions {
		n := normalizeExt(ext)
		if n == "" {
			continue
		}
		f.allowedExts[n] = struct{}{}
	}

	return f
}

func (f filter) shouldSkipDir(name string) bool {
	_, ok := f.skipDirs[strings.ToLower(name)]
	return ok
}

func (f filter) shouldEmitByExt(path string) bool {
	if len(f.allowedExts) == 0 {
		return true
	}
	_, ok := f.allowedExts[normalizeExt(filepath.Ext(path))]
	return ok
}

func (f filter) shouldSkipSymlink(de fs.DirEntry) bool {
	if f.followLinks {
		return false
	}
	return de.Type()&os.ModeSymlink != 0
}

func (f filter) withinSizeLimit(info fs.FileInfo) bool {
	if f.maxFileSizeB <= 0 {
		return true
	}
	return info.Size() <= f.maxFileSizeB
}

func normalizeExt(ext string) string {
	e := strings.ToLower(strings.TrimSpace(ext))
	if e == "" {
		return ""
	}
	if !strings.HasPrefix(e, ".") {
		e = "." + e
	}
	return e
}
