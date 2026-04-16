package walker

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
)

// Walker streams regular file paths from the filesystem.
// It avoids storing the full file list in memory.
type Walker struct {
	cfg    Config
	filter filter
}

func New(cfg Config) *Walker {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultConfig().BufferSize
	}
	if len(cfg.SkipDirs) == 0 {
		cfg.SkipDirs = append([]string(nil), defaultSkipDirs...)
	}
	return &Walker{cfg: cfg, filter: newFilter(cfg)}
}

// Walk starts directory traversal and returns a channel of discovered file paths.
// Unreadable entries are skipped so traversal can continue on large heterogeneous trees.
func (w *Walker) Walk(ctx context.Context, root string, recursive bool) <-chan string {
	out := make(chan string, w.cfg.BufferSize)

	go func() {
		defer close(out)

		st, err := os.Stat(root)
		if err != nil {
			return
		}
		if !st.IsDir() {
			if !w.filter.shouldEmitByExt(root) || !w.filter.withinSizeLimit(st) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case out <- root:
				return
			}
		}

		if recursive {
			w.walkRecursive(ctx, root, out)
			return
		}
		w.walkFlat(ctx, root, out)
	}()

	return out
}

func (w *Walker) walkFlat(ctx context.Context, dir string, out chan<- string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !w.emitEntry(ctx, dir, entry, out) {
			return
		}
	}
}

func (w *Walker) walkRecursive(ctx context.Context, root string, out chan<- string) {
	stack := []string{root}
	for len(stack) > 0 {
		select {
		case <-ctx.Done():
			return
		default:
		}

		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())

			if entry.IsDir() {
				if w.filter.shouldSkipDir(entry.Name()) {
					continue
				}
				if w.filter.shouldSkipSymlink(entry) {
					continue
				}
				stack = append(stack, path)
				continue
			}

			if !w.emitEntry(ctx, dir, entry, out) {
				return
			}
		}
	}
}

func (w *Walker) emitEntry(ctx context.Context, dir string, entry fs.DirEntry, out chan<- string) bool {
	if w.filter.shouldSkipSymlink(entry) {
		return true
	}

	path := filepath.Join(dir, entry.Name())
	if !w.filter.shouldEmitByExt(path) {
		return true
	}

	info, err := entry.Info()
	if err != nil {
		return true
	}
	if !info.Mode().IsRegular() {
		return true
	}
	if !w.filter.withinSizeLimit(info) {
		return true
	}

	select {
	case <-ctx.Done():
		return false
	case out <- path:
		return true
	}
}
