// engine.go — convenience compile helpers for one-time engine initialization.
package engine

import "fmt"

// CompileFromDir loads rule files and returns a fully initialized Engine.
// The returned Engine is read-only and safe to share across worker goroutines.
func CompileFromDir(rulesDir string, cfg EngineConfig) (*Engine, error) {
	rs, err := LoadRuleSet(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("load rule set: %w", err)
	}
	return New(rs, cfg), nil
}
