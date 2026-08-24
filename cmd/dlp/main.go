package main

import (
	"fmt"
	"os"
	"runtime/debug"
)

func init() {
	// Aggressive GC: trigger at 20% heap growth instead of default 100%.
	// Keeps RSS low at the cost of slightly more frequent GC pauses.
	debug.SetGCPercent(20)
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
