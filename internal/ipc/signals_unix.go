//go:build !windows

package ipc

import (
	"os"
	"os/signal"
	"syscall"
)

func registerShutdownSignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
}

func stopSignalNotify(ch chan<- os.Signal) {
	signal.Stop(ch)
}
