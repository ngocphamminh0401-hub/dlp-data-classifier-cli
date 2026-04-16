//go:build windows

package ipc

import (
	"os"
	"os/signal"
)

func registerShutdownSignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt)
}

func stopSignalNotify(ch chan<- os.Signal) {
	signal.Stop(ch)
}
