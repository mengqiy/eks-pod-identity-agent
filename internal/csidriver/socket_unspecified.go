//go:build !linux

package csidriver

import (
	"errors"
	"net"
	"os"
)

// The agent only ships for Linux. This file keeps the package compilable elsewhere, the
// way pkg/initalizer/iproute does, so an editor and `go build ./...` work on any machine
// and reaching one of these is a named error rather than a link failure.
var errPodSocketsUnsupported = errors.New("csidriver: per-pod sockets are only supported on linux")

func listenIn(_ *os.File, _ string, _ os.FileMode) (net.Listener, error) {
	return nil, errPodSocketsUnsupported
}

func unlinkIn(_ *os.File, _ string) error {
	return errPodSocketsUnsupported
}

func removeStaleSocket(_ *os.File, _ string) error {
	return errPodSocketsUnsupported
}
