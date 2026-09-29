//go:build !linux

package csidriver

import (
	"errors"
	"fmt"
)

// The agent only ships for Linux. This file keeps the package compilable elsewhere, the
// way pkg/initalizer/iproute does, so an editor and `go build ./...` work on any machine
// and reaching one of these is a named error rather than a link failure.
var errMountUnsupported = errors.New("csidriver: bind mounts are only supported on linux")

type unsupportedMounter struct{}

// NewMounter returns a Mounter whose every operation fails.
func NewMounter() Mounter {
	return unsupportedMounter{}
}

func (unsupportedMounter) BindMountReadOnly(source, target string) error {
	return fmt.Errorf("bind mounting %s at %s: %w", source, target, errMountUnsupported)
}

func (unsupportedMounter) Unmount(target string) error {
	return fmt.Errorf("unmounting %s: %w", target, errMountUnsupported)
}

func (unsupportedMounter) IsMountPoint(path string) (bool, error) {
	return false, fmt.Errorf("checking whether %s is a mount point: %w", path, errMountUnsupported)
}
