package csidriver

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// listenIn binds a Unix socket named name inside dir and leaves it with mode. The bind goes
// through /proc/self/fd/<dir> because a kubelet target path is longer than the 107 bytes a
// socket address holds; only the address is limited, and the pod connects through its own
// short path to the same inode.
func listenIn(dir *os.File, name string, mode os.FileMode) (net.Listener, error) {
	address := fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), name)

	lis, err := net.Listen("unix", address)
	if err != nil {
		return nil, fmt.Errorf("binding %s: %w", name, err)
	}
	// Unlinked through dir instead, so closing the listener never depends on the address
	// still resolving, and closeAll can leave the file in place.
	lis.(*net.UnixListener).SetUnlinkOnClose(false)

	// The bind applies the umask; see grpcserver.ListenUnix.
	if err := unix.Fchmodat(int(dir.Fd()), name, uint32(mode.Perm()), 0); err != nil {
		_ = lis.Close()
		_ = unlinkIn(dir, name)
		return nil, fmt.Errorf("setting mode %04o on %s: %w", mode.Perm(), name, err)
	}

	return lis, nil
}

// unlinkIn removes name from dir. A name already gone is not an error.
func unlinkIn(dir *os.File, name string) error {
	if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("removing %s: %w", name, err)
	}
	return nil
}

// removeStaleSocket removes name from dir if it is a socket, and refuses anything else
// there. Nothing is not an error.
func removeStaleSocket(dir *os.File, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking %s: %w", name, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fmt.Errorf("refusing to replace %s: it is not a socket (mode %o)", name, stat.Mode)
	}
	return unlinkIn(dir, name)
}
