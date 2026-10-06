package csidriver

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// mountInfoPath is this process's mount table. A variable so a test can point at a
// fixture; the format is stable kernel ABI, see proc(5).
var mountInfoPath = "/proc/self/mountinfo"

// mountInfoMountPointField is the mount point's index in a mountinfo line, after the
// mount ID, parent ID, device and root.
const mountInfoMountPointField = 4

type systemMounter struct{}

// NewMounter returns the Mounter that talks to the kernel.
func NewMounter() Mounter {
	return systemMounter{}
}

// BindMountRW makes source visible at target, read-write.
//
// Read-write on purpose, and the read-only-ness the pod needs is not attempted here.
// MS_RDONLY is ignored on a bind, so it would take a second MS_REMOUNT syscall, and a
// remount changes only the per-mount flags in this namespace: propagation carries mount
// and unmount events, not attribute changes. The copy the kubelet sees was propagated by
// the bind below, before any remount, so it would stay read-write and so would the mount
// containerd clones from it. The pod's view is made read-only by the kubelet instead,
// which nodeServer.publish requires; upstream spiffe-csi does the same.
//
// Leaving it writable here is also what lets the host set file attributes on the mount,
// SELinux relabelling included.
func (systemMounter) BindMountRW(source, target string) error {
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mounting %s at %s: %w", source, target, err)
	}
	return nil
}

// Unmount removes the mount at target.
//
// MNT_DETACH so a workload still holding the socket open cannot block a pod's teardown
// with EBUSY. EINVAL (not a mount point) and ENOENT (target already gone) are the
// ordinary repeated-unpublish cases and report success.
func (systemMounter) Unmount(target string) error {
	err := unix.Unmount(target, unix.MNT_DETACH)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOENT):
		return nil
	default:
		return fmt.Errorf("unmounting %s: %w", target, err)
	}
}

// IsMountPoint reports whether anything is mounted at path.
//
// It reads the mount table rather than comparing st_dev with the parent's, which is the
// usual trick and is wrong here: a bind mount within one filesystem leaves the device
// unchanged, so the comparison would call a mounted target unmounted and a publish would
// stack a second mount.
func (systemMounter) IsMountPoint(path string) (bool, error) {
	cleaned := filepath.Clean(path)

	file, err := os.Open(mountInfoPath)
	if err != nil {
		return false, fmt.Errorf("reading the mount table at %s: %w", mountInfoPath, err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) <= mountInfoMountPointField {
			continue
		}
		mountPoint, err := unescapeMountInfoField(fields[mountInfoMountPointField])
		if err != nil {
			// Not treated as "no mount here": that would let a publish stack a mount on a
			// target that already has one.
			return false, fmt.Errorf("parsing the mount point in %s: %w", mountInfoPath, err)
		}
		if mountPoint == cleaned {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("reading the mount table at %s: %w", mountInfoPath, err)
	}

	// A path that does not exist has no mount on it, and that is not an error: an
	// unpublish for a target the kubelet already removed takes this path.
	if _, err := os.Lstat(cleaned); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("stat %s: %w", cleaned, err)
	}

	return false, nil
}

// unescapeMountInfoField decodes the octal escapes the kernel writes for a space, tab,
// newline or backslash in a mount point (\040, \011, \012, \134), since the fields are
// space separated. A kubelet target path contains none of them; this keeps the parse
// honest rather than handling an expected case.
func unescapeMountInfoField(field string) (string, error) {
	if !strings.Contains(field, `\`) {
		return field, nil
	}

	var out strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] != '\\' {
			out.WriteByte(field[i])
			continue
		}
		if i+3 >= len(field) {
			return "", fmt.Errorf("truncated escape in %q", field)
		}
		value, err := strconv.ParseUint(field[i+1:i+4], 8, 8)
		if err != nil {
			return "", fmt.Errorf("invalid escape %q in %q", field[i:i+4], field)
		}
		out.WriteByte(byte(value))
		i += 3
	}
	return out.String(), nil
}
