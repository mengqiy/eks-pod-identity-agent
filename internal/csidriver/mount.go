package csidriver

// Mounter is the node service's whole dependency on the kernel's mount table.
//
// It is a seam because a bind mount needs CAP_SYS_ADMIN, which a test binary does not
// have. Everything else worth testing — validation, containment, idempotence, failure
// handling — is reachable through a fake.
//
// IsMountPoint is separate from BindMountReadOnly because it is what makes a repeated
// publish idempotent instead of stacking mounts on one target.
type Mounter interface {
	// BindMountReadOnly makes source visible at target, read-only. Both must exist and
	// target must be a directory.
	BindMountReadOnly(source, target string) error

	// Unmount removes the mount at target. A target with no mount is not an error: the
	// kubelet calls unpublish for volumes it has already torn down.
	Unmount(target string) error

	// IsMountPoint reports whether anything is mounted at path. A path that does not
	// exist is not a mount point and not an error.
	IsMountPoint(path string) (bool, error)
}
