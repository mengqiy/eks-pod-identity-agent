package csidriver

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// writeMountInfo points IsMountPoint at a fixture. The format is stable kernel ABI, and
// the alternative needs CAP_SYS_ADMIN to create the mount it then looks for.
func writeMountInfo(t *testing.T, contents string) {
	t.Helper()
	g := NewWithT(t)

	path := filepath.Join(t.TempDir(), "mountinfo")
	g.Expect(os.WriteFile(path, []byte(contents), 0o600)).To(Succeed())

	previous := mountInfoPath
	t.Cleanup(func() { mountInfoPath = previous })
	mountInfoPath = path
}

// Why the mount table is read at all: the usual st_dev comparison answers "not mounted"
// for a bind mount within one filesystem, and a publish would stack a second mount.
func TestIsMountPoint_BindMountWithinOneFilesystem_IsFound(t *testing.T) {
	g := NewWithT(t)

	target := "/var/lib/kubelet/pods/pod-uid/volumes/kubernetes.io~csi/eks-workload-identity-socket/mount"
	writeMountInfo(t, `22 21 0:20 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
2153 1876 259:1 /var/run/secrets/pods.eks.amazonaws.com/workloadidentity `+target+` ro,relatime shared:1 - ext4 /dev/nvme0n1p1 ro
`)

	mounted, err := systemMounter{}.IsMountPoint(target)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(mounted).To(BeTrue())
}

func TestIsMountPoint_UnmountedPath_IsNotAMountPointAndIsNotAnError(t *testing.T) {
	g := NewWithT(t)

	writeMountInfo(t, "22 21 0:20 / /proc rw,relatime shared:5 - proc proc rw\n")

	// A nonexistent path too: the kubelet can unpublish after removing the target, and a
	// failure there would leave the pod terminating forever.
	mounted, err := systemMounter{}.IsMountPoint("/var/lib/kubelet/pods/gone/volumes/kubernetes.io~csi/v/mount")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(mounted).To(BeFalse())
}

// Equality, not a prefix match: treating a published target's parent as mounted would make
// a publish to it a silent no-op.
func TestIsMountPoint_PrefixOfAMountPoint_IsNotAMountPoint(t *testing.T) {
	g := NewWithT(t)

	writeMountInfo(t, "2153 1876 259:1 / /var/lib/kubelet/pods/pod-uid/volumes/kubernetes.io~csi/v/mount ro - ext4 /dev/root ro\n")

	mounted, err := systemMounter{}.IsMountPoint("/var/lib/kubelet/pods/pod-uid/volumes/kubernetes.io~csi/v")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(mounted).To(BeFalse())
}

// An unknown answer is not "not mounted": guessing would stack a mount on a target that
// already has one.
func TestIsMountPoint_UnreadableMountTable_IsAnError(t *testing.T) {
	g := NewWithT(t)

	previous := mountInfoPath
	t.Cleanup(func() { mountInfoPath = previous })
	mountInfoPath = filepath.Join(t.TempDir(), "does-not-exist")

	_, err := systemMounter{}.IsMountPoint("/var/lib/kubelet/pods/pod-uid/volumes/kubernetes.io~csi/v/mount")
	g.Expect(err).To(HaveOccurred())
}

func TestIsMountPoint_EscapedMountPoint_IsDecoded(t *testing.T) {
	g := NewWithT(t)

	// The kernel escapes a space in a mount point as \040, because the fields are
	// separated by spaces and a raw one would split the line.
	writeMountInfo(t, `2153 1876 259:1 / /var/lib/kubelet/pods/pod\040uid/mount ro - ext4 /dev/root ro
`)

	mounted, err := systemMounter{}.IsMountPoint("/var/lib/kubelet/pods/pod uid/mount")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(mounted).To(BeTrue())
}

func TestUnescapeMountInfoField(t *testing.T) {
	testCases := []struct {
		name    string
		field   string
		want    string
		wantErr bool
	}{
		{name: "no escapes", field: "/var/lib/kubelet/pods/uid/mount", want: "/var/lib/kubelet/pods/uid/mount"},
		{name: "space", field: `/mnt/with\040space`, want: "/mnt/with space"},
		{name: "tab", field: `/mnt/with\011tab`, want: "/mnt/with\ttab"},
		{name: "newline", field: `/mnt/with\012newline`, want: "/mnt/with\nnewline"},
		{name: "backslash", field: `/mnt/with\134backslash`, want: `/mnt/with\backslash`},
		{name: "several", field: `/mnt/a\040b\040c`, want: "/mnt/a b c"},
		{name: "truncated escape", field: `/mnt/a\04`, wantErr: true},
		{name: "not octal", field: `/mnt/a\09z`, wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := unescapeMountInfoField(testCase.field)
			if testCase.wantErr {
				g.Expect(err).To(HaveOccurred())
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).To(Equal(testCase.want))
		})
	}
}

// The only test here that touches the kernel, skipped unless the binary can mount. CI and
// developer machines have no CAP_SYS_ADMIN, so these two syscalls are only covered on a
// node; everything around them goes through the fake mounter in node_test.go.
func TestBindMountReadOnly_OnARealMountNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("a bind mount needs CAP_SYS_ADMIN; the rest of the node service is covered through the Mounter seam")
	}

	g := NewWithT(t)

	root := t.TempDir()
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	g.Expect(os.MkdirAll(source, 0o755)).To(Succeed())
	g.Expect(os.MkdirAll(target, 0o755)).To(Succeed())
	g.Expect(os.WriteFile(filepath.Join(source, "agent.sock"), nil, 0o666)).To(Succeed())

	mounter := systemMounter{}
	g.Expect(mounter.BindMountReadOnly(source, target)).To(Succeed())
	t.Cleanup(func() { _ = mounter.Unmount(target) })

	mounted, err := mounter.IsMountPoint(target)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(mounted).To(BeTrue())

	// The file is visible through the second path, which is what the pod sees.
	g.Expect(filepath.Join(target, "agent.sock")).To(BeAnExistingFile())

	// And the mount is read-only, which is the property the second syscall exists for:
	// a writable mount would let a workload unlink the agent's socket and bind its own.
	err = os.WriteFile(filepath.Join(target, "written-by-test"), nil, 0o600)
	g.Expect(err).To(HaveOccurred(), "the published mount must be read-only")

	g.Expect(mounter.Unmount(target)).To(Succeed())
	mounted, err = mounter.IsMountPoint(target)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(mounted).To(BeFalse())
}
