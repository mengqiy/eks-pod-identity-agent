package csidriver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// fakeMounter stands in for the kernel, since a bind mount needs CAP_SYS_ADMIN. Only the
// two mount syscalls are out of reach this way.
type fakeMounter struct {
	// mounted maps target to source, so a test can assert what was published.
	mounted map[string]string

	bindErr         error
	unmountErr      error
	isMountPointErr error

	bindCalls    int
	unmountCalls int
}

func newFakeMounter() *fakeMounter {
	return &fakeMounter{mounted: map[string]string{}}
}

func (m *fakeMounter) BindMountReadOnly(source, target string) error {
	m.bindCalls++
	if m.bindErr != nil {
		return m.bindErr
	}
	m.mounted[target] = source
	return nil
}

func (m *fakeMounter) Unmount(target string) error {
	m.unmountCalls++
	if m.unmountErr != nil {
		return m.unmountErr
	}
	delete(m.mounted, target)
	return nil
}

func (m *fakeMounter) IsMountPoint(path string) (bool, error) {
	if m.isMountPointErr != nil {
		return false, m.isMountPointErr
	}
	_, ok := m.mounted[path]
	return ok, nil
}

// ephemeralContext is what the kubelet sends for an inline ephemeral volume, with the pod
// fields podInfoOnMount asks for.
func ephemeralContext() map[string]string {
	return map[string]string{
		ephemeralVolumeContextKey:    "true",
		podNameVolumeContextKey:      "workload-0",
		podNamespaceVolumeContextKey: "default",
	}
}

// mountCapability is the capability the kubelet sends for a filesystem volume.
func mountCapability() *csi.VolumeCapability {
	return &csi.VolumeCapability{
		AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
	}
}

// newTestNodeServer gives the node service a real temporary pods directory, so the
// containment check and directory handling run against a filesystem.
func newTestNodeServer(t *testing.T, mounter Mounter) (*nodeServer, string) {
	t.Helper()
	podsDir := t.TempDir()
	return newNodeServer(mounter, "ip-10-0-0-1.ec2.internal", "/var/run/secrets/workloadidentity", podsDir), podsDir
}

// targetUnder builds a kubelet-shaped target path without creating it; the node service
// has to cope either way.
func targetUnder(podsDir string) string {
	return filepath.Join(podsDir, "6f1c9f4e-0000-0000-0000-000000000001",
		"volumes", "kubernetes.io~csi", "eks-workload-identity-socket", "mount")
}

func TestNodePublishVolume_ValidRequest_BindMountsTheSocketDirectoryReadOnly(t *testing.T) {
	g := NewWithT(t)

	mounter := newFakeMounter()
	nodeSrv, podsDir := newTestNodeServer(t, mounter)
	target := targetUnder(podsDir)

	_, err := nodeSrv.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
		VolumeId:         "csi-volume-1",
		TargetPath:       target,
		VolumeCapability: mountCapability(),
		VolumeContext:    ephemeralContext(),
		Readonly:         true,
	})
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(mounter.mounted).To(HaveKeyWithValue(target, nodeSrv.source),
		"the node service must publish the directory it was constructed with, never a path from the request")
	g.Expect(target).To(BeADirectory(), "the target has to exist for the kubelet to bind it into the container")
}

// Readonly: false is not honoured: a workload able to write into the socket directory
// could unlink the agent's socket and bind its own.
func TestNodePublishVolume_WritableRequest_IsStillMountedReadOnly(t *testing.T) {
	g := NewWithT(t)

	mounter := newFakeMounter()
	nodeSrv, podsDir := newTestNodeServer(t, mounter)
	target := targetUnder(podsDir)

	_, err := nodeSrv.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
		VolumeId:         "csi-volume-1",
		TargetPath:       target,
		VolumeCapability: mountCapability(),
		VolumeContext:    ephemeralContext(),
		Readonly:         false,
	})
	g.Expect(err).ToNot(HaveOccurred())

	// The fake records only the read-only call, so reaching it is the assertion.
	g.Expect(mounter.bindCalls).To(Equal(1))
	g.Expect(mounter.mounted).To(HaveKey(target))
}

// The kubelet retries a publish whose reply it never got. A second mount would stack, and
// the unpublish unwinds one.
func TestNodePublishVolume_AlreadyMounted_DoesNotMountAgain(t *testing.T) {
	g := NewWithT(t)

	mounter := newFakeMounter()
	nodeSrv, podsDir := newTestNodeServer(t, mounter)
	target := targetUnder(podsDir)

	request := &csi.NodePublishVolumeRequest{
		VolumeId:         "csi-volume-1",
		TargetPath:       target,
		VolumeCapability: mountCapability(),
		VolumeContext:    ephemeralContext(),
		Readonly:         true,
	}

	_, err := nodeSrv.NodePublishVolume(context.Background(), request)
	g.Expect(err).ToNot(HaveOccurred())
	_, err = nodeSrv.NodePublishVolume(context.Background(), request)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(mounter.bindCalls).To(Equal(1), "a repeated publish must be a no-op, not a second mount")
}

func TestNodePublishVolume_RejectedRequests_AreInvalidArgument(t *testing.T) {
	podsDir := t.TempDir()
	target := targetUnder(podsDir)

	testCases := []struct {
		name    string
		request *csi.NodePublishVolumeRequest
		// why names the rule, so a failure reads as the rule that broke.
		why string
	}{
		{
			name: "no volume ID",
			request: &csi.NodePublishVolumeRequest{
				TargetPath: target, VolumeCapability: mountCapability(), VolumeContext: ephemeralContext(),
			},
			why: "the volume ID is what the kubelet correlates its retries by",
		},
		{
			name: "no target path",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", VolumeCapability: mountCapability(), VolumeContext: ephemeralContext(),
			},
			why: "there is nowhere to mount",
		},
		{
			name: "no volume capability",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: target, VolumeContext: ephemeralContext(),
			},
			why: "the CSI specification requires one",
		},
		{
			name: "block volume",
			request: &csi.NodePublishVolumeRequest{
				VolumeId:   "csi-volume-1",
				TargetPath: target,
				VolumeCapability: &csi.VolumeCapability{
					AccessType: &csi.VolumeCapability_Block{Block: &csi.VolumeCapability_BlockVolume{}},
				},
				VolumeContext: ephemeralContext(),
			},
			why: "this driver publishes a directory and has no device to hand out",
		},
		{
			name: "not an inline ephemeral volume",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: target, VolumeCapability: mountCapability(),
				VolumeContext: map[string]string{},
			},
			why: "the CSIDriver object declares Ephemeral only, so anything else is a PersistentVolume naming this driver",
		},
		{
			name: "target outside the kubelet pods directory",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: "/etc", VolumeCapability: mountCapability(),
				VolumeContext: ephemeralContext(),
			},
			why: "the process serving this can mount, so an arbitrary target is a path it would shadow",
		},
		{
			name: "target with a traversal segment",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: podsDir + "/../../etc", VolumeCapability: mountCapability(),
				VolumeContext: ephemeralContext(),
			},
			why: "the kubelet sends clean paths, so a traversal did not come from it",
		},
		{
			name: "relative target",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: "relative/path", VolumeCapability: mountCapability(),
				VolumeContext: ephemeralContext(),
			},
			why: "a relative path is resolved against the agent's working directory, which is not the kubelet's",
		},
		{
			name: "the pods directory itself",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: podsDir, VolumeCapability: mountCapability(),
				VolumeContext: ephemeralContext(),
			},
			why: "mounting over the pods directory would shadow every pod's volumes on the node",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := NewWithT(t)

			mounter := newFakeMounter()
			nodeSrv := newNodeServer(mounter, "node-1", "/var/run/secrets/workloadidentity", podsDir)

			_, err := nodeSrv.NodePublishVolume(context.Background(), testCase.request)
			g.Expect(err).To(HaveOccurred(), testCase.why)
			g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument), testCase.why)
			g.Expect(mounter.bindCalls).To(BeZero(), "a refused request must not reach the mount table")
		})
	}
}

func TestNodePublishVolume_MounterFailures_AreInternalAndDoNotClaimSuccess(t *testing.T) {
	testCases := []struct {
		name    string
		prepare func(*fakeMounter)
	}{
		{
			name:    "the mount table cannot be read",
			prepare: func(m *fakeMounter) { m.isMountPointErr = errors.New("mountinfo is unreadable") },
		},
		{
			name:    "the bind mount is refused",
			prepare: func(m *fakeMounter) { m.bindErr = errors.New("operation not permitted") },
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := NewWithT(t)

			mounter := newFakeMounter()
			testCase.prepare(mounter)
			nodeSrv, podsDir := newTestNodeServer(t, mounter)

			_, err := nodeSrv.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
				VolumeId:         "csi-volume-1",
				TargetPath:       targetUnder(podsDir),
				VolumeCapability: mountCapability(),
				VolumeContext:    ephemeralContext(),
				Readonly:         true,
			})
			g.Expect(err).To(HaveOccurred())
			g.Expect(status.Code(err)).To(Equal(codes.Internal))
		})
	}
}

func TestNodeUnpublishVolume_MountedVolume_UnmountsAndRemovesTheTarget(t *testing.T) {
	g := NewWithT(t)

	mounter := newFakeMounter()
	nodeSrv, podsDir := newTestNodeServer(t, mounter)
	target := targetUnder(podsDir)

	_, err := nodeSrv.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
		VolumeId:         "csi-volume-1",
		TargetPath:       target,
		VolumeCapability: mountCapability(),
		VolumeContext:    ephemeralContext(),
		Readonly:         true,
	})
	g.Expect(err).ToNot(HaveOccurred())

	_, err = nodeSrv.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
		VolumeId:   "csi-volume-1",
		TargetPath: target,
	})
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(mounter.mounted).ToNot(HaveKey(target))
	g.Expect(target).ToNot(BeADirectory(), "the kubelet expects the plugin to remove the target it was given")
}

// The kubelet repeats unpublish until it succeeds, so an error for a volume already gone
// would leave the pod stuck terminating.
func TestNodeUnpublishVolume_NothingMounted_Succeeds(t *testing.T) {
	g := NewWithT(t)

	mounter := newFakeMounter()
	nodeSrv, podsDir := newTestNodeServer(t, mounter)

	_, err := nodeSrv.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
		VolumeId:   "csi-volume-1",
		TargetPath: targetUnder(podsDir),
	})
	g.Expect(err).ToNot(HaveOccurred())
}

func TestNodeUnpublishVolume_RejectedRequests_AreInvalidArgument(t *testing.T) {
	podsDir := t.TempDir()

	testCases := []struct {
		name    string
		request *csi.NodeUnpublishVolumeRequest
	}{
		{name: "no volume ID", request: &csi.NodeUnpublishVolumeRequest{TargetPath: targetUnder(podsDir)}},
		{name: "no target path", request: &csi.NodeUnpublishVolumeRequest{VolumeId: "csi-volume-1"}},
		{
			name:    "target outside the kubelet pods directory",
			request: &csi.NodeUnpublishVolumeRequest{VolumeId: "csi-volume-1", TargetPath: "/etc"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := NewWithT(t)

			mounter := newFakeMounter()
			nodeSrv := newNodeServer(mounter, "node-1", "/var/run/secrets/workloadidentity", podsDir)

			_, err := nodeSrv.NodeUnpublishVolume(context.Background(), testCase.request)
			g.Expect(err).To(HaveOccurred())
			g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
			g.Expect(mounter.unmountCalls).To(BeZero(),
				"an unpublish is an unmount and a delete, so a refused one must touch neither")
		})
	}
}

// Something other than this mount at the target: removing it would delete data the node
// service did not put there.
func TestNodeUnpublishVolume_NonEmptyTarget_Fails(t *testing.T) {
	g := NewWithT(t)

	mounter := newFakeMounter()
	nodeSrv, podsDir := newTestNodeServer(t, mounter)
	target := targetUnder(podsDir)

	g.Expect(os.MkdirAll(target, targetPathMode)).To(Succeed())
	g.Expect(os.WriteFile(filepath.Join(target, "unexpected"), []byte("data"), 0o600)).To(Succeed())

	_, err := nodeSrv.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
		VolumeId:   "csi-volume-1",
		TargetPath: target,
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(status.Code(err)).To(Equal(codes.Internal))
}

func TestNodeGetInfo_ReportsTheNodeName(t *testing.T) {
	g := NewWithT(t)

	nodeSrv := newNodeServer(newFakeMounter(), "ip-10-0-0-1.ec2.internal", "/src", "/var/lib/kubelet/pods")

	resp, err := nodeSrv.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.GetNodeId()).To(Equal("ip-10-0-0-1.ec2.internal"))
}

// STAGE_UNSTAGE_VOLUME would make the kubelet call NodeStageVolume, which is not
// implemented, and every mount would fail.
func TestNodeGetCapabilities_ReportsNone(t *testing.T) {
	g := NewWithT(t)

	nodeSrv := newNodeServer(newFakeMounter(), "node-1", "/src", "/var/lib/kubelet/pods")

	resp, err := nodeSrv.NodeGetCapabilities(context.Background(), &csi.NodeGetCapabilitiesRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.GetCapabilities()).To(BeEmpty())
}

// The other half of that: the method answers Unimplemented if the kubelet ever asks.
func TestNodeStageVolume_IsUnimplemented(t *testing.T) {
	g := NewWithT(t)

	nodeSrv := newNodeServer(newFakeMounter(), "node-1", "/src", "/var/lib/kubelet/pods")

	_, err := nodeSrv.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{})
	g.Expect(status.Code(err)).To(Equal(codes.Unimplemented))
}
