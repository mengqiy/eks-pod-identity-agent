//go:build linux

package csidriver

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
)

// ephemeralContext is what the kubelet sends for an inline ephemeral volume, with the pod
// fields podInfoOnMount asks for.
func ephemeralContext() map[string]string {
	return map[string]string{
		ephemeralVolumeContextKey:    "true",
		podNameVolumeContextKey:      "workload-0",
		podNamespaceVolumeContextKey: "default",
	}
}

// mountCapability is the capability the kubelet sends for an inline ephemeral volume: an
// empty mount, since the filesystem type comes from a csi.fsType the webhook does not set
// and mount flags from a PersistentVolume there is none of, and SINGLE_NODE_WRITER, which
// is the kubelet's default when it has no access modes to read.
func mountCapability() *csi.VolumeCapability {
	return &csi.VolumeCapability{
		AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
		AccessMode: &csi.VolumeCapability_AccessMode{
			Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
		},
	}
}

// newTestNodeServer gives the node service a real temporary pods directory and a fake
// workload identity server, so the containment check, the directory handling and the
// socket all run against a filesystem.
func newTestNodeServer(t *testing.T) (*nodeServer, *fakeServer, string) {
	t.Helper()
	server := &fakeServer{}
	sockets := newPodSockets(server.serve)
	t.Cleanup(sockets.closeAll)
	podsDir := t.TempDir()
	return newNodeServer(sockets, "ip-10-0-0-1.ec2.internal", podsDir), server, podsDir
}

// targetUnder builds a kubelet-shaped target path without creating it; the node service
// has to cope either way. Under t.TempDir it is longer than a socket address can hold,
// as a real one is, so every test here also covers the bind that works around that.
func targetUnder(podsDir string) string {
	return filepath.Join(podsDir, "6f1c9f4e-0000-0000-0000-000000000001",
		"volumes", "kubernetes.io~csi", "eks-workload-identity-socket", "mount")
}

func publishRequest(target string) *csi.NodePublishVolumeRequest {
	return &csi.NodePublishVolumeRequest{
		VolumeId:         "csi-volume-1",
		TargetPath:       target,
		VolumeCapability: mountCapability(),
		VolumeContext:    ephemeralContext(),
		Readonly:         true,
	}
}

func unpublishRequest(target string) *csi.NodeUnpublishVolumeRequest {
	return &csi.NodeUnpublishVolumeRequest{VolumeId: "csi-volume-1", TargetPath: target}
}

func TestNodePublishVolume_ValidRequest_ServesTheSocketInTheTarget(t *testing.T) {
	g := NewWithT(t)

	nodeSrv, server, podsDir := newTestNodeServer(t)
	target := targetUnder(podsDir)
	g.Expect(len(filepath.Join(target, podSocketName))).To(BeNumerically(">", 107),
		"a real target is longer than a socket address, and so is this one")

	_, err := nodeSrv.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())

	targetInfo, err := os.Stat(target)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(targetInfo.Mode().Perm()).To(Equal(targetPathMode),
		"the pod sees this directory as the mount root and may run as any UID")

	socketInfo, err := os.Lstat(filepath.Join(target, podSocketName))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(socketInfo.Mode().Type()).To(Equal(os.ModeSocket))
	g.Expect(socketInfo.Mode().Perm()).To(Equal(grpcserver.SocketMode))

	g.Expect(server.served()).To(Equal(1))
	g.Expect(dialGreeting(podView(t, target))).To(Equal(greeting),
		"the pod reaches the socket through its own path to the target directory")
}

// The pod may run as any UID, so the target's mode must not come from the umask.
func TestNodePublishVolume_RestrictiveUmask_StillLeavesTheTargetTraversable(t *testing.T) {
	g := NewWithT(t)

	previous := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previous) })

	nodeSrv, _, podsDir := newTestNodeServer(t)
	target := targetUnder(podsDir)

	_, err := nodeSrv.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())

	targetInfo, err := os.Stat(target)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(targetInfo.Mode().Perm()).To(Equal(targetPathMode))
	socketInfo, err := os.Lstat(filepath.Join(target, podSocketName))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(socketInfo.Mode().Perm()).To(Equal(grpcserver.SocketMode))
}

// Readonly is the pod's own csi.readOnly, and the kubelet acting on it is what keeps the
// workload from replacing its socket. A publish without it is refused rather than served.
func TestNodePublishVolume_WritableRequest_IsRefusedAndServesNothing(t *testing.T) {
	g := NewWithT(t)

	nodeSrv, server, podsDir := newTestNodeServer(t)
	target := targetUnder(podsDir)
	request := publishRequest(target)
	request.Readonly = false

	_, err := nodeSrv.NodePublishVolume(context.Background(), request)
	g.Expect(err).To(HaveOccurred())
	g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
	g.Expect(err.Error()).To(ContainSubstring("csi.readOnly"),
		"the message has to name the field, since fixing it means changing the webhook's injected volume")

	g.Expect(server.served()).To(BeZero())
	g.Expect(target).ToNot(BeADirectory())
}

// The kubelet retries a publish whose reply it never got.
func TestNodePublishVolume_Repeated_ServesOneSocket(t *testing.T) {
	g := NewWithT(t)

	nodeSrv, server, podsDir := newTestNodeServer(t)
	target := targetUnder(podsDir)

	_, err := nodeSrv.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())
	_, err = nodeSrv.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(server.served()).To(Equal(1), "a repeated publish must be a no-op, not a second listener")
	g.Expect(dialGreeting(podView(t, target))).To(Equal(greeting))
}

// An earlier run of the agent leaves its sockets in place on exit; the next publish of the
// same target replaces the dead one.
func TestNodePublishVolume_SocketLeftByAnEarlierRun_IsReplaced(t *testing.T) {
	g := NewWithT(t)

	nodeSrv, _, podsDir := newTestNodeServer(t)
	target := targetUnder(podsDir)
	leaveStaleSocket(t, target)

	_, err := nodeSrv.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(dialGreeting(podView(t, target))).To(Equal(greeting))
}

// Anything but a socket at the socket's path is not ours to remove.
func TestNodePublishVolume_NonSocketAtTheSocketPath_IsInternalAndLeftAlone(t *testing.T) {
	g := NewWithT(t)

	nodeSrv, server, podsDir := newTestNodeServer(t)
	target := targetUnder(podsDir)
	g.Expect(os.MkdirAll(target, targetPathMode)).To(Succeed())
	occupant := filepath.Join(target, podSocketName)
	g.Expect(os.WriteFile(occupant, []byte("data"), 0o600)).To(Succeed())

	_, err := nodeSrv.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).To(HaveOccurred())
	g.Expect(status.Code(err)).To(Equal(codes.Internal))

	g.Expect(os.ReadFile(occupant)).To(Equal([]byte("data")))
	g.Expect(server.served()).To(BeZero())
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
				Readonly: true,
			},
			why: "the volume ID is what the kubelet correlates its retries by",
		},
		{
			name: "no target path",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", VolumeCapability: mountCapability(), VolumeContext: ephemeralContext(),
				Readonly: true,
			},
			why: "there is nowhere to publish",
		},
		{
			name: "no volume capability",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: target, VolumeContext: ephemeralContext(),
				Readonly: true,
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
				Readonly:      true,
			},
			why: "this driver publishes a directory and has no device to hand out",
		},
		{
			name: "no access type",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: target,
				VolumeCapability: &csi.VolumeCapability{
					AccessMode: &csi.VolumeCapability_AccessMode{
						Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
					},
				},
				VolumeContext: ephemeralContext(), Readonly: true,
			},
			why: "the CSI specification requires an access type, and this driver only has handling for a mount",
		},
		{
			name: "mount with a filesystem type",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: target,
				VolumeCapability: &csi.VolumeCapability{
					AccessType: &csi.VolumeCapability_Mount{
						Mount: &csi.VolumeCapability_MountVolume{FsType: "ext4"},
					},
					AccessMode: &csi.VolumeCapability_AccessMode{
						Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
					},
				},
				VolumeContext: ephemeralContext(), Readonly: true,
			},
			why: "the publish creates a socket in a plain directory, so there is nothing to format",
		},
		{
			name: "mount with mount flags",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: target,
				VolumeCapability: &csi.VolumeCapability{
					AccessType: &csi.VolumeCapability_Mount{
						Mount: &csi.VolumeCapability_MountVolume{MountFlags: []string{"noexec"}},
					},
					AccessMode: &csi.VolumeCapability_AccessMode{
						Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
					},
				},
				VolumeContext: ephemeralContext(), Readonly: true,
			},
			why: "the publish mounts nothing, so there is nowhere to put flags",
		},
		{
			name: "no access mode",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: target,
				VolumeCapability: &csi.VolumeCapability{
					AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
				},
				VolumeContext: ephemeralContext(), Readonly: true,
			},
			why: "the CSI specification requires an access mode",
		},
		{
			name: "reader-only access mode",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: target,
				VolumeCapability: &csi.VolumeCapability{
					AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
					AccessMode: &csi.VolumeCapability_AccessMode{
						Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY,
					},
				},
				VolumeContext: ephemeralContext(), Readonly: true,
			},
			why: "the kubelet sends SINGLE_NODE_WRITER for an inline ephemeral volume, so this came from elsewhere",
		},
		{
			name: "not an inline ephemeral volume",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: target, VolumeCapability: mountCapability(),
				VolumeContext: map[string]string{}, Readonly: true,
			},
			why: "the CSIDriver object declares Ephemeral only, so anything else is a PersistentVolume naming this driver",
		},
		{
			name: "target outside the kubelet pods directory",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: "/etc", VolumeCapability: mountCapability(),
				VolumeContext: ephemeralContext(), Readonly: true,
			},
			why: "an accepted target is a directory the node service creates and later deletes",
		},
		{
			name: "target with a traversal segment",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: podsDir + "/../../etc", VolumeCapability: mountCapability(),
				VolumeContext: ephemeralContext(), Readonly: true,
			},
			why: "the kubelet sends clean paths, so a traversal did not come from it",
		},
		{
			name: "relative target",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: "relative/path", VolumeCapability: mountCapability(),
				VolumeContext: ephemeralContext(), Readonly: true,
			},
			why: "a relative path is resolved against the agent's working directory, which is not the kubelet's",
		},
		{
			name: "the pods directory itself",
			request: &csi.NodePublishVolumeRequest{
				VolumeId: "csi-volume-1", TargetPath: podsDir, VolumeCapability: mountCapability(),
				VolumeContext: ephemeralContext(), Readonly: true,
			},
			why: "the pods directory is every pod's, and unpublish would try to delete it",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := NewWithT(t)

			server := &fakeServer{}
			nodeSrv := newNodeServer(newPodSockets(server.serve), "node-1", podsDir)

			_, err := nodeSrv.NodePublishVolume(context.Background(), testCase.request)
			g.Expect(err).To(HaveOccurred(), testCase.why)
			g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument), testCase.why)
			g.Expect(server.served()).To(BeZero(), "a refused request must serve nothing")
			g.Expect(target).ToNot(BeADirectory(), "a refused request must create nothing")
		})
	}
}

func TestNodeUnpublishVolume_PublishedVolume_StopsServingAndRemovesTheTarget(t *testing.T) {
	g := NewWithT(t)

	nodeSrv, server, podsDir := newTestNodeServer(t)
	target := targetUnder(podsDir)
	pod := podView(t, target)

	_, err := nodeSrv.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(dialGreeting(pod)).To(Equal(greeting))

	_, err = nodeSrv.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(target).ToNot(BeADirectory(), "the kubelet expects the plugin to remove the target it was given")
	g.Eventually(server.stoppedCount).Should(Equal(1),
		"the listener has to be closed, not just unlinked, or every torn-down pod leaks one")
}

// The kubelet repeats unpublish until it succeeds, so an error for a volume already gone
// would leave the pod stuck terminating.
func TestNodeUnpublishVolume_CalledTwice_Succeeds(t *testing.T) {
	g := NewWithT(t)

	nodeSrv, _, podsDir := newTestNodeServer(t)
	target := targetUnder(podsDir)

	_, err := nodeSrv.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())

	for range 2 {
		_, err = nodeSrv.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
		g.Expect(err).ToNot(HaveOccurred())
	}
	g.Expect(target).ToNot(BeADirectory())
}

func TestNodeUnpublishVolume_NeverPublished_Succeeds(t *testing.T) {
	testCases := []struct {
		name    string
		prepare func(g Gomega, target string)
	}{
		{name: "target absent", prepare: func(Gomega, string) {}},
		{
			name:    "target present and empty",
			prepare: func(g Gomega, target string) { g.Expect(os.MkdirAll(target, targetPathMode)).To(Succeed()) },
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := NewWithT(t)

			nodeSrv, _, podsDir := newTestNodeServer(t)
			target := targetUnder(podsDir)
			testCase.prepare(g, target)

			_, err := nodeSrv.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(target).ToNot(BeADirectory())
		})
	}
}

// Anything but a socket at the socket's path is not ours to remove, published or not.
func TestNodeUnpublishVolume_NonSocketAtTheSocketPath_IsInternalAndLeftAlone(t *testing.T) {
	g := NewWithT(t)

	nodeSrv, _, podsDir := newTestNodeServer(t)
	target := targetUnder(podsDir)
	g.Expect(os.MkdirAll(target, targetPathMode)).To(Succeed())
	occupant := filepath.Join(target, podSocketName)
	g.Expect(os.WriteFile(occupant, []byte("data"), 0o600)).To(Succeed())

	_, err := nodeSrv.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).To(HaveOccurred())
	g.Expect(status.Code(err)).To(Equal(codes.Internal))
	g.Expect(os.ReadFile(occupant)).To(Equal([]byte("data")))
}

// The kubelet may unpublish a volume an earlier run published and this one never served,
// such as one torn down while the agent was restarting.
func TestNodeUnpublishVolume_SocketLeftByAnEarlierRun_IsRemoved(t *testing.T) {
	g := NewWithT(t)

	nodeSrv, _, podsDir := newTestNodeServer(t)
	target := targetUnder(podsDir)
	leaveStaleSocket(t, target)

	_, err := nodeSrv.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(target).ToNot(BeADirectory())
}

func TestNodeUnpublishVolume_RejectedRequests_AreInvalidArgument(t *testing.T) {
	testCases := []struct {
		name    string
		request func(target string) *csi.NodeUnpublishVolumeRequest
	}{
		{
			name: "no volume ID",
			request: func(target string) *csi.NodeUnpublishVolumeRequest {
				return &csi.NodeUnpublishVolumeRequest{TargetPath: target}
			},
		},
		{
			name: "no target path",
			request: func(string) *csi.NodeUnpublishVolumeRequest {
				return &csi.NodeUnpublishVolumeRequest{VolumeId: "csi-volume-1"}
			},
		},
		{
			name: "target outside the kubelet pods directory",
			request: func(string) *csi.NodeUnpublishVolumeRequest {
				return &csi.NodeUnpublishVolumeRequest{VolumeId: "csi-volume-1", TargetPath: "/etc"}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := NewWithT(t)

			nodeSrv, _, podsDir := newTestNodeServer(t)
			target := targetUnder(podsDir)
			_, err := nodeSrv.NodePublishVolume(context.Background(), publishRequest(target))
			g.Expect(err).ToNot(HaveOccurred())

			_, err = nodeSrv.NodeUnpublishVolume(context.Background(), testCase.request(target))
			g.Expect(err).To(HaveOccurred())
			g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
			g.Expect(dialGreeting(podView(t, target))).To(Equal(greeting),
				"a refused unpublish must leave the published socket served")
		})
	}
}

// Something other than the socket in the target: removing it would delete data the node
// service did not put there.
func TestNodeUnpublishVolume_NonEmptyTarget_Fails(t *testing.T) {
	g := NewWithT(t)

	nodeSrv, _, podsDir := newTestNodeServer(t)
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

	nodeSrv := newNodeServer(newPodSockets((&fakeServer{}).serve), "ip-10-0-0-1.ec2.internal", "/var/lib/kubelet/pods")

	resp, err := nodeSrv.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.GetNodeId()).To(Equal("ip-10-0-0-1.ec2.internal"))
}

// STAGE_UNSTAGE_VOLUME would make the kubelet call NodeStageVolume, which is not
// implemented, and every mount would fail.
func TestNodeGetCapabilities_ReportsNone(t *testing.T) {
	g := NewWithT(t)

	nodeSrv := newNodeServer(newPodSockets((&fakeServer{}).serve), "node-1", "/var/lib/kubelet/pods")

	resp, err := nodeSrv.NodeGetCapabilities(context.Background(), &csi.NodeGetCapabilitiesRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.GetCapabilities()).To(BeEmpty())
}

// The other half of that: the method answers Unimplemented if the kubelet ever asks.
func TestNodeStageVolume_IsUnimplemented(t *testing.T) {
	g := NewWithT(t)

	nodeSrv := newNodeServer(newPodSockets((&fakeServer{}).serve), "node-1", "/var/lib/kubelet/pods")

	_, err := nodeSrv.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{})
	g.Expect(status.Code(err)).To(Equal(codes.Unimplemented))
}
