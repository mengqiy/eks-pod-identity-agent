package csidriver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pluginregistration "k8s.io/kubelet/pkg/apis/pluginregistration/v1"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// testOpts puts the sockets in a temporary directory, so a test binds real Unix sockets
// without needing the kubelet's directories.
func testOpts(t *testing.T, mounter Mounter) Opts {
	t.Helper()
	root := t.TempDir()
	return Opts{
		NodeName:               "ip-10-0-0-1.ec2.internal",
		Mounter:                mounter,
		SourceDir:              filepath.Join(root, "source"),
		PluginSocketPath:       filepath.Join(root, "plugins", "csi.sock"),
		RegistrationSocketPath: filepath.Join(root, "plugins_registry", "driver-reg.sock"),
		PodsDir:                filepath.Join(root, "pods"),
		ShutdownWait:           100 * time.Millisecond,
		VendorVersion:          "v1.2.3",
	}
}

// serve runs the driver until the test ends.
func serve(t *testing.T, driver *Driver, opts Opts) {
	t.Helper()
	g := NewWithT(t)

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		driver.ListenUntilContextCancelled(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		g.Eventually(stopped, 5*time.Second).Should(BeClosed(), "the driver must return once its context is cancelled")
	})
}

func dial(t *testing.T, socketPath string) *grpc.ClientConn {
	t.Helper()
	g := NewWithT(t)

	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// The kubelet's two conversations end to end, through generated clients over real sockets,
// so the socket wiring and service registration are covered and not just the handlers.
func TestNew_ServesBothSocketsEndToEnd(t *testing.T) {
	g := NewWithT(t)

	mounter := newFakeMounter()
	opts := testOpts(t, mounter)

	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	serve(t, driver, opts)

	// 1. The kubelet finds the registration socket and asks who this is. The endpoint
	// it gets back is what it dials for everything after this.
	info, err := pluginregistration.NewRegistrationClient(dial(t, opts.RegistrationSocketPath)).
		GetInfo(context.Background(), &pluginregistration.InfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(info.GetType()).To(Equal(pluginregistration.CSIPlugin))
	g.Expect(info.GetName()).To(Equal(configuration.WorkloadIdentityCSIDriver))
	g.Expect(info.GetEndpoint()).To(Equal(opts.PluginSocketPath))

	pluginConn := dial(t, info.GetEndpoint())

	// 2. The kubelet confirms the plugin agrees about its own name, which is the check
	// it refuses the plugin over.
	pluginInfo, err := csi.NewIdentityClient(pluginConn).GetPluginInfo(context.Background(), &csi.GetPluginInfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(pluginInfo.GetName()).To(Equal(info.GetName()))

	// 3. The kubelet records the node ID.
	nodeInfo, err := csi.NewNodeClient(pluginConn).NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(nodeInfo.GetNodeId()).To(Equal(opts.NodeName))

	// 4. A pod is scheduled, and the kubelet asks for the volume.
	target := filepath.Join(opts.PodsDir, "pod-uid", "volumes", "kubernetes.io~csi",
		configuration.WorkloadIdentitySocketVolumeName, "mount")
	_, err = csi.NewNodeClient(pluginConn).NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
		VolumeId:         "csi-volume-1",
		TargetPath:       target,
		VolumeCapability: mountCapability(),
		VolumeContext:    ephemeralContext(),
		Readonly:         true,
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(mounter.mounted).To(HaveKeyWithValue(target, opts.SourceDir),
		"the published source is the socket directory the driver was built with")

	// 5. The pod goes away.
	_, err = csi.NewNodeClient(pluginConn).NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
		VolumeId:   "csi-volume-1",
		TargetPath: target,
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(mounter.mounted).ToNot(HaveKey(target))
}

// 0600, unlike the workload identity socket's 0666: only the kubelet dials these, and the
// calls behind the plugin socket mount.
func TestNew_BindsBothSockets0600(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t, newFakeMounter())
	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(driver.RemoveSockets)

	for _, socketPath := range []string{opts.PluginSocketPath, opts.RegistrationSocketPath} {
		info, err := os.Stat(socketPath)
		g.Expect(err).ToNot(HaveOccurred(), "New must bind %s before it returns", socketPath)
		g.Expect(info.Mode().Perm()).To(Equal(socketMode),
			"%s is reachable by anything with the bits to dial it", socketPath)
	}
}

// Refused where the process can still exit non-zero, rather than registering without a
// node ID.
func TestNew_NoNodeName_Fails(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t, newFakeMounter())
	opts.NodeName = ""

	_, err := New(opts)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("node name"))
}

// The half-built case: a registration socket with no plugin behind it advertises a plugin
// that is not running, and the kubelet would try to register from it.
func TestNew_UnbindablePluginSocket_LeavesNoRegistrationSocketBehind(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t, newFakeMounter())
	// A directory where the socket should go: the bind cannot replace it, and
	// UnlinkIfStale refuses to remove something that is not a socket.
	g.Expect(os.MkdirAll(opts.PluginSocketPath, 0o755)).To(Succeed())

	_, err := New(opts)
	g.Expect(err).To(HaveOccurred())

	_, err = os.Stat(opts.RegistrationSocketPath)
	g.Expect(os.IsNotExist(err)).To(BeTrue(),
		"a failed New must not leave a registration socket the kubelet can find")
}

// What the next boot inherits. The registration socket matters most: the kubelet watches
// that directory.
func TestRemoveSockets_AfterShutdown_UnlinksBoth(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t, newFakeMounter())
	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		driver.ListenUntilContextCancelled(ctx)
	}()

	// Reached through the socket rather than by waiting, so the shutdown below happens
	// to a driver that was actually serving.
	_, err = pluginregistration.NewRegistrationClient(dial(t, opts.RegistrationSocketPath)).
		GetInfo(context.Background(), &pluginregistration.InfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())

	cancel()
	g.Eventually(stopped, 5*time.Second).Should(BeClosed())

	for _, socketPath := range []string{opts.PluginSocketPath, opts.RegistrationSocketPath} {
		_, err := os.Stat(socketPath)
		g.Expect(os.IsNotExist(err)).To(BeTrue(), "%s outlived the driver", socketPath)
	}
}

// It is both deferred in the serve loop and registered as a logrus exit handler.
func TestRemoveSockets_CalledTwice_IsSafe(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t, newFakeMounter())
	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(driver.RemoveSockets).ToNot(Panic())
	g.Expect(driver.RemoveSockets).ToNot(Panic())
}

func TestAddr_IsThePluginSocket(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t, newFakeMounter())
	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(driver.RemoveSockets)

	g.Expect(driver.Addr()).To(Equal(opts.PluginSocketPath))
}

// The production paths come from package configuration. Not bound here: the kubelet's
// directories do not exist on a test host.
func TestNew_DefaultOpts_UseTheConfigurationConstants(t *testing.T) {
	g := NewWithT(t)

	g.Expect(valueOrDefault("", configuration.KubeletPluginSocketPath)).To(Equal("/var/lib/kubelet/plugins/spiffe.csi.eks.amazonaws.com/csi.sock"))
	g.Expect(valueOrDefault("", configuration.KubeletRegistrationSocketPath)).To(Equal("/var/lib/kubelet/plugins_registry/spiffe.csi.eks.amazonaws.com-reg.sock"))
	g.Expect(valueOrDefault("", configuration.KubeletPodsDir)).To(Equal("/var/lib/kubelet/pods"))
	g.Expect(valueOrDefault("", configuration.WorkloadIdentitySocketMountPath)).
		To(Equal("/var/run/secrets/pods.eks.amazonaws.com/workloadidentity"),
			"the published directory is the one the agent's socket lives in")
	g.Expect(valueOrDefault("set", configuration.KubeletPodsDir)).To(Equal("set"))
}
