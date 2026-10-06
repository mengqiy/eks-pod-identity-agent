//go:build linux

package csidriver

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	pluginregistration "k8s.io/kubelet/pkg/apis/pluginregistration/v1"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
)

// testOpts puts the sockets in a temporary directory, so a test binds real Unix sockets
// without needing the kubelet's directories.
func testOpts(t *testing.T, serveSocket func(net.Listener)) Opts {
	t.Helper()
	root := t.TempDir()
	return Opts{
		NodeName:               "ip-10-0-0-1.ec2.internal",
		ServeSocket:            serveSocket,
		PluginSocketPath:       filepath.Join(root, "plugins", "csi.sock"),
		RegistrationSocketPath: filepath.Join(root, "plugins_registry", "driver-reg.sock"),
		PodsDir:                filepath.Join(root, "pods"),
		ShutdownWait:           100 * time.Millisecond,
		VendorVersion:          "v1.2.3",
	}
}

// serve runs the driver until the test ends, or until the returned stop is called.
func serve(t *testing.T, driver *Driver) (stop func()) {
	t.Helper()
	g := NewWithT(t)

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		driver.ListenUntilContextCancelled(ctx)
	}()
	stop = func() {
		cancel()
		g.Eventually(stopped, 5*time.Second).Should(BeClosed(), "the driver must return once its context is cancelled")
	}
	t.Cleanup(stop)
	return stop
}

// newWorkloadIdentityServer binds the real workload identity gRPC server, with the stub
// services, on a short temporary socket. runServer serves it.
func newWorkloadIdentityServer(t *testing.T) *grpcserver.Server {
	t.Helper()
	g := NewWithT(t)

	dir, err := os.MkdirTemp("", "wi")
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	server, err := grpcserver.New(grpcserver.Opts{
		SocketPath:   filepath.Join(dir, "agent.sock"),
		ShutdownWait: 100 * time.Millisecond,
		Register:     grpcserver.RegisterStubServices,
	})
	g.Expect(err).ToNot(HaveOccurred())
	return server
}

// runServer serves server until the test ends, or until the returned stop is called.
func runServer(t *testing.T, server *grpcserver.Server) (stop func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		server.ListenUntilContextCancelled(ctx)
	}()
	stop = func() {
		cancel()
		<-stopped
	}
	t.Cleanup(stop)
	return stop
}

// workloadIdentityServer is newWorkloadIdentityServer, already serving.
func workloadIdentityServer(t *testing.T) *grpcserver.Server {
	t.Helper()
	server := newWorkloadIdentityServer(t)
	runServer(t, server)
	return server
}

// fetchJWTBundlesCode calls the Workload API through the socket at path, as a SPIFFE client
// does, and returns the status. The stubs answer Unimplemented, so that code means the call
// went through the workload identity server's whole interceptor chain.
func fetchJWTBundlesCode(t *testing.T, path string) codes.Code {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx,
		metadata.Pairs(grpcserver.SpiffeSecurityHeader, grpcserver.SpiffeSecurityHeaderValue))

	stream, err := workload.NewSpiffeWorkloadAPIClient(dial(t, path)).
		FetchJWTBundles(ctx, &workload.JWTBundlesRequest{})
	if err != nil {
		return status.Code(err)
	}
	_, err = stream.Recv()
	return status.Code(err)
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
// and then a pod's call through the socket the publish served, into the real workload
// identity server.
func TestNew_ServesBothSocketsEndToEnd(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t, workloadIdentityServer(t).ServeListener)

	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	serve(t, driver)

	// 1. The kubelet finds the registration socket and asks who this is. The endpoint
	// it gets back is what it dials for everything after this.
	info, err := pluginregistration.NewRegistrationClient(dial(t, opts.RegistrationSocketPath)).
		GetInfo(context.Background(), &pluginregistration.InfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(info.GetType()).To(Equal(pluginregistration.CSIPlugin))
	g.Expect(info.GetName()).To(Equal(configuration.WorkloadIdentityCSIDriver))
	g.Expect(info.GetEndpoint()).To(Equal(opts.PluginSocketPath))

	pluginConn := dial(t, info.GetEndpoint())

	// 2. The plugin agrees about its own name.
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
	_, err = csi.NewNodeClient(pluginConn).NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())

	// 5. The pod calls the Workload API through its own path to the target.
	pod := podView(t, target)
	g.Expect(fetchJWTBundlesCode(t, pod)).To(Equal(codes.Unimplemented))

	// 6. The pod goes away.
	_, err = csi.NewNodeClient(pluginConn).NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(target).ToNot(BeADirectory())
}

// T12's definition of done: an agent restart leaves an already-published pod able to
// reconnect, at the same path, with no republish from the kubelet.
func TestNew_AfterARestart_ServesThePodsPublishedBefore(t *testing.T) {
	g := NewWithT(t)

	// The first run of the agent: its workload identity server and its driver.
	firstServer := newWorkloadIdentityServer(t)
	opts := testOpts(t, firstServer.ServeListener)
	first, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	stopFirstServer := runServer(t, firstServer)
	stopFirst := serve(t, first)

	// The kubelet records the volume, then publishes it.
	podUID := "6f1c9f4e-0000-0000-0000-000000000001"
	volumeDir := filepath.Join(opts.PodsDir, podUID, "volumes", kubeletCSIVolumesDir,
		configuration.WorkloadIdentitySocketVolumeName)
	target := filepath.Join(volumeDir, kubeletMountDir)
	g.Expect(os.MkdirAll(volumeDir, 0o750)).To(Succeed())
	raw, err := json.Marshal(ourVolData())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(os.WriteFile(filepath.Join(volumeDir, kubeletVolDataFile), raw, 0o644)).To(Succeed())

	_, err = csi.NewNodeClient(dial(t, opts.PluginSocketPath)).
		NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())

	pod := podView(t, target)
	g.Expect(fetchJWTBundlesCode(t, pod)).To(Equal(codes.Unimplemented))

	// The agent stops. The pod's socket is still there and nothing answers on it.
	stopFirst()
	stopFirstServer()
	info, err := os.Lstat(filepath.Join(target, podSocketName))
	g.Expect(err).ToNot(HaveOccurred(), "the socket stays on disk across a restart")
	g.Expect(info.Mode().Type()).To(Equal(os.ModeSocket))
	g.Expect(fetchJWTBundlesCode(t, pod)).To(Equal(codes.Unavailable))

	// The agent starts again in production order: a fresh server, then the driver, whose
	// restore hands the socket over before the server's own loop runs.
	secondServer := newWorkloadIdentityServer(t)
	opts.ServeSocket = secondServer.ServeListener
	second, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fetchJWTBundlesCode(t, pod)).To(Equal(codes.Unimplemented),
		"the pod reconnects at the path it already had")

	runServer(t, secondServer)
	serve(t, second)
	g.Expect(fetchJWTBundlesCode(t, pod)).To(Equal(codes.Unimplemented))
}

// 0600, unlike the workload identity socket's 0666: only the kubelet dials these, and the
// calls behind the plugin socket mount.
func TestNew_BindsBothSockets0600(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t, (&fakeServer{}).serve)
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

	opts := testOpts(t, (&fakeServer{}).serve)
	opts.NodeName = ""

	_, err := New(opts)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("node name"))
}

// The half-built case: a registration socket with no plugin behind it advertises a plugin
// that is not running, and the kubelet would try to register from it.
func TestNew_UnbindablePluginSocket_LeavesNoRegistrationSocketBehind(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t, (&fakeServer{}).serve)
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

	opts := testOpts(t, (&fakeServer{}).serve)
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

	opts := testOpts(t, (&fakeServer{}).serve)
	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(driver.RemoveSockets).ToNot(Panic())
	g.Expect(driver.RemoveSockets).ToNot(Panic())
}

func TestAddr_IsThePluginSocket(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t, (&fakeServer{}).serve)
	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(driver.RemoveSockets)

	g.Expect(driver.Addr()).To(Equal(opts.PluginSocketPath))
}

// Refused where the process can still exit non-zero, rather than accepting publishes that
// nothing serves.
func TestNew_NoServeSocket_Fails(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t, nil)

	_, err := New(opts)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("ServeSocket"))
}

// The production paths come from package configuration. Not bound here: the kubelet's
// directories do not exist on a test host.
func TestNew_DefaultOpts_UseTheConfigurationConstants(t *testing.T) {
	g := NewWithT(t)

	g.Expect(valueOrDefault("", configuration.KubeletPluginSocketPath)).To(Equal("/var/lib/kubelet/plugins/spiffe.csi.eks.amazonaws.com/csi.sock"))
	g.Expect(valueOrDefault("", configuration.KubeletRegistrationSocketPath)).To(Equal("/var/lib/kubelet/plugins_registry/spiffe.csi.eks.amazonaws.com-reg.sock"))
	g.Expect(valueOrDefault("", configuration.KubeletPodsDir)).To(Equal("/var/lib/kubelet/pods"))
	g.Expect(filepath.Join(configuration.WorkloadIdentitySocketMountPath, podSocketName)).
		To(Equal(configuration.WorkloadIdentitySocketPath),
			"the socket in the target is what the pod sees at the path the webhook injects")
	g.Expect(valueOrDefault("set", configuration.KubeletPodsDir)).To(Equal("set"))
}
