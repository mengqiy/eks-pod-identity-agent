// Package csidriver makes the agent the CSI node plugin for
// spiffe.csi.eks.amazonaws.com, so the workload identity socket appears inside an
// enrolled pod without that pod mounting a hostPath, which a restricted Pod Security
// Standard forbids.
//
// Scope: the per-node plugin only. The cluster-scoped CSIDriver object is installed by
// the Helm chart (a node identity has no create on csidrivers), and the per-pod volume
// is injected by the Pod Identity webhook.
//
// Two sockets, because the kubelet's discovery needs two: one carrying the CSI Identity
// and Node services, one carrying the registration handshake. The handshake is served
// in-process rather than by the node-driver-registrar sidecar; see registrationServer.
package csidriver

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	pluginregistration "k8s.io/kubelet/pkg/apis/pluginregistration/v1"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
)

const (
	// socketMode is 0600, unlike the workload identity socket's 0666: the only caller
	// is the kubelet, which is root, and NodePublishVolume mounts. A world-writable
	// plugin socket would hand any process on the node a mount primitive.
	socketMode os.FileMode = 0o600

	// defaultShutdownWait bounds each server's graceful stop. Short because every call
	// here is a unary request the kubelet waits for; nothing is held open.
	defaultShutdownWait = 2 * time.Second

	// forcedStopWait bounds the wait for an accept loop to unwind after in-flight calls
	// are cancelled. By then the listener is closed and the socket unlinked.
	forcedStopWait = 1 * time.Second
)

// Driver serves the CSI plugin and the kubelet registration handshake for the life of a
// context. It satisfies the same two-method interface cmd drives the other servers
// through.
type Driver struct {
	plugin    *grpc.Server
	pluginLis net.Listener

	registration    *grpc.Server
	registrationLis net.Listener

	pluginSocketPath       string
	registrationSocketPath string

	shutdownWait time.Duration
}

// Opts configures the driver. Every path defaults to the constant production uses, so a
// caller passes the node name and nothing else, and a test passes temporary paths.
type Opts struct {
	// NodeName is reported to the kubelet as the CSI node ID and recorded in the node's
	// CSINode object. It is supplied by the caller (from the downward API in
	// production) rather than resolved here: the node name authorization depends on is
	// the one the API server authenticates the agent as, which internal/kube derives
	// from a SelfSubjectReview, and registration should not wait on an API call.
	NodeName string

	// Mounter performs the bind mount. Nil means the real one.
	Mounter Mounter

	// SourceDir is the directory published into each enrolled pod. Empty means
	// configuration.WorkloadIdentitySocketMountPath.
	SourceDir string

	// PluginSocketPath serves the CSI Identity and Node services. Empty means
	// configuration.KubeletPluginSocketPath.
	PluginSocketPath string

	// RegistrationSocketPath serves the kubelet's registration handshake. Empty means
	// configuration.KubeletRegistrationSocketPath.
	RegistrationSocketPath string

	// PodsDir is the root every target path must be inside. Empty means
	// configuration.KubeletPodsDir.
	PodsDir string

	// ShutdownWait bounds each graceful stop. Zero or less means defaultShutdownWait.
	ShutdownWait time.Duration

	// VendorVersion is reported by GetPluginInfo. Empty is reported as "unknown".
	VendorVersion string
}

// New binds both sockets and returns a driver ready to be driven.
//
// Binding here rather than in the serve loop makes an unbindable socket a boot failure.
// These two live under the kubelet's directories, which the chart mounts in, so the
// usual cause is a missing hostPath.
//
// The plugin socket is bound first: the kubelet may dial the registration socket as soon
// as it exists and its first act is to ask for the plugin endpoint. Serving can follow,
// since a connection to a bound socket waits in the backlog.
func New(opts Opts) (*Driver, error) {
	// Refused rather than defaulted: the CSI specification requires a node ID, and a
	// driver that registers without one is a thing an operator has to go and find.
	if opts.NodeName == "" {
		return nil, errors.New("csidriver: no node name configured: neither the NODE_NAME environment variable " +
			"the chart sets from spec.nodeName nor the hostname yielded one")
	}

	mounter := opts.Mounter
	if mounter == nil {
		mounter = NewMounter()
	}
	source := valueOrDefault(opts.SourceDir, configuration.WorkloadIdentitySocketMountPath)
	pluginSocketPath := valueOrDefault(opts.PluginSocketPath, configuration.KubeletPluginSocketPath)
	registrationSocketPath := valueOrDefault(opts.RegistrationSocketPath, configuration.KubeletRegistrationSocketPath)
	podsDir := valueOrDefault(opts.PodsDir, configuration.KubeletPodsDir)

	shutdownWait := opts.ShutdownWait
	if shutdownWait <= 0 {
		shutdownWait = defaultShutdownWait
	}

	pluginLis, err := grpcserver.ListenUnix(pluginSocketPath, socketMode)
	if err != nil {
		return nil, err
	}

	registrationLis, err := grpcserver.ListenUnix(registrationSocketPath, socketMode)
	if err != nil {
		// Nothing else will close the plugin socket if this returns an error.
		_ = pluginLis.Close()
		_ = grpcserver.UnlinkIfStale(pluginSocketPath)
		return nil, err
	}

	plugin := grpc.NewServer()
	csi.RegisterIdentityServer(plugin, newIdentityServer(configuration.WorkloadIdentityCSIDriver, opts.VendorVersion))
	csi.RegisterNodeServer(plugin, newNodeServer(mounter, opts.NodeName, source, podsDir))

	registration := grpc.NewServer()
	pluginregistration.RegisterRegistrationServer(registration,
		newRegistrationServer(configuration.WorkloadIdentityCSIDriver, pluginSocketPath))

	return &Driver{
		plugin:                 plugin,
		pluginLis:              pluginLis,
		registration:           registration,
		registrationLis:        registrationLis,
		pluginSocketPath:       pluginSocketPath,
		registrationSocketPath: registrationSocketPath,
		shutdownWait:           shutdownWait,
	}, nil
}

// Addr is the plugin socket path, the log field cmd tags this server's lines with.
func (d *Driver) Addr() string {
	return d.pluginSocketPath
}

// ListenUntilContextCancelled serves both sockets until ctx is cancelled, then shuts
// them down and returns.
func (d *Driver) ListenUntilContextCancelled(ctx context.Context) {
	log := logger.FromContext(ctx)

	// Deferred so the sockets are cleaned up on the ordinary shutdown, the fatal path,
	// and a panic unwinding this goroutine.
	defer d.RemoveSockets()

	served := make(chan error, 2)
	go func() {
		log.Infof("Starting CSI plugin server for driver %s...", configuration.WorkloadIdentityCSIDriver)
		served <- d.plugin.Serve(d.pluginLis)
	}()
	go func() {
		log.Infof("Starting kubelet plugin registration server at %s...", d.registrationSocketPath)
		served <- d.registration.Serve(d.registrationLis)
	}()

	select {
	case err := <-served:
		// After a successful bind, Serve returning means the accept loop failed. Fatal
		// either way: a plugin that cannot be dialled and one that cannot be registered
		// both end in enrolled pods that never start.
		if err != nil {
			log.Fatalf("Unable to serve the CSI driver: %v", err)
		}
		return
	case <-ctx.Done():
	}

	log.Info("Shutting down the CSI driver...")

	// Registration first, so the kubelet cannot start a registration the plugin server
	// is about to stop answering. It also re-registers from scratch when the socket
	// reappears, so it is the cheaper of the two to lose.
	d.stop(log, "kubelet plugin registration", d.registration, served)
	d.stop(log, "CSI plugin", d.plugin, served)

	log.Info("CSI driver stopped")
}

// stop runs GracefulStop under a deadline, escalates to Stop, and returns once Serve has
// returned or the escalation has had its own slice of time.
//
// Neither wait may be unbounded: gRPC holds the server lock while waiting for handler
// goroutines, so a wedged handler would park GracefulStop, Stop and Serve behind each
// other and take the whole agent's shutdown with it. Abandoning it is safe once the
// listener is closed and the socket unlinked.
func (d *Driver) stop(log *logrus.Entry, name string, server *grpc.Server, served <-chan error) {
	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		<-served
		return
	case <-time.After(d.shutdownWait):
		log.Warnf("Graceful stop of the %s server did not finish within %s, cancelling in-flight calls", name, d.shutdownWait)
	}

	// In its own goroutine: the GracefulStop in flight may hold the lock Stop needs.
	go server.Stop()

	select {
	case <-served:
	case <-time.After(forcedStopWait):
		log.Warnf("The %s server did not stop within %s of cancelling its calls, abandoning it", name, forcedStopWait)
	}
}

// RemoveSockets unlinks both sockets if they are still there. Safe to call more than
// once.
//
// Usually a no-op, since Go unlinks a socket it created when the listener closes, but
// that is skipped for a listener the agent did not create. It matters most for the
// registration socket: the kubelet watches that directory, so one left behind
// advertises a plugin that is not running.
//
// Exported because log.Fatalf exits without running deferred functions, so the wiring
// site also hands this to logrus.RegisterExitHandler.
func (d *Driver) RemoveSockets() {
	for _, socket := range []struct {
		path     string
		listener net.Listener
	}{
		{path: d.registrationSocketPath, listener: d.registrationLis},
		{path: d.pluginSocketPath, listener: d.pluginLis},
	} {
		// Close first: UnlinkIfStale would otherwise read our own still-open socket as a
		// live successor's and leave it behind.
		if socket.listener != nil {
			_ = socket.listener.Close()
		}
		if err := grpcserver.UnlinkIfStale(socket.path); err != nil {
			logger.FromContext(context.Background()).Warnf("Leaving %s in place: %v", socket.path, err)
		}
	}
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// cmd's runnable is unexported, so this is the closest assertion available here.
var _ interface {
	ListenUntilContextCancelled(ctx context.Context)
	Addr() string
} = (*Driver)(nil)
