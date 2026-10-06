package csidriver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
)

const (
	// Kubelet layout of an inline CSI volume, <pods>/<uid>/volumes/kubernetes.io~csi/<name>/,
	// holding vol_data.json and the mount directory that is the publish target.
	kubeletCSIVolumesDir = "kubernetes.io~csi"
	kubeletVolDataFile   = "vol_data.json"
	kubeletMountDir      = "mount"

	// Keys and the lifecycle value the kubelet writes into vol_data.json.
	volDataDriverNameKey    = "driverName"
	volDataLifecycleModeKey = "volumeLifecycleMode"
	volDataEphemeralMode    = "Ephemeral"
)

// podSocketName is the socket's file name in each target. The pod sees the target at
// WorkloadIdentitySocketMountPath, so this is what makes the socket appear at
// WorkloadIdentitySocketPath.
var podSocketName = filepath.Base(configuration.WorkloadIdentitySocketPath)

// errPodSocketsClosed is what a publish gets once the driver is shutting down.
var errPodSocketsClosed = errors.New("the CSI driver is shutting down")

// podSockets is the workload identity socket in every published target, one per pod.
//
// The socket is created inside the target directory, which is an ordinary directory on the
// host filesystem, and the container runtime bind mounts that directory into the pod. So the
// pod sees the socket without the agent mounting anything, and the agent needs neither
// CAP_SYS_ADMIN nor Bidirectional propagation, and so not privileged either.
type podSockets struct {
	// serve hands a bound listener to the workload identity gRPC server.
	serve func(net.Listener)

	mu sync.Mutex
	// byTarget is every socket this process is serving, keyed by target path.
	byTarget map[string]*podSocket
	// closed is set by closeAll, after which publish refuses: a forced stop does not wait
	// for in-flight handlers, so one can still reach publish.
	closed bool
}

// podSocket is one served socket. dir stays open for the socket's life because every
// operation on the socket goes through it; see listenIn.
type podSocket struct {
	dir *os.File
	lis net.Listener
}

func newPodSockets(serve func(net.Listener)) *podSockets {
	return &podSockets{serve: serve, byTarget: map[string]*podSocket{}}
}

// publish creates and serves the socket in target, which must exist. It reports false when
// target was already served, so a repeated publish is a no-op. A socket file already there
// is an earlier run's, since the agent leaves them on exit, and is replaced; anything else
// there is not ours and is refused.
func (p *podSockets) publish(target string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return false, errPodSocketsClosed
	}
	if _, ok := p.byTarget[target]; ok {
		return false, nil
	}

	dir, err := os.Open(target)
	if err != nil {
		return false, fmt.Errorf("opening %s: %w", target, err)
	}

	if err := removeStaleSocket(dir, podSocketName); err != nil {
		_ = dir.Close()
		return false, fmt.Errorf("in %s: %w", target, err)
	}

	lis, err := listenIn(dir, podSocketName, grpcserver.SocketMode)
	if err != nil {
		_ = dir.Close()
		return false, fmt.Errorf("in %s: %w", target, err)
	}
	// The bound address is /proc/self/fd/<n>/..., whose n is reused across pods, so the
	// listener reports the target path to whatever logs it.
	lis = namedListener{Listener: lis, addr: &net.UnixAddr{Name: filepath.Join(target, podSocketName), Net: "unix"}}

	p.byTarget[target] = &podSocket{dir: dir, lis: lis}
	p.serve(lis)
	return true, nil
}

// unpublish stops serving target and removes its socket. Idempotent, and also removes a
// socket an earlier run left behind, since the kubelet may unpublish a volume this process
// never published.
func (p *podSockets) unpublish(target string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	socket, ok := p.byTarget[target]
	if ok {
		delete(p.byTarget, target)
		_ = socket.lis.Close()
		defer func() { _ = socket.dir.Close() }()
		return unlinkIn(socket.dir, podSocketName)
	}

	dir, err := os.Open(target)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opening %s: %w", target, err)
	}
	defer func() { _ = dir.Close() }()
	return removeStaleSocket(dir, podSocketName)
}

// closeAll stops serving every socket and refuses further publishes. The files stay: a pod
// dialling before the next run is refused and retries, and the next run's restore replaces
// them.
func (p *podSockets) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true
	for target, socket := range p.byTarget {
		_ = socket.lis.Close()
		_ = socket.dir.Close()
		delete(p.byTarget, target)
	}
}

// restore serves the socket again in every target the kubelet records in vol_data.json for
// driverName, so pods published before an agent restart reconnect: the kubelet does not
// publish a volume it has already set up again. A target that cannot be restored is logged
// and skipped, so one bad volume does not cost the other pods their sockets.
func (p *podSockets) restore(podsDir, driverName string) int {
	log := logger.FromContext(context.Background())

	pattern := filepath.Join(podsDir, "*", "volumes", kubeletCSIVolumesDir, "*", kubeletVolDataFile)
	volData, err := filepath.Glob(pattern)
	if err != nil {
		log.Warnf("Unable to look for published workload identity volumes under %s: %v", podsDir, err)
		return 0
	}

	restored := 0
	for _, path := range volData {
		if !isOurEphemeralVolume(path, driverName) {
			continue
		}

		target := filepath.Join(filepath.Dir(path), kubeletMountDir)
		if info, err := os.Stat(target); err != nil || !info.IsDir() {
			continue
		}

		created, err := p.publish(target)
		if err != nil {
			log.Warnf("Unable to restore the workload identity socket in %s: %v", target, err)
			continue
		}
		if created {
			restored++
		}
	}
	return restored
}

// isOurEphemeralVolume reports whether the kubelet's vol_data.json at path describes an
// inline volume of driverName. Unreadable or unparsable data is not ours.
func isOurEphemeralVolume(path, driverName string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		// Gone is a volume being torn down; anything else is worth knowing about.
		if !errors.Is(err, fs.ErrNotExist) {
			logger.FromContext(context.Background()).Warnf("Unable to read %s: %v", path, err)
		}
		return false
	}
	var data map[string]string
	if err := json.Unmarshal(raw, &data); err != nil {
		return false
	}
	return data[volDataDriverNameKey] == driverName && data[volDataLifecycleModeKey] == volDataEphemeralMode
}

// namedListener reports addr instead of the address it is bound to. Accepted connections are
// the embedded listener's own, so attestation still gets a *net.UnixConn.
type namedListener struct {
	net.Listener
	addr net.Addr
}

func (l namedListener) Addr() net.Addr { return l.addr }
