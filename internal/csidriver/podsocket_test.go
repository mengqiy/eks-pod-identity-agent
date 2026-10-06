//go:build linux

package csidriver

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
)

// greeting is what fakeServer answers every connection with, so a dial that reads it
// reached a socket that is being served rather than one that is merely bound.
const greeting = "workload identity"

// fakeServer stands in for the workload identity gRPC server: it accepts on every
// listener it is handed and writes greeting to each connection.
type fakeServer struct {
	mu        sync.Mutex
	listeners []net.Listener
	// stopped counts listeners whose accept loop ended, which only a Close causes here.
	stopped int
}

func (f *fakeServer) serve(lis net.Listener) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listeners = append(f.listeners, lis)

	go func() {
		defer func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.stopped++
		}()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte(greeting))
			_ = conn.Close()
		}
	}()
}

func (f *fakeServer) served() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.listeners)
}

func (f *fakeServer) stoppedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopped
}

// podView returns the socket path as the pod dials it: a short path to the target, the way
// the container runtime's bind mount gives the pod one. A symlink stands in for the bind.
func podView(t *testing.T, target string) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "pod")
	if err != nil {
		t.Fatalf("creating the pod view: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	link := filepath.Join(dir, "wi")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("linking the pod view to %s: %v", target, err)
	}
	return filepath.Join(link, podSocketName)
}

// dialGreeting connects to path and returns what the server wrote.
func dialGreeting(path string) (string, error) {
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	answer, err := io.ReadAll(conn)
	return string(answer), err
}

// leaveStaleSocket binds a socket in target and closes it without unlinking, which is
// what an earlier run of the agent leaves behind.
func leaveStaleSocket(t *testing.T, target string) {
	t.Helper()
	g := NewWithT(t)

	g.Expect(os.MkdirAll(target, targetPathMode)).To(Succeed())
	dir, err := os.Open(target)
	g.Expect(err).ToNot(HaveOccurred())
	defer func() { _ = dir.Close() }()

	lis, err := listenIn(dir, podSocketName, grpcserver.SocketMode)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(lis.Close()).To(Succeed())

	info, err := os.Lstat(filepath.Join(target, podSocketName))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(info.Mode().Type()).To(Equal(os.ModeSocket))
}

// kubeletVolume lays out what the kubelet leaves for an inline CSI volume, with the given
// vol_data.json contents, and returns the target. A nil volData writes none.
func kubeletVolume(t *testing.T, podsDir, podUID string, volData map[string]string) string {
	t.Helper()
	g := NewWithT(t)

	volumeDir := filepath.Join(podsDir, podUID, "volumes", kubeletCSIVolumesDir,
		configuration.WorkloadIdentitySocketVolumeName)
	target := filepath.Join(volumeDir, kubeletMountDir)
	g.Expect(os.MkdirAll(target, targetPathMode)).To(Succeed())

	if volData != nil {
		raw, err := json.Marshal(volData)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(os.WriteFile(filepath.Join(volumeDir, kubeletVolDataFile), raw, 0o644)).To(Succeed())
	}
	return target
}

// ourVolData is what the kubelet records for the volume the webhook injects.
func ourVolData() map[string]string {
	return map[string]string{
		"specVolID":             configuration.WorkloadIdentitySocketVolumeName,
		volDataDriverNameKey:    configuration.WorkloadIdentityCSIDriver,
		"volumeHandle":          "csi-0123",
		"nodeName":              "ip-10-0-0-1.ec2.internal",
		volDataLifecycleModeKey: volDataEphemeralMode,
	}
}

// An agent restart must not strand the pods it published: the kubelet does not publish a
// set-up volume again, so the new process finds them itself.
func TestRestore_OurVolumeFromAnEarlierRun_IsServedAgain(t *testing.T) {
	g := NewWithT(t)

	podsDir := t.TempDir()
	target := kubeletVolume(t, podsDir, "pod-a", ourVolData())
	leaveStaleSocket(t, target)

	server := &fakeServer{}
	sockets := newPodSockets(server.serve)
	t.Cleanup(sockets.closeAll)

	g.Expect(sockets.restore(podsDir, configuration.WorkloadIdentityCSIDriver)).To(Equal(1))
	g.Expect(dialGreeting(podView(t, target))).To(Equal(greeting))
}

func TestRestore_VolumesThatAreNotOurs_AreLeftAlone(t *testing.T) {
	g := NewWithT(t)

	podsDir := t.TempDir()

	otherDriver := ourVolData()
	otherDriver[volDataDriverNameKey] = "csi.spiffe.io"
	otherTarget := kubeletVolume(t, podsDir, "pod-other-driver", otherDriver)

	persistent := ourVolData()
	persistent[volDataLifecycleModeKey] = "Persistent"
	persistentTarget := kubeletVolume(t, podsDir, "pod-persistent", persistent)

	noVolData := kubeletVolume(t, podsDir, "pod-no-vol-data", nil)

	malformed := kubeletVolume(t, podsDir, "pod-malformed", nil)
	g.Expect(os.WriteFile(filepath.Join(filepath.Dir(malformed), kubeletVolDataFile), []byte("{"), 0o644)).
		To(Succeed())

	server := &fakeServer{}
	sockets := newPodSockets(server.serve)
	t.Cleanup(sockets.closeAll)

	g.Expect(sockets.restore(podsDir, configuration.WorkloadIdentityCSIDriver)).To(BeZero())
	g.Expect(server.served()).To(BeZero())
	for _, target := range []string{otherTarget, persistentTarget, noVolData, malformed} {
		g.Expect(filepath.Join(target, podSocketName)).ToNot(BeAnExistingFile(),
			"nothing may be created in a volume this driver did not publish")
	}
}

// A volume whose mount directory is gone is being torn down; there is nothing to serve.
func TestRestore_VolumeWithoutItsMountDirectory_IsSkipped(t *testing.T) {
	g := NewWithT(t)

	podsDir := t.TempDir()
	target := kubeletVolume(t, podsDir, "pod-a", ourVolData())
	g.Expect(os.Remove(target)).To(Succeed())

	server := &fakeServer{}
	sockets := newPodSockets(server.serve)
	t.Cleanup(sockets.closeAll)

	g.Expect(sockets.restore(podsDir, configuration.WorkloadIdentityCSIDriver)).To(BeZero())
	g.Expect(target).ToNot(BeADirectory())
}

// One volume that cannot be restored must not cost every other pod on the node its socket.
func TestRestore_OneBadVolume_DoesNotStopTheRest(t *testing.T) {
	g := NewWithT(t)

	podsDir := t.TempDir()
	bad := kubeletVolume(t, podsDir, "pod-bad", ourVolData())
	g.Expect(os.WriteFile(filepath.Join(bad, podSocketName), []byte("not a socket"), 0o600)).To(Succeed())
	good := kubeletVolume(t, podsDir, "pod-good", ourVolData())

	server := &fakeServer{}
	sockets := newPodSockets(server.serve)
	t.Cleanup(sockets.closeAll)

	g.Expect(sockets.restore(podsDir, configuration.WorkloadIdentityCSIDriver)).To(Equal(1))
	g.Expect(dialGreeting(podView(t, good))).To(Equal(greeting))
}

// The files stay for the next run to replace. A pod dialling in between is refused, which a
// SPIFFE client retries.
func TestCloseAll_PublishedSockets_StopServingAndStayOnDisk(t *testing.T) {
	g := NewWithT(t)

	target := filepath.Join(t.TempDir(), "mount")
	g.Expect(os.MkdirAll(target, targetPathMode)).To(Succeed())

	server := &fakeServer{}
	sockets := newPodSockets(server.serve)
	created, err := sockets.publish(target)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(created).To(BeTrue())

	sockets.closeAll()

	info, err := os.Lstat(filepath.Join(target, podSocketName))
	g.Expect(err).ToNot(HaveOccurred(), "closeAll must leave the socket file in place")
	g.Expect(info.Mode().Type()).To(Equal(os.ModeSocket))

	_, err = dialGreeting(podView(t, target))
	g.Expect(errors.Is(err, syscall.ECONNREFUSED)).To(BeTrue(), "got %v", err)
	g.Eventually(server.stoppedCount).Should(Equal(1))
}

// A forced stop does not wait for in-flight handlers, so a publish can arrive after
// closeAll; it must not leave a socket served by a server that is going away.
func TestPublish_AfterCloseAll_IsRefused(t *testing.T) {
	g := NewWithT(t)

	target := filepath.Join(t.TempDir(), "mount")
	g.Expect(os.MkdirAll(target, targetPathMode)).To(Succeed())

	server := &fakeServer{}
	sockets := newPodSockets(server.serve)
	sockets.closeAll()

	_, err := sockets.publish(target)
	g.Expect(err).To(MatchError(errPodSocketsClosed))
	g.Expect(server.served()).To(BeZero())
}

// The listener reports the target rather than the /proc/self/fd address it is bound to,
// whose descriptor number is reused across pods.
func TestPublish_ServedListener_ReportsTheTargetAsItsAddress(t *testing.T) {
	g := NewWithT(t)

	target := filepath.Join(t.TempDir(), "mount")
	g.Expect(os.MkdirAll(target, targetPathMode)).To(Succeed())

	server := &fakeServer{}
	sockets := newPodSockets(server.serve)
	t.Cleanup(sockets.closeAll)
	_, err := sockets.publish(target)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(server.listeners[0].Addr().String()).To(Equal(filepath.Join(target, podSocketName)))
}

// A bind that fails must not leak the directory it opened: the kubelet retries a failed
// publish every few seconds. Run as non-root, since root bypasses the mode.
func TestPublish_UnwritableTarget_FailsWithoutLeakingADescriptor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory mode this test relies on")
	}
	g := NewWithT(t)

	target := filepath.Join(t.TempDir(), "mount")
	g.Expect(os.MkdirAll(target, 0o555)).To(Succeed())

	server := &fakeServer{}
	sockets := newPodSockets(server.serve)
	t.Cleanup(sockets.closeAll)

	before := openDescriptors(t)
	_, err := sockets.publish(target)
	g.Expect(err).To(HaveOccurred())
	g.Expect(openDescriptors(t)).To(Equal(before))
	g.Expect(server.served()).To(BeZero())
}

func openDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("listing /proc/self/fd: %v", err)
	}
	return len(entries)
}
