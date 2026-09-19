package attestation

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// fakePeer is an injected peerConn. It records recheck against a shared event
// sink so a test can assert recheck runs after pod resolution, and lets a test
// force a recheck failure without a real process to kill.
type fakePeer struct {
	fakePID    int
	recheckErr error
	closed     bool
	events     *[]string
}

func (f *fakePeer) pid() int { return f.fakePID }

func (f *fakePeer) recheck() error {
	if f.events != nil {
		*f.events = append(*f.events, "recheck")
	}
	return f.recheckErr
}

func (f *fakePeer) close() error {
	f.closed = true
	return nil
}

// fakePods is an injected PodGetter. It records each lookup against the shared
// event sink.
type fakePods struct {
	byUID  map[string]*PodInfo
	events *[]string
}

func (f *fakePods) PodByUID(uid string) (*PodInfo, bool) {
	if f.events != nil {
		*f.events = append(*f.events, "resolve")
	}
	p, ok := f.byUID[uid]
	return p, ok
}

// fakeCgroup is an injected CgroupResolver returning a fixed UID or error,
// ignoring the PID.
type fakeCgroup struct {
	uid string
	err error
}

func (f *fakeCgroup) PodUIDForPID(int) (string, error) { return f.uid, f.err }

// staticPeer returns a newPeer function that always yields peer, or err when
// peer is nil.
func staticPeer(peer peerConn, err error) func(net.Conn) (peerConn, error) {
	return func(net.Conn) (peerConn, error) {
		if err != nil {
			return nil, err
		}
		return peer, nil
	}
}

const (
	testNode   = "ip-10-0-1-23.us-west-2.compute.internal"
	testPodUID = "4e8f8d3a-9c3d-4b7e-8f2a-1c2d3e4f5a6b"
)

func knownPod(node string) *PodInfo {
	return &PodInfo{
		UID:            testPodUID,
		Name:           "web-0",
		Namespace:      "team-a",
		ServiceAccount: "web",
		NodeName:       node,
	}
}

// TestAttest_KnownPod_ReturnsPopulatedWorkload proves the happy path fills every
// Workload field and closes the peer handle.
func TestAttest_KnownPod_ReturnsPopulatedWorkload(t *testing.T) {
	g := NewWithT(t)

	peer := &fakePeer{fakePID: 4242}
	att := newAttestor(testNode,
		&fakePods{byUID: map[string]*PodInfo{testPodUID: knownPod(testNode)}},
		&fakeCgroup{uid: testPodUID},
		staticPeer(peer, nil))

	w, err := att.Attest(context.Background(), nil)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(w.PodUID).To(Equal(testPodUID))
	g.Expect(w.PodName).To(Equal("web-0"))
	g.Expect(w.Namespace).To(Equal("team-a"))
	g.Expect(w.ServiceAccount).To(Equal("web"))
	g.Expect(w.NodeName).To(Equal(testNode))
	g.Expect(peer.closed).To(BeTrue(), "the peer handle must be closed after attestation")
}

// TestAttest_RechecksAfterResolution asserts ordering rather than outcome: the
// liveness recheck must run after the pod has been resolved, since a recheck
// before resolution proves nothing about the window that matters.
func TestAttest_RechecksAfterResolution(t *testing.T) {
	g := NewWithT(t)

	var events []string
	peer := &fakePeer{fakePID: 4242, events: &events}
	att := newAttestor(testNode,
		&fakePods{byUID: map[string]*PodInfo{testPodUID: knownPod(testNode)}, events: &events},
		&fakeCgroup{uid: testPodUID},
		staticPeer(peer, nil))

	_, err := att.Attest(context.Background(), nil)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(events).To(Equal([]string{"resolve", "recheck"}),
		"recheck must run after pod resolution, not before")
}

// TestAttest_RefusalPaths covers every refusal reachable through the injected
// seams, asserting each returns ErrUnattestable and names its reason.
func TestAttest_RefusalPaths(t *testing.T) {
	testCases := []struct {
		name    string
		pods    *fakePods
		cgroup  *fakeCgroup
		peer    peerConn
		peerErr error
		reason  string
	}{
		{
			name:    "not a unix socket",
			peerErr: errNotUnixSocket,
			reason:  workloadidentity.ReasonNotUnixSocket,
		},
		{
			name:    "peer pid zero (no hostPID)",
			peerErr: errPeerPIDZero,
			reason:  workloadidentity.ReasonPeerPIDZero,
		},
		{
			name:    "peer gone before resolution",
			peerErr: errPeerGone,
			reason:  workloadidentity.ReasonPeerGone,
		},
		{
			name:   "cgroup carries no pod uid",
			peer:   &fakePeer{fakePID: 1},
			cgroup: &fakeCgroup{err: ErrNoPodUID},
			reason: workloadidentity.ReasonCgroupNoPodUID,
		},
		{
			name:   "cgroup read fails (process gone)",
			peer:   &fakePeer{fakePID: 1},
			cgroup: &fakeCgroup{err: os.ErrNotExist},
			reason: workloadidentity.ReasonPeerGone,
		},
		{
			name:   "pod not in node store",
			peer:   &fakePeer{fakePID: 1},
			cgroup: &fakeCgroup{uid: testPodUID},
			pods:   &fakePods{byUID: map[string]*PodInfo{}},
			reason: workloadidentity.ReasonPodNotInStore,
		},
		{
			name:   "pod bound to another node",
			peer:   &fakePeer{fakePID: 1},
			cgroup: &fakeCgroup{uid: testPodUID},
			pods:   &fakePods{byUID: map[string]*PodInfo{testPodUID: knownPod("some-other-node")}},
			reason: workloadidentity.ReasonPodNodeMismatch,
		},
		{
			name:   "liveness recheck fails after resolution",
			peer:   &fakePeer{fakePID: 1, recheckErr: errLivenessRecheckFailed},
			cgroup: &fakeCgroup{uid: testPodUID},
			pods:   &fakePods{byUID: map[string]*PodInfo{testPodUID: knownPod(testNode)}},
			reason: workloadidentity.ReasonLivenessRecheckFailed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			pods := tc.pods
			if pods == nil {
				pods = &fakePods{byUID: map[string]*PodInfo{}}
			}
			cgroup := tc.cgroup
			if cgroup == nil {
				cgroup = &fakeCgroup{}
			}
			att := newAttestor(testNode, pods, cgroup, staticPeer(tc.peer, tc.peerErr))

			w, err := att.Attest(context.Background(), nil)

			g.Expect(w).To(BeNil())
			g.Expect(err).To(MatchError(wierrors.ErrUnattestable),
				"every refusal returns the ErrUnattestable taxonomy member")
			g.Expect(err.Error()).To(ContainSubstring(tc.reason),
				"the refusal names its reason")
		})
	}
}

// TestAttest_NodeMismatch_CountsOwnMetric proves the security-relevant refusal
// increments its own reason series, which is what an operator alarms on.
func TestAttest_NodeMismatch_CountsOwnMetric(t *testing.T) {
	g := NewWithT(t)

	before := testutil.ToFloat64(
		promAttestationTotal.WithLabelValues(workloadidentity.OutcomeFailure, workloadidentity.ReasonPodNodeMismatch))

	att := newAttestor(testNode,
		&fakePods{byUID: map[string]*PodInfo{testPodUID: knownPod("some-other-node")}},
		&fakeCgroup{uid: testPodUID},
		staticPeer(&fakePeer{fakePID: 1}, nil))

	_, err := att.Attest(context.Background(), nil)
	g.Expect(err).To(HaveOccurred())

	after := testutil.ToFloat64(
		promAttestationTotal.WithLabelValues(workloadidentity.OutcomeFailure, workloadidentity.ReasonPodNodeMismatch))
	g.Expect(after - before).To(Equal(1.0))
}

// TestAttest_RealUnixSocket_AttestsSelf drives the real peer-credential path
// over a real Unix socket, with the test process as its own peer. Only the
// cgroup and pod store are faked, so SO_PEERCRED, the /proc handle and the
// recheck all run for real.
func TestAttest_RealUnixSocket_AttestsSelf(t *testing.T) {
	g := NewWithT(t)

	conn, cleanup := selfConnectedUnixConn(t)
	defer cleanup()

	att := New(testNode,
		&fakePods{byUID: map[string]*PodInfo{testPodUID: knownPod(testNode)}},
		&fakeCgroup{uid: testPodUID})

	w, err := att.Attest(context.Background(), conn)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(w.PodUID).To(Equal(testPodUID))
	g.Expect(w.NodeName).To(Equal(testNode))
}

// TestAttest_NonUnixConn_RefusedNotPanic proves the real peer reader refuses a
// non-Unix connection through the taxonomy rather than panicking on the type
// assertion.
func TestAttest_NonUnixConn_RefusedNotPanic(t *testing.T) {
	g := NewWithT(t)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	att := New(testNode, &fakePods{byUID: map[string]*PodInfo{}}, &fakeCgroup{})

	_, err := att.Attest(context.Background(), c1)

	g.Expect(err).To(MatchError(wierrors.ErrUnattestable))
	g.Expect(err.Error()).To(ContainSubstring(workloadidentity.ReasonNotUnixSocket))
}

// TestAttest_PeerExited_Refused forks a child that connects and exits, then
// attests the accepted connection. The peer is gone by the time the agent
// resolves it, so it must be refused rather than attested.
func TestAttest_PeerExited_Refused(t *testing.T) {
	g := NewWithT(t)

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "exit.sock")
	ln, err := net.Listen("unix", sockPath)
	g.Expect(err).NotTo(HaveOccurred())
	defer ln.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	accepts := make(chan accepted, 1)
	go func() {
		c, e := ln.Accept()
		accepts <- accepted{c, e}
	}()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperConnectAndExit")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER=1", "ATTEST_HELPER_SOCK="+sockPath)
	g.Expect(cmd.Start()).To(Succeed())

	got := <-accepts
	g.Expect(got.err).NotTo(HaveOccurred())
	defer got.conn.Close()

	// Reap the child so its /proc entry is gone before we resolve it.
	g.Expect(cmd.Wait()).To(Succeed())

	att := New(testNode,
		&fakePods{byUID: map[string]*PodInfo{testPodUID: knownPod(testNode)}},
		&fakeCgroup{uid: testPodUID})

	_, err = att.Attest(context.Background(), got.conn)
	g.Expect(err).To(MatchError(wierrors.ErrUnattestable),
		"a peer that has exited must be refused")
}

// TestHelperConnectAndExit is the child process for TestAttest_PeerExited_Refused.
// It connects to the socket and exits immediately. It is inert unless launched
// with GO_WANT_HELPER=1, so it is a no-op in a normal test run.
func TestHelperConnectAndExit(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER") != "1" {
		return
	}
	c, err := net.Dial("unix", os.Getenv("ATTEST_HELPER_SOCK"))
	if err != nil {
		os.Exit(2)
	}
	_ = c.Close()
	os.Exit(0)
}

// selfConnectedUnixConn returns the server side of a Unix socket connected to by
// this same process, so SO_PEERCRED reports the test process. It blocks briefly
// on accept, which is fine for a unit test.
func selfConnectedUnixConn(t *testing.T) (net.Conn, func()) {
	t.Helper()
	g := NewWithT(t)

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "self.sock")
	ln, err := net.Listen("unix", sockPath)
	g.Expect(err).NotTo(HaveOccurred())

	type accepted struct {
		conn net.Conn
		err  error
	}
	accepts := make(chan accepted, 1)
	go func() {
		c, e := ln.Accept()
		accepts <- accepted{c, e}
	}()

	client, err := net.Dial("unix", sockPath)
	g.Expect(err).NotTo(HaveOccurred())

	var got accepted
	select {
	case got = <-accepts:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out accepting self connection")
	}
	g.Expect(got.err).NotTo(HaveOccurred())

	return got.conn, func() {
		_ = got.conn.Close()
		_ = client.Close()
		_ = ln.Close()
	}
}
