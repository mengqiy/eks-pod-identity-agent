package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	spiffeworkloadapi "github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clocktesting "k8s.io/utils/clock/testing"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/attestation"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts/ststest"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

// The end-to-end harness stands the workload identity feature up as cmd wires
// it, through buildWorkloadIdentityTiers and serveWorkloadIdentity, against fakes
// at its edges: client-go's fake clientset for the API server, ststest for STS at
// the wire, and a stand-in for the session tier until T5 lands. The test process
// is the pod: SO_PEERCRED, the /proc pin and the liveness recheck run for real,
// and only the cgroup lookup is faked. One fake clock drives the bundle and
// X.509-SVID tiers, the session stand-in and the STS fake, so no scenario sleeps
// to wait for a renewal or a rotation.

// e2ePodSpec is one pod the harness knows and the identity STS issues it.
type e2ePodSpec struct {
	uid, name, namespace, serviceAccount string
	spiffeID                             spiffeid.ID
}

var (
	// e2ePodA is the pod the test process attests as by default, and e2ePodB a
	// second one it can attest as through h.as, so two workloads share the agent.
	e2ePodA = e2ePodSpec{"4e8f8d3a-9c3d-4b7e-8f2a-1c2d3e4f5a6b", "web-0", "team-a", "web", spiffeid.RequireFromString(e2eSpiffeID)}
	e2ePodB = e2ePodSpec{"7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", "api-0", "team-b", "api", spiffeid.RequireFromString("spiffe://example.org/ns/team-b/sa/api")}
)

const (
	// e2ePodUID, e2ePodName, e2eNamespace and e2eServiceAccount name e2ePodA.
	e2ePodUID         = "4e8f8d3a-9c3d-4b7e-8f2a-1c2d3e4f5a6b"
	e2ePodName        = "web-0"
	e2eNamespace      = "team-a"
	e2eServiceAccount = "web"
	// e2eSpiffeID is the identity the STS fake issues to e2ePodA's sessions.
	e2eSpiffeID = "spiffe://example.org/ns/team-a/sa/web"
	// e2eWait bounds every wait on the agent.
	e2eWait = 10 * time.Second
	// e2eQuiet is how long a test watches for something that must not happen.
	e2eQuiet = 300 * time.Millisecond
	// e2eRenewalStep is past the renewal point of any 12h certificate at
	// fraction 0.5 with jitter 0.1, which falls between 5h24m and 6h36m.
	e2eRenewalStep = 7 * time.Hour
)

// e2eConfig is what a scenario may change before the agent starts.
type e2eConfig struct {
	// sts configures the STS fake. Now is always the harness clock.
	sts ststest.Opts
	// sessionLife is how long each session lasts. Zero means an hour.
	sessionLife time.Duration
}

// e2eHarness is one agent and the fakes around it. Everything is torn down by
// t.Cleanup, the agent before the fakes; stop shuts the agent down earlier.
type e2eHarness struct {
	t        *testing.T
	clock    *clocktesting.FakeClock
	sts      *ststest.Server
	kube     *wiNodeClientset
	cgroup   *e2eCgroup
	sessions *fake.SessionProvider
	passes   *e2ePasses
	tiers    *workloadIdentityTiers
	// path is the workload identity socket.
	path string

	stopOnce sync.Once
	cancel   context.CancelFunc
	stopped  chan struct{}

	sessionMu   sync.Mutex
	enrolled    []e2ePodSpec
	sessionLife time.Duration
	current     map[string]*workloadidentity.WorkloadSession
	issuedKeys  map[string][]string
	sessionErr  atomic.Pointer[error]
}

// newE2EHarness builds the fakes, lets configure adjust them, then starts the
// agent and returns once its socket is bound and its pod store has synced.
func newE2EHarness(t *testing.T, configure ...func(*e2eConfig)) *e2eHarness {
	t.Helper()

	// Real time, truncated to the second, so certificates the fakes issue are
	// valid for a TLS handshake that checks the wall clock until a step.
	clock := clocktesting.NewFakeClock(time.Now().Truncate(time.Second))
	cfg := e2eConfig{sts: ststest.Opts{RefreshHint: time.Minute}}
	for _, c := range configure {
		c(&cfg)
	}
	cfg.sts.Now = clock.Now
	if cfg.sessionLife == 0 {
		cfg.sessionLife = time.Hour
	}

	h := &e2eHarness{
		t: t, clock: clock, cgroup: &e2eCgroup{}, passes: newE2EPasses(),
		enrolled:    []e2ePodSpec{e2ePodA, e2ePodB},
		sessionLife: cfg.sessionLife,
		current:     map[string]*workloadidentity.WorkloadSession{},
		issuedKeys:  map[string][]string{},
	}
	h.as(e2ePodA)
	h.sts = ststest.New(t, cfg.sts)
	h.kube = newWINodeClientset("system:node:" + wiTestNode)
	for _, pod := range []e2ePodSpec{e2ePodA, e2ePodB} {
		if err := h.kube.Tracker().Add(pod.object()); err != nil {
			t.Fatalf("seeding pod %s: %v", pod.name, err)
		}
	}
	h.sessions = &fake.SessionProvider{Func: h.session}

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	tiers, err := buildWorkloadIdentityTiers(ctx, wiOpts, tierDeps{
		clientset:  h.kube,
		sts:        sts.NewService(h.sts.Config()),
		cgroup:     h.cgroup,
		sessions:   h.sessions,
		now:        clock.Now,
		after:      h.passes.After,
		certSweep:  -1,
		tokenSweep: -1,
	})
	if err != nil {
		cancel()
		t.Fatalf("building the tiers: %v", err)
	}
	h.tiers = tiers

	dir, err := os.MkdirTemp("", "e2e")
	if err != nil {
		cancel()
		t.Fatalf("creating a socket directory: %v", err)
	}
	h.path = filepath.Join(dir, "agent.sock")
	server, err := serveWorkloadIdentity(tiers, h.path)
	if err != nil {
		cancel()
		t.Fatalf("serving the socket: %v", err)
	}
	servers := []runnable{server, backgroundLoop{name: "trust-bundle-refresh", run: tiers.bundleSource.Run}}
	h.stopped = make(chan struct{})
	go func() {
		defer close(h.stopped)
		runServersUntilShutdown(ctx, servers)
	}()
	t.Cleanup(func() {
		h.stop()
		_ = os.RemoveAll(dir)
	})
	return h
}

// stop shuts the agent down and waits for every server and loop to return,
// failing the test if that takes longer than e2eWait. Calling it again is a no-op.
func (h *e2eHarness) stop() {
	h.stopOnce.Do(func() {
		h.cancel()
		select {
		case <-h.stopped:
		case <-time.After(e2eWait):
			h.t.Errorf("the agent did not stop within %s", e2eWait)
		}
	})
}

// object is the pod as the API server holds it. The fake clientset applies no
// defaults, so every field the attestor reads is set.
func (p e2ePodSpec) object() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID(p.uid), Name: p.name, Namespace: p.namespace},
		Spec:       corev1.PodSpec{NodeName: wiTestNode, ServiceAccountName: p.serviceAccount},
	}
}

// e2ePod is e2ePodA as the API server holds it.
func e2ePod() *corev1.Pod {
	return e2ePodA.object()
}

// as makes the test process attest as pod from now on. Attestation runs when a
// stream opens and on every unary call, so a stream already open keeps its pod.
func (h *e2eHarness) as(pod e2ePodSpec) {
	h.cgroup.uid.Store(pod.uid)
}

// session stands in for the session tier: each known pod gets credentials the
// STS fake knows as its identity, expiring after sessionLife by the clock, and new
// ones once they have, as the real tier refreshes.
func (h *e2eHarness) session(_ context.Context, w *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error) {
	if err := h.sessionErr.Load(); err != nil {
		return nil, *err
	}
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	var pod *e2ePodSpec
	for _, p := range h.enrolled {
		if p.uid == w.PodUID {
			pod = &p
		}
	}
	if pod == nil {
		return nil, wierrors.ErrNotEnrolled.Wrapf(nil, "the harness knows no session for pod %s", w.PodUID)
	}
	now := h.clock.Now()
	if s := h.current[pod.uid]; s != nil && now.Before(s.ExpiresAt) {
		return s, nil
	}
	creds := aws.Credentials{
		AccessKeyID:     fmt.Sprintf("ASIAE2E%s%d", pod.name[:3], len(h.issuedKeys[pod.uid])),
		SecretAccessKey: "secret-" + pod.uid,
		SessionToken:    "token-" + pod.uid,
		CanExpire:       true,
		Expires:         now.Add(h.sessionLife),
	}
	h.sts.Register(creds, pod.spiffeID)
	s := &workloadidentity.WorkloadSession{Credentials: creds, ProviderArn: h.sts.ProviderArn(), ExpiresAt: creds.Expires}
	h.current[pod.uid] = s
	h.issuedKeys[pod.uid] = append(h.issuedKeys[pod.uid], creds.AccessKeyID)
	return s, nil
}

// enroll gives pod sessions from now on, as an association created for it would.
// It does not add the pod to the API server; a test does that when it chooses.
func (h *e2eHarness) enroll(pod e2ePodSpec) {
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	h.enrolled = append(h.enrolled, pod)
}

// failSessions makes every session request fail with err, or succeed again when
// err is nil.
func (h *e2eHarness) failSessions(err error) {
	if err == nil {
		h.sessionErr.Store(nil)
		return
	}
	h.sessionErr.Store(&err)
}

// accessKeys are the access key IDs of every session issued to pod, oldest first.
func (h *e2eHarness) accessKeys(pod e2ePodSpec) []string {
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	return append([]string(nil), h.issuedKeys[pod.uid]...)
}

// client is a go-spiffe Workload API client on the agent's socket, closed when
// the test ends. Which pod it attests as is decided by h.as when it calls.
func (h *e2eHarness) client() *spiffeworkloadapi.Client {
	h.t.Helper()

	client, err := spiffeworkloadapi.New(h.ctx(), spiffeworkloadapi.WithAddr("unix://"+h.path))
	if err != nil {
		h.t.Fatalf("dialling the agent: %v", err)
	}
	h.t.Cleanup(func() { _ = client.Close() })
	return client
}

// rawClient is the generated Workload API client on the agent's socket, for a
// test that needs status codes go-spiffe does not surface. Use it with rawCtx.
func (h *e2eHarness) rawClient() workload.SpiffeWorkloadAPIClient {
	h.t.Helper()

	conn, err := grpc.NewClient("unix://"+h.path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		h.t.Fatalf("dialling the agent: %v", err)
	}
	h.t.Cleanup(func() { _ = conn.Close() })
	return workload.NewSpiffeWorkloadAPIClient(conn)
}

// rawCtx carries the SPIFFE header the server's gate requires and is bounded by
// e2eWait.
func (h *e2eHarness) rawCtx() context.Context {
	return metadata.AppendToOutgoingContext(h.ctx(), grpcserver.SpiffeSecurityHeader, grpcserver.SpiffeSecurityHeaderValue)
}

// ctx is bounded by e2eWait and cancelled when the test ends.
func (h *e2eHarness) ctx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), e2eWait)
	h.t.Cleanup(cancel)
	return ctx
}

// watchCtx lives until the test ends, for a stream held open across a scenario.
// It is cancelled before the agent stops, since cleanups run last in, first out.
func (h *e2eHarness) watchCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	h.t.Cleanup(cancel)
	return ctx
}

// podWatchStarted reports whether the pod store's watch is registered, after
// which a pod added to the fake clientset reaches the store. The fake has no
// resourceVersion replay, so a pod added before it would be lost.
func (h *e2eHarness) podWatchStarted() bool {
	for _, action := range h.kube.Actions() {
		if action.GetVerb() == "watch" && action.GetResource().Resource == "pods" {
			return true
		}
	}
	return false
}

// e2eCgroup is the one faked step of attestation: it reports uid as the pod of
// the test process, and only of the test process, so it also proves SO_PEERCRED
// named the caller. An empty uid makes the process no pod's.
type e2eCgroup struct {
	uid atomic.Value
}

func (c *e2eCgroup) PodUIDForPID(pid int) (string, error) {
	uid, _ := c.uid.Load().(string)
	if pid != os.Getpid() || uid == "" {
		return "", attestation.ErrNoPodUID
	}
	return uid, nil
}

var _ attestation.CgroupResolver = (*e2eCgroup)(nil)

// e2ePasses is the bundle tier's Opts.After: Run waits on it between refresh
// passes, and pass runs one on demand.
type e2ePasses struct {
	// waiting holds a token while Run is waiting for a pass, and fire starts one.
	waiting chan struct{}
	fire    chan time.Time
}

func newE2EPasses() *e2ePasses {
	return &e2ePasses{waiting: make(chan struct{}, 1), fire: make(chan time.Time)}
}

// After never blocks, so Run still stops when its context ends.
func (p *e2ePasses) After(time.Duration) <-chan time.Time {
	select {
	case p.waiting <- struct{}{}:
	default:
	}
	return p.fire
}

// pass runs one refresh pass, and the idle sweep if it is due, and returns once
// Run is waiting again, so the pass's fetches and notifications have happened.
func (h *e2eHarness) pass() {
	h.t.Helper()

	p := h.passes
	for _, step := range []func(){
		func() { <-p.waiting },
		func() { p.fire <- h.clock.Now() },
		func() { <-p.waiting },
	} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			step()
		}()
		select {
		case <-done:
		case <-time.After(e2eWait):
			h.t.Fatalf("the trust bundle refresh loop is not running")
		}
	}
	p.waiting <- struct{}{}
}

// e2eFeed collects what a go-spiffe watcher is handed, so a test can wait for
// the next update or assert that none comes. A send gives up when the watch's
// context ends, so a stream that sends too much cannot wedge the watch goroutine.
type e2eFeed[T any] struct {
	ctx     context.Context
	updates chan T
	errs    chan error
}

func newE2EFeed[T any](ctx context.Context) *e2eFeed[T] {
	return &e2eFeed[T]{ctx: ctx, updates: make(chan T, 64), errs: make(chan error, 64)}
}

func (f *e2eFeed[T]) push(v T) {
	select {
	case f.updates <- v:
	case <-f.ctx.Done():
	}
}

func (f *e2eFeed[T]) fail(err error) {
	select {
	case f.errs <- err:
	default:
	}
}

// next waits for the stream's next update. A watch error fails at once rather
// than being waited out, which is how a scenario asserts the stream never broke.
func (f *e2eFeed[T]) next(g Gomega, what string) T {
	var v T
	select {
	case v = <-f.updates:
	case err := <-f.errs:
		g.Expect(err).ToNot(HaveOccurred(), "the stream broke waiting for %s", what)
	case <-time.After(e2eWait):
		g.Expect(false).To(BeTrue(), "no %s within %s", what, e2eWait)
	}
	return v
}

// quiet asserts the stream receives nothing, and reports no error, for e2eQuiet.
func (f *e2eFeed[T]) quiet(g Gomega, what string) {
	g.Consistently(func() int { return len(f.updates) + len(f.errs) }, e2eQuiet, 10*time.Millisecond).
		Should(BeZero(), "the stream received something when %s", what)
}

// errors reports the watch errors received so far.
func (f *e2eFeed[T]) errors() int {
	return len(f.errs)
}

type e2eX509ContextWatcher struct {
	*e2eFeed[*spiffeworkloadapi.X509Context]
}

func (w e2eX509ContextWatcher) OnX509ContextUpdate(c *spiffeworkloadapi.X509Context) { w.push(c) }
func (w e2eX509ContextWatcher) OnX509ContextWatchError(err error)                    { w.fail(err) }

type e2eX509BundlesWatcher struct{ *e2eFeed[*x509bundle.Set] }

func (w e2eX509BundlesWatcher) OnX509BundlesUpdate(s *x509bundle.Set) { w.push(s) }
func (w e2eX509BundlesWatcher) OnX509BundlesWatchError(err error)     { w.fail(err) }

type e2eJWTBundlesWatcher struct{ *e2eFeed[*jwtbundle.Set] }

func (w e2eJWTBundlesWatcher) OnJWTBundlesUpdate(s *jwtbundle.Set) { w.push(s) }
func (w e2eJWTBundlesWatcher) OnJWTBundlesWatchError(err error)    { w.fail(err) }

// watch runs a go-spiffe watch on its own goroutine until the test ends, joined
// at cleanup within e2eWait, and returns the feed its watcher fills.
func watch[T any](h *e2eHarness, run func(ctx context.Context, feed *e2eFeed[T]) error) *e2eFeed[T] {
	h.t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	feed := newE2EFeed[T](ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = run(ctx, feed)
	}()
	h.t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(e2eWait):
			h.t.Errorf("a watch did not end within %s of its context", e2eWait)
		}
	})
	return feed
}

// watchX509Context opens a FetchX509SVID stream on client.
func (h *e2eHarness) watchX509Context(client *spiffeworkloadapi.Client) *e2eFeed[*spiffeworkloadapi.X509Context] {
	return watch(h, func(ctx context.Context, feed *e2eFeed[*spiffeworkloadapi.X509Context]) error {
		return client.WatchX509Context(ctx, e2eX509ContextWatcher{feed})
	})
}

// watchX509Bundles opens a FetchX509Bundles stream on client.
func (h *e2eHarness) watchX509Bundles(client *spiffeworkloadapi.Client) *e2eFeed[*x509bundle.Set] {
	return watch(h, func(ctx context.Context, feed *e2eFeed[*x509bundle.Set]) error {
		return client.WatchX509Bundles(ctx, e2eX509BundlesWatcher{feed})
	})
}

// watchJWTBundles opens a FetchJWTBundles stream on client.
func (h *e2eHarness) watchJWTBundles(client *spiffeworkloadapi.Client) *e2eFeed[*jwtbundle.Set] {
	return watch(h, func(ctx context.Context, feed *e2eFeed[*jwtbundle.Set]) error {
		return client.WatchJWTBundles(ctx, e2eJWTBundlesWatcher{feed})
	})
}

// e2eSide is one end of a handshake: the error it ended with, or the peer ID it
// read off the verified connection.
type e2eSide struct {
	err  error
	peer spiffeid.ID
}

// handshake runs one mutual TLS handshake over loopback between a server holding
// server and trusting serverTrust and a client holding client and trusting
// clientTrust. Both authorize any ID, so a refusal is chain verification's, and
// each side reports the peer ID it read. A TLS 1.3 client hears a refusal on read.
func handshake(t *testing.T, server x509svid.Source, serverTrust x509bundle.Source, client x509svid.Source, clientTrust x509bundle.Source) (serverSide, clientSide e2eSide) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer lis.Close()

	served := make(chan e2eSide, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			served <- e2eSide{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(e2eWait))
		tlsConn := tls.Server(conn, tlsconfig.MTLSServerConfig(server, serverTrust, tlsconfig.AuthorizeAny()))
		served <- readPeer(tlsConn, func() error {
			_, err := tlsConn.Write([]byte{1})
			return err
		})
	}()

	conn, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(e2eWait))
	tlsConn := tls.Client(conn, tlsconfig.MTLSClientConfig(client, clientTrust, tlsconfig.AuthorizeAny()))
	clientSide = readPeer(tlsConn, func() error {
		_, err := tlsConn.Read(make([]byte, 1))
		return err
	})
	_ = conn.Close()
	return <-served, clientSide
}

// readPeer completes the handshake and one exchange on conn and reads the peer's
// SPIFFE ID off the verified connection.
func readPeer(conn *tls.Conn, exchange func() error) e2eSide {
	if err := conn.Handshake(); err != nil {
		return e2eSide{err: err}
	}
	if err := exchange(); err != nil {
		return e2eSide{err: err}
	}
	id, err := spiffetls.PeerIDFromConnectionState(conn.ConnectionState())
	return e2eSide{err: err, peer: id}
}

// settledGoroutines is the goroutine count once it stops falling, collecting
// garbage between samples, so goroutines earlier tests left winding down are not
// counted against a leak check.
func settledGoroutines() int {
	last := -1
	for i := 0; i < 50; i++ {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n == last {
			return n
		}
		last = n
		time.Sleep(20 * time.Millisecond)
	}
	return last
}
