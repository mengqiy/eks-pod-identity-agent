package bundle

import (
	"context"
	"errors"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	testingclock "k8s.io/utils/clock/testing"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

// clockStart is years behind the wall clock, so any part of the tier reading
// time.Now instead of Opts.Now gets every due check wrong.
var clockStart = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)

// passDriver is an Opts.After that never fires on its own. Each wait Run starts
// lands on waits, and pass runs one refresh pass.
type passDriver struct {
	waits chan time.Duration
	fire  chan time.Time
}

func newPassDriver() *passDriver {
	return &passDriver{waits: make(chan time.Duration, 1), fire: make(chan time.Time)}
}

func (d *passDriver) After(wait time.Duration) <-chan time.Time {
	d.waits <- wait
	return d.fire
}

// pass runs one refresh pass and returns once Run waits again, so the pass and
// any sweep after it have finished.
func (d *passDriver) pass(g Gomega) {
	g.Eventually(d.fire).Should(BeSent(time.Time{}))
	g.Eventually(d.waits).Should(Receive(Equal(tickInterval)))
}

func TestRegistry_RefreshPassRunByOptsAfter_IsDueByOptsNow(t *testing.T) {
	g := NewWithT(t)
	k1 := jwtECKey(t, "k1", newECKey(t))
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: sequence(
			ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, k1)}),
			ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, k1, jwtECKey(t, "k2", newECKey(t)))}),
		),
	})
	notifier := &fake.Subscriber{}
	clock := testingclock.NewFakeClock(clockStart)
	passes := newPassDriver()
	opts := sessionOpts(fetcher, notifier, newTestSessions())
	opts.Now, opts.After = clock.Now, passes.After
	registry, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		registry.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	g.Eventually(passes.waits).Should(Receive(Equal(tickInterval)))

	_, err = registry.JWTBundles(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())

	// jitter takes up to a tenth off the interval, and never adds to it
	clock.Step(defaultRefreshInterval*9/10 - time.Second)
	passes.pass(g)
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1), "not due before 0.9x the interval")

	clock.SetTime(clockStart.Add(defaultRefreshInterval))
	passes.pass(g)
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(2), "due at the full interval, and fetched once")
	g.Expect(notifier.JWTBundleCalls()).To(Equal(1), "k2 is a real change")
	g.Expect(notifier.CertBundleCalls()).To(BeZero())

	passes.pass(g)
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(2), "the next refresh is scheduled from Opts.Now")
}

func TestRegistry_SourceBackoff_FollowsOptsNow(t *testing.T) {
	g := NewWithT(t)
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: sequence(
			fail(errors.New("STS is down")),
			ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, jwtECKey(t, "k1", newECKey(t)))}),
		),
	})
	clock := testingclock.NewFakeClock(clockStart)
	opts := sessionOpts(fetcher, &fake.Subscriber{}, newTestSessions())
	opts.Now = clock.Now
	registry, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	ctx := context.Background()

	_, err = registry.JWTBundles(ctx, ownPod)
	g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))

	// the first retry waits between 0.9x and the whole of retryBaseDelay
	clock.Step(retryBaseDelay*9/10 - time.Millisecond)
	_, err = registry.JWTBundles(ctx, ownPod)
	g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable), "still inside the backoff")
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1))

	clock.SetTime(clockStart.Add(retryBaseDelay))
	bundles, err := registry.JWTBundles(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred(), "the backoff has passed by Opts.Now")
	g.Expect(bundles).To(HaveKey(testDomain))
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(2))
}

func TestRegistry_Run_StopsOnCancelWhileWaitingOnOptsAfter(t *testing.T) {
	g := NewWithT(t)
	fetcher := newProviderFetcher(nil)
	clock := testingclock.NewFakeClock(clockStart)
	opts := sessionOpts(fetcher, &fake.Subscriber{}, newTestSessions())
	opts.Now, opts.After = clock.Now, clock.After
	registry, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		registry.Run(ctx)
	}()

	g.Eventually(clock.HasWaiters).Should(BeTrue(), "Run waits on Opts.After")
	g.Consistently(done, 50*time.Millisecond).ShouldNot(BeClosed())
	cancel()

	g.Eventually(done).Should(BeClosed())
	g.Expect(fetcher.TotalCalls()).To(BeZero())
}
