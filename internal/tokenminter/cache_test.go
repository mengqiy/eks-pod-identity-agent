package tokenminter

import (
	"context"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// fakeRawMinter is a rawMinter that counts calls and returns a canned token or
// error, or defers to a func. An optional block channel parks each call so a
// test can hold mints in flight to exercise single-flight.
type fakeRawMinter struct {
	mu    sync.Mutex
	calls int

	token *workloadidentity.ProjectedToken
	err   error
	fn    func(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error)
	block chan struct{}
}

func (f *fakeRawMinter) mint(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	f.calls++
	fn, tok, err := f.fn, f.token, f.err
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, w)
	}
	return tok, err
}

func (f *fakeRawMinter) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// clockAt returns a clock whose value the test can advance.
func clockAt(t *time.Time) func() time.Time {
	return func() time.Time { return *t }
}

// newTestMinter builds a CachedMinter over the fake with the janitor disabled,
// so a test drives expiry through the injected clock and invokes onRefresh
// directly rather than racing the background sweep.
func newTestMinter(raw rawMinter, now func() time.Time) *CachedMinter {
	return newCachedMinter(raw, CachedMinterOpts{
		CleanupInterval: -1,
		now:             now,
	})
}

// TestMint_Miss_MintsAndCaches proves the first mint for a pod calls the API and
// returns the token.
func TestMint_Miss_MintsAndCaches(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	raw := &fakeRawMinter{token: &workloadidentity.ProjectedToken{Token: "t1", ExpiresAt: clock.Add(time.Hour)}}
	m := newTestMinter(raw, clockAt(&clock))

	got, err := m.Mint(context.Background(), testWorkload())

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Token).To(Equal("t1"))
	g.Expect(raw.callCount()).To(Equal(1))
}

// TestMint_CachedAmpleLife_Reused proves a second lookup while the cached token
// has ample life is served from cache without a second API call.
func TestMint_CachedAmpleLife_Reused(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	raw := &fakeRawMinter{token: &workloadidentity.ProjectedToken{Token: "t1", ExpiresAt: clock.Add(time.Hour)}}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	_, err := m.Mint(context.Background(), w)
	g.Expect(err).NotTo(HaveOccurred())

	// Advance a little, still well within the token's life.
	clock = clock.Add(time.Minute)

	got, err := m.Mint(context.Background(), w)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Token).To(Equal("t1"))
	g.Expect(raw.callCount()).To(Equal(1), "cache hit must not mint again")
}

// TestMint_CachedNearExpiry_Reminted proves a cached token with less than the
// minimum remaining life is re-minted rather than served.
func TestMint_CachedNearExpiry_Reminted(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	raw := &fakeRawMinter{fn: func(_ context.Context, _ *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
		return &workloadidentity.ProjectedToken{Token: "fresh", ExpiresAt: clock.Add(time.Hour)}, nil
	}}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	_, err := m.Mint(context.Background(), w)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(raw.callCount()).To(Equal(1))

	// Advance to within the 15s floor of the first token's expiry.
	clock = clock.Add(time.Hour - 5*time.Second)

	got, err := m.Mint(context.Background(), w)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Token).To(Equal("fresh"))
	g.Expect(raw.callCount()).To(Equal(2), "near-expiry token must be re-minted")
}

// TestMint_TooShortLived_Rejected proves a freshly minted token with too little
// life is a failed mint and is not cached.
func TestMint_TooShortLived_Rejected(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	raw := &fakeRawMinter{token: &workloadidentity.ProjectedToken{Token: "brief", ExpiresAt: clock.Add(5 * time.Second)}}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	_, err := m.Mint(context.Background(), w)
	g.Expect(err).To(MatchError(wierrors.ErrTokenMintFailed))

	_, ok := m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeFalse(), "a too-short token must not be cached")
}

// TestMint_NilWorkload_Errors proves an empty workload is refused before any API
// call.
func TestMint_NilWorkload_Errors(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	raw := &fakeRawMinter{}
	m := newTestMinter(raw, clockAt(&clock))

	_, err := m.Mint(context.Background(), &workloadidentity.Workload{})

	g.Expect(err).To(MatchError(wierrors.ErrTokenMintFailed))
	g.Expect(raw.callCount()).To(Equal(0))
}

// TestMint_Concurrent_SingleFlight proves concurrent lookups for one pod, such
// as an X.509 and a JWT stream opening at once, collapse onto a single mint.
func TestMint_Concurrent_SingleFlight(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	raw := &fakeRawMinter{
		token: &workloadidentity.ProjectedToken{Token: "shared", ExpiresAt: clock.Add(time.Hour)},
		block: make(chan struct{}),
	}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	const n = 8
	results := make(chan *workloadidentity.ProjectedToken, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			tok, err := m.Mint(context.Background(), w)
			results <- tok
			errs <- err
		}()
	}

	// Give every goroutine time to reach the shared singleflight call, then
	// release the one in-flight mint.
	time.Sleep(100 * time.Millisecond)
	close(raw.block)

	for i := 0; i < n; i++ {
		g.Expect(<-errs).NotTo(HaveOccurred())
		g.Expect(<-results).To(Equal(raw.token))
	}
	g.Expect(raw.callCount()).To(Equal(1), "concurrent lookups must share one mint")
}

// TestOnRefresh_Success_UpdatesCache proves a background refresh re-mints and
// replaces the cached token.
func TestOnRefresh_Success_UpdatesCache(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	current := "first"
	raw := &fakeRawMinter{fn: func(_ context.Context, _ *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
		return &workloadidentity.ProjectedToken{Token: current, ExpiresAt: clock.Add(time.Hour)}, nil
	}}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	_, err := m.Mint(context.Background(), w)
	g.Expect(err).NotTo(HaveOccurred())

	current = "second"
	entry, ok := m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeTrue())
	m.onRefresh(w.PodUID, entry)

	refreshed, ok := m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeTrue())
	g.Expect(refreshed.token.Token).To(Equal("second"))
	g.Expect(raw.callCount()).To(Equal(2))
}

// TestOnRefresh_Forbidden_DropsEntry proves a non-retryable refresh failure
// evicts the entry rather than keeping a token that can never be renewed.
func TestOnRefresh_Forbidden_DropsEntry(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	calls := 0
	raw := &fakeRawMinter{fn: func(_ context.Context, _ *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
		calls++
		if calls == 1 {
			return &workloadidentity.ProjectedToken{Token: "first", ExpiresAt: clock.Add(time.Hour)}, nil
		}
		return nil, wierrors.ErrTokenMintForbidden
	}}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	_, err := m.Mint(context.Background(), w)
	g.Expect(err).NotTo(HaveOccurred())

	entry, ok := m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeTrue())
	m.onRefresh(w.PodUID, entry)

	_, ok = m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeFalse(), "a forbidden renewal must drop the entry")
}

// TestOnRefresh_RetryableFailure_KeepsToken proves a transient refresh failure
// leaves the existing token in place rather than dropping a live credential.
func TestOnRefresh_RetryableFailure_KeepsToken(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	calls := 0
	raw := &fakeRawMinter{fn: func(_ context.Context, _ *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
		calls++
		if calls == 1 {
			return &workloadidentity.ProjectedToken{Token: "first", ExpiresAt: clock.Add(time.Hour)}, nil
		}
		return nil, wierrors.ErrTokenMintFailed
	}}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	_, err := m.Mint(context.Background(), w)
	g.Expect(err).NotTo(HaveOccurred())

	entry, ok := m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeTrue())
	m.onRefresh(w.PodUID, entry)

	kept, ok := m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeTrue(), "a transient renewal failure must keep the existing token")
	g.Expect(kept.token.Token).To(Equal("first"))
}
