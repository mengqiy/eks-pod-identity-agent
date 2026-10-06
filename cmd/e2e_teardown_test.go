package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	spiffeworkloadapi "github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
)

const (
	// teardownRuns is how many agents the repeated start and stop runs.
	teardownRuns = 10
	// teardownGoroutineSlack is how far the settled goroutine count may end above
	// its baseline: room for process-wide goroutines the first agent starts, such
	// as os/signal's loop, and well below one goroutine leaked per agent.
	teardownGoroutineSlack = 3
	// teardownStopBound is how long a shutdown with a stream open may take: the
	// drain budget, then the forced stop's two seconds, with a second to spare.
	teardownStopBound = grpcserver.DefaultShutdownWait + 3*time.Second
)

// TestE2E_Teardown_RepeatedStartAndStopLeaksNoGoroutine runs ten agents in turn,
// each serving a go-spiffe X509Source, and asserts the settled goroutine count
// returns to its baseline. An expiring cache stops its janitor only from a
// finalizer, which a registered callback keeps from running by holding the cache
// the janitor reaches, so the harness disables both the token and certificate sweeps.
func TestE2E_Teardown_RepeatedStartAndStopLeaksNoGoroutine(t *testing.T) {
	g := NewWithT(t)
	baseline := settledGoroutines()

	for i := range teardownRuns {
		ok := t.Run(fmt.Sprintf("agent-%d", i), func(t *testing.T) {
			g := NewWithT(t)
			h := newE2EHarness(t)

			source, err := spiffeworkloadapi.NewX509Source(h.ctx(),
				spiffeworkloadapi.WithClientOptions(spiffeworkloadapi.WithAddr("unix://"+h.path)))
			g.Expect(err).ToNot(HaveOccurred())
			svid, err := source.GetX509SVID()
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(svid.ID.String()).To(Equal(e2eSpiffeID))
			g.Expect(source.Close()).To(Succeed())
		})
		if !ok {
			t.FailNow()
		}
	}

	g.Eventually(settledGoroutines, e2eWait).Should(BeNumerically("<=", baseline+teardownGoroutineSlack), func() string {
		return fmt.Sprintf("%d goroutines before %d agents, %d after, which are:\n%s",
			baseline, teardownRuns, settledGoroutines(), teardownGoroutines())
	})
}

// TestE2E_Teardown_ShutdownWithAStreamOpenEndsItWithinTheDrainBudget stops the
// agent under a go-spiffe watch. A GOAWAY does not end a push stream, so the drain
// runs out and the forced stop ends it: the agent returns within the budget, the
// watcher hears the stream end as Unavailable, and the socket is gone.
func TestE2E_Teardown_ShutdownWithAStreamOpenEndsItWithinTheDrainBudget(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)

	feed := h.watchX509Context(h.client())
	g.Expect(feed.next(g, "the first X.509 context").DefaultSVID().ID.String()).To(Equal(e2eSpiffeID))

	start := time.Now()
	h.stop()
	g.Expect(time.Since(start)).To(BeNumerically("<", teardownStopBound),
		"the agent's shutdown is not bounded by the drain budget with a stream open")

	var streamErr error
	g.Eventually(feed.errs, e2eWait).Should(Receive(&streamErr), "the stream outlived the agent")
	g.Expect(status.Code(streamErr)).To(Equal(codes.Unavailable), "the stream ended with %v", streamErr)
	_, err := os.Lstat(h.path)
	g.Expect(err).To(MatchError(fs.ErrNotExist), "the agent left its socket behind")
}

// TestE2E_Teardown_ShutdownRemovesTheSocket asserts the agent, and not the
// harness's cleanup, unlinks the socket it served on: once h.stop returns, and
// before the cleanup removes the directory, the socket is gone and its directory
// is not.
func TestE2E_Teardown_ShutdownRemovesTheSocket(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)

	_, err := h.client().FetchX509Context(h.ctx())
	g.Expect(err).ToNot(HaveOccurred())
	info, err := os.Lstat(h.path)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(info.Mode().Type()).To(Equal(fs.ModeSocket))

	h.stop()

	_, err = os.Lstat(h.path)
	g.Expect(err).To(MatchError(fs.ErrNotExist), "the agent left its socket behind")
	dir, err := os.Lstat(filepath.Dir(h.path))
	g.Expect(err).ToNot(HaveOccurred(), "the socket directory is gone before the harness's cleanup")
	g.Expect(dir.IsDir()).To(BeTrue())
}

// teardownGoroutines is every goroutine's stack, grouped, for a failure message.
func teardownGoroutines() string {
	var b strings.Builder
	_ = pprof.Lookup("goroutine").WriteTo(&b, 1)
	return b.String()
}
