package cmd

import (
	"context"
	"crypto"
	cryptox509 "crypto/x509"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	spiffeworkloadapi "github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts/ststest"
)

// The renewal scenarios: what a workload holding an open FetchX509SVID stream
// sees as its certificate is replaced, and what it keeps seeing when STS stops
// issuing. The fake clock moves time and h.tiers.certs.RenewDue() runs the sweep
// the janitor would, so nothing here waits for a renewal. Only the handler's own
// retry backoff is real time, which is why a retry is waited for up to e2eWait.

// TestE2E_Renewal_AnOpenStreamGetsANewLeafWithoutReconnecting advances past the
// renewal point and asserts the replacement reaches the workload on the stream it
// already has: a new leaf, a new key, a later expiry, verifying against the
// published root, with no watch error, one more issuance at STS, and that
// issuance signed with a new session, since the first one expired in the step.
func TestE2E_Renewal_AnOpenStreamGetsANewLeafWithoutReconnecting(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)

	feed := h.watchX509Context(h.client())
	firstLeaf := renewLeaf(feed.next(g, "the initial X.509 context"))
	g.Expect(renewIssuances(h)).To(HaveLen(1))

	h.clock.Step(e2eRenewalStep)
	h.tiers.certs.RenewDue()

	renewed := feed.next(g, "the renewed X.509 context")
	renewedLeaf := renewLeaf(renewed)
	g.Expect(renewedLeaf.SerialNumber.String()).ToNot(Equal(firstLeaf.SerialNumber.String()))
	g.Expect(renewedLeaf.NotAfter.After(firstLeaf.NotAfter)).To(BeTrue(), "the replacement expires no later than what it replaces")
	g.Expect(renewSameKey(firstLeaf, renewedLeaf)).To(BeFalse(), "the renewal reused the old key")
	g.Expect(renewed.DefaultSVID().ID.String()).To(Equal(e2eSpiffeID))

	// The wall clock is 7h behind the certificate, so verification is at the
	// agent's clock, against the root the fake publishes now.
	published := x509bundle.FromX509Authorities(h.sts.TrustDomain(), h.sts.X509Authorities())
	_, _, err := x509svid.Verify(renewed.DefaultSVID().Certificates, published, x509svid.WithTime(h.clock.Now()))
	g.Expect(err).ToNot(HaveOccurred(), "the new SVID does not chain to the published root")
	_, _, err = x509svid.Verify(renewed.DefaultSVID().Certificates, renewed.Bundles, x509svid.WithTime(h.clock.Now()))
	g.Expect(err).ToNot(HaveOccurred(), "the new SVID does not verify against the bundle served with it")

	g.Expect(feed.errors()).To(BeZero(), "the client reconnected instead of being pushed to")
	issued := renewIssuances(h)
	g.Expect(issued).To(HaveLen(2), "the renewal signed one certificate")

	// The 1h session ran out during the step, so the tier must have asked for the
	// session again rather than sign the renewal with credentials STS would reject.
	keys := h.accessKeys(e2ePodA)
	g.Expect(keys).To(HaveLen(2), "the renewal did not fetch a new session")
	g.Expect(issued[0].AccessKeyID).To(Equal(keys[0]))
	g.Expect(issued[1].AccessKeyID).To(Equal(keys[1]), "the renewal was signed with the expired session")
	feed.quiet(g, "the renewal had already been sent")
}

// TestE2E_Renewal_ASessionShorterThanTheSVID_StillGetsAFullLifetime issues for a
// pod whose session has five minutes left. The credentials only prove who the pod
// is now, so the agent asks for the certificate's own full life, and nothing
// clamps the request to what the session has left.
func TestE2E_Renewal_ASessionShorterThanTheSVID_StillGetsAFullLifetime(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t, func(c *e2eConfig) { c.sessionLife = 5 * time.Minute })

	x509Ctx, err := h.client().FetchX509Context(h.ctx())
	g.Expect(err).ToNot(HaveOccurred())

	issued := renewIssuances(h)
	g.Expect(issued).To(HaveLen(1))
	keys := h.accessKeys(e2ePodA)
	g.Expect(keys).To(HaveLen(1))
	g.Expect(issued[0].AccessKeyID).To(Equal(keys[0]), "the certificate was not bought with the 5-minute session")
	g.Expect(issued[0].Form.Get("MaxDurationSeconds")).To(Equal("43200"), "the agent asked STS for less than the full lifetime")

	// The STS fake never clamps a lifetime to the session, so a 12h leaf asserts
	// the fake rather than the agent. It stays as a sanity check on the wiring.
	leaf := renewLeaf(x509Ctx)
	g.Expect(leaf.NotAfter.Sub(leaf.NotBefore)).To(Equal(12 * time.Hour))
}

// TestE2E_Renewal_AFailedIssuanceKeepsTheWorkingCertificateUntilItExpires fails
// issuance at STS and asserts the agent never withdraws what works: the open
// stream keeps its SVID and a new caller is served the cached one. Past NotAfter
// the entry is evicted, no caller is served an expired certificate, and the open
// stream recovers by itself, with no second caller, once STS issues again.
func TestE2E_Renewal_AFailedIssuanceKeepsTheWorkingCertificateUntilItExpires(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)
	issuances := func() int { return h.sts.Calls(ststest.ActionGetWorkloadIdentityCertificate) }

	feed := h.watchX509Context(h.client())
	firstLeaf := renewLeaf(feed.next(g, "the initial X.509 context"))

	h.sts.SetError(ststest.ActionGetWorkloadIdentityCertificate, &ststest.APIError{Status: 500, Code: "InternalFailure"})
	h.clock.Step(e2eRenewalStep)
	attempted := issuances()
	h.tiers.certs.RenewDue()

	// RenewDue renews in this goroutine, so the attempt has happened when it returns.
	g.Expect(issuances()).To(Equal(attempted+1), "STS saw no renewal attempt")
	feed.quiet(g, "a renewal failed")

	cached, err := h.client().FetchX509Context(h.ctx())
	g.Expect(err).ToNot(HaveOccurred(), "a new caller was refused while a usable certificate was cached")
	g.Expect(renewLeaf(cached).SerialNumber.String()).To(Equal(firstLeaf.SerialNumber.String()), "the new caller got something other than the cached certificate")
	g.Expect(issuances()).To(Equal(attempted+1), "serving the cached certificate called STS")

	// Past NotAfter the sweep tries once more and evicts, which wakes the stream: it
	// re-reads, finds nothing, and retries issuance on its own backoff. Three calls
	// are the sweep's, the woken stream's and its first retry, about a second later.
	h.clock.SetTime(firstLeaf.NotAfter.Add(time.Minute))
	evicting := issuances()
	h.tiers.certs.RenewDue()
	g.Eventually(issuances, e2eWait).Should(BeNumerically(">=", evicting+3), "the evicted stream is not retrying issuance")
	feed.quiet(g, "issuance was failing with nothing cached")

	renewNewStreamWaitsOnIssuance(g, h, issuances)

	// No second caller: the parked stream's own retry succeeds once STS does, and
	// the certificate it stores reaches it on the stream it already has.
	h.sts.SetError(ststest.ActionGetWorkloadIdentityCertificate, nil)
	recovered := feed.next(g, "the X.509 context after STS recovered")
	recoveredLeaf := renewLeaf(recovered)
	g.Expect(recoveredLeaf.SerialNumber.String()).ToNot(Equal(firstLeaf.SerialNumber.String()), "the stream was sent the evicted certificate")
	g.Expect(recoveredLeaf.NotAfter.After(h.clock.Now())).To(BeTrue(), "the stream was sent an expired certificate")
	_, _, err = x509svid.Verify(recovered.DefaultSVID().Certificates, recovered.Bundles, x509svid.WithTime(h.clock.Now()))
	g.Expect(err).ToNot(HaveOccurred(), "the recovered SVID does not verify against the bundle served with it")
	g.Expect(feed.errors()).To(BeZero(), "the stream ended instead of waiting out the failures")
}

// renewNewStreamWaitsOnIssuance opens a FetchX509SVID stream for the pod while
// nothing servable is cached and STS fails, and asserts it sends nothing while
// issuance is attempted, neither the expired certificate nor an error, until
// cancelled. The raw client is used so the cancellation's code can be checked.
func renewNewStreamWaitsOnIssuance(g *WithT, h *e2eHarness, issuances func() int) {
	ctx, cancel := context.WithCancel(h.rawCtx())
	defer cancel()
	before := issuances()
	stream, err := h.rawClient().FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	answered := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		answered <- err
	}()

	g.Eventually(issuances, e2eWait).Should(BeNumerically(">", before), "the new caller's stream attempted no issuance")
	g.Consistently(answered, e2eQuiet).ShouldNot(Receive(), "the new caller was answered with nothing servable cached")
	cancel()
	g.Eventually(answered, e2eWait).Should(Receive(WithTransform(status.Code, Equal(codes.Canceled))))
}

// renewLeaf is the workload's own certificate in a context the agent served.
func renewLeaf(x509Ctx *spiffeworkloadapi.X509Context) *cryptox509.Certificate {
	return x509Ctx.DefaultSVID().Certificates[0]
}

// renewSameKey says whether two certificates certify the same public key.
func renewSameKey(a, b *cryptox509.Certificate) bool {
	pub, ok := a.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(b.PublicKey)
}

// renewIssuances are the GetWorkloadIdentityCertificate requests the fake has
// received, oldest first, refused ones included.
func renewIssuances(h *e2eHarness) []ststest.Request {
	var issuances []ststest.Request
	for _, r := range h.sts.Requests() {
		if r.Action == ststest.ActionGetWorkloadIdentityCertificate {
			issuances = append(issuances, r)
		}
	}
	return issuances
}
