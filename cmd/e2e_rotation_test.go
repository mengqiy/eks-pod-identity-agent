package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptox509 "crypto/x509"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	spiffeworkloadapi "github.com/spiffe/go-spiffe/v2/workloadapi"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts/ststest"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Bundle rotation, from T13. The STS fake rotates its CA publish-then-promote: the
// new root is published, every open stream has to carry both roots, and only then
// does the new CA issue, so a pod still holding the old CA's certificate meets
// peers holding the new one's. The streams are go-spiffe watchers, so a reconnect
// shows up as a watch error rather than as a silently re-established stream.

const (
	// rotatePeerID is a workload the agent does not serve, issued straight from the
	// STS fake, so the overlap window has something from the new CA to verify.
	rotatePeerID = "spiffe://example.org/ns/team-c/sa/peer"
	// rotateFirstKeyID and rotateSecondKeyID name the published JWT authorities.
	rotateFirstKeyID  = "rotate-key-1"
	rotateSecondKeyID = "rotate-key-2"
)

// TestE2E_BundleRotation_PublishThenPromoteCarriesBothPodsOntoTheNewRoot rotates
// the CA under three open streams of two pods: publishing reaches every stream as
// both roots, a new-CA peer and pod A's old-CA certificate trust each other through
// what was streamed, renewals after promotion chain to the new root, and retiring
// the old CA leaves only the new root on every stream.
func TestE2E_BundleRotation_PublishThenPromoteCarriesBothPodsOntoTheNewRoot(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)
	// Before anything is issued, the clock goes a refresh step behind the wall
	// clock, so the peer issued after that step is already valid for a handshake,
	// which reads the wall clock. The fake CA is backdated an hour, so it covers it.
	h.clock.SetTime(h.clock.Now().Add(-time.Minute))
	td := h.sts.TrustDomain()

	// A stream attests when it opens, so each pod's first update proves it opened
	// as that pod before h.as moves on.
	h.as(e2ePodA)
	clientA := h.client()
	svidsA := h.watchX509Context(clientA)
	bundlesA := h.watchX509Bundles(clientA)
	initialA := svidsA.next(g, "pod A's initial X.509 context").DefaultSVID()
	initialSet := bundlesA.next(g, "pod A's initial X.509 bundles")
	g.Expect(initialA.ID).To(Equal(e2ePodA.spiffeID))
	h.as(e2ePodB)
	svidsB := h.watchX509Context(h.client())
	initialB := svidsB.next(g, "pod B's initial X.509 context").DefaultSVID()
	g.Expect(initialB.ID).To(Equal(e2ePodB.spiffeID))
	g.Expect(rotateRoots(g, initialSet, td)).To(ConsistOf(rotateDER(h.sts.X509Authorities())), "a node starts on the one published root")

	h.sts.PublishCA()
	roots := h.sts.X509Authorities()
	g.Expect(roots).To(HaveLen(2))
	oldRoot, newRoot := roots[0], roots[1]
	h.clock.Step(time.Minute)
	h.pass()

	overlapSet := bundlesA.next(g, "pod A's X.509 bundles once the new root is published")
	overlapA := svidsA.next(g, "pod A's X.509 context once the new root is published")
	overlapB := svidsB.next(g, "pod B's X.509 context once the new root is published")
	g.Expect(rotateRoots(g, overlapSet, td)).To(ConsistOf(rotateDER(roots)), "pod A's bundle stream did not receive both roots")
	g.Expect(rotateRoots(g, overlapA.Bundles, td)).To(ConsistOf(rotateDER(roots)), "pod A's SVID stream did not receive both roots")
	g.Expect(rotateRoots(g, overlapB.Bundles, td)).To(ConsistOf(rotateDER(roots)), "pod B's SVID stream did not receive both roots")
	// Publishing changes who a pod trusts, nothing about its own identity.
	podA := overlapA.DefaultSVID()
	g.Expect(podA.Certificates[0].Raw).To(Equal(initialA.Certificates[0].Raw), "publishing reissued pod A's certificate")
	g.Expect(overlapB.DefaultSVID().Certificates[0].Raw).To(Equal(initialB.Certificates[0].Raw), "publishing reissued pod B's certificate")

	// The new CA issues only once every stream trusts it. Each side's certificate
	// chains to a different root, so each handshake needs both in what was streamed.
	h.sts.PromoteCA()
	peer := h.sts.NewPeer(spiffeid.RequireFromString(rotatePeerID))
	g.Expect(rotateChainsTo(td, peer.Certificates, newRoot, h.clock.Now())).To(Succeed(), "the peer is not from the new CA")
	g.Expect(rotateChainsTo(td, peer.Certificates, oldRoot, h.clock.Now())).ToNot(Succeed(), "the peer chains to the old root")
	g.Expect(rotateChainsTo(td, podA.Certificates, oldRoot, h.clock.Now())).To(Succeed(), "pod A's certificate is not from the old CA")
	g.Expect(rotateChainsTo(td, podA.Certificates, newRoot, h.clock.Now())).ToNot(Succeed(), "pod A's certificate chains to the new root")

	server, client := handshake(t, podA, overlapA.Bundles, peer, overlapSet)
	g.Expect(server.err).ToNot(HaveOccurred(), "pod A serving the new-CA peer")
	g.Expect(client.err).ToNot(HaveOccurred(), "the new-CA peer dialling pod A")
	g.Expect(server.peer.String()).To(Equal(rotatePeerID))
	g.Expect(client.peer).To(Equal(e2ePodA.spiffeID))
	server, client = handshake(t, peer, overlapSet, podA, overlapA.Bundles)
	g.Expect(server.err).ToNot(HaveOccurred(), "the new-CA peer serving pod A")
	g.Expect(client.err).ToNot(HaveOccurred(), "pod A dialling the new-CA peer")
	g.Expect(server.peer).To(Equal(e2ePodA.spiffeID))
	g.Expect(client.peer.String()).To(Equal(rotatePeerID))

	// Renewed certificates are dated past the wall clock, so they are only ever
	// verified at the agent's clock.
	h.clock.Step(e2eRenewalStep)
	h.tiers.certs.RenewDue()
	renewed := map[string]*x509svid.SVID{}
	for _, pod := range []struct {
		spec    e2ePodSpec
		stream  *e2eFeed[*spiffeworkloadapi.X509Context]
		initial *x509svid.SVID
	}{{e2ePodA, svidsA, initialA}, {e2ePodB, svidsB, initialB}} {
		svid := pod.stream.next(g, "pod "+pod.spec.name+"'s renewed X.509 context").DefaultSVID()
		g.Expect(svid.ID).To(Equal(pod.spec.spiffeID))
		g.Expect(svid.Certificates[0].Raw).ToNot(Equal(pod.initial.Certificates[0].Raw), "pod %s was not renewed", pod.spec.name)
		g.Expect(rotateChainsTo(td, svid.Certificates, newRoot, h.clock.Now())).To(Succeed(), "pod %s's renewal does not chain to the new root", pod.spec.name)
		g.Expect(rotateChainsTo(td, svid.Certificates, oldRoot, h.clock.Now())).ToNot(Succeed(), "pod %s's renewal still chains to the old root", pod.spec.name)
		renewed[pod.spec.uid] = svid
	}
	bundlesA.quiet(g, "a renewal changed no root")

	h.sts.RetireOldCAs()
	h.clock.Step(time.Minute)
	h.pass()
	newOnly := rotateDER(roots[1:])
	g.Expect(rotateRoots(g, bundlesA.next(g, "pod A's X.509 bundles after the retirement"), td)).
		To(ConsistOf(newOnly), "pod A's bundle stream still carries the retired root")
	retiredA := svidsA.next(g, "pod A's X.509 context after the retirement")
	g.Expect(rotateRoots(g, retiredA.Bundles, td)).To(ConsistOf(newOnly), "pod A's SVID stream still carries the retired root")
	g.Expect(retiredA.DefaultSVID().Certificates[0].Raw).To(Equal(renewed[e2ePodA.uid].Certificates[0].Raw), "retiring a root reissued pod A's certificate")
	retiredB := svidsB.next(g, "pod B's X.509 context after the retirement")
	g.Expect(rotateRoots(g, retiredB.Bundles, td)).To(ConsistOf(newOnly), "pod B's SVID stream still carries the retired root")
	g.Expect(retiredB.DefaultSVID().Certificates[0].Raw).To(Equal(renewed[e2ePodB.uid].Certificates[0].Raw), "retiring a root reissued pod B's certificate")

	g.Expect(h.sts.Calls(ststest.ActionGetWorkloadIdentityCertificate)).To(Equal(4), "each pod's certificate was issued once and renewed once")
	g.Expect(svidsA.errors()+bundlesA.errors()+svidsB.errors()).To(BeZero(), "a stream reconnected")
}

// TestE2E_BundleRotation_ARenewalBeforePromotionStillComesFromTheOldCA renews
// while the new root is published but not yet issuing: the renewal keeps the old
// CA's intermediate. It is apart from the rotation above because the renewal step
// would leave the overlap handshake nothing valid by the wall clock.
func TestE2E_BundleRotation_ARenewalBeforePromotionStillComesFromTheOldCA(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)
	td := h.sts.TrustDomain()
	h.as(e2ePodA)
	stream := h.watchX509Context(h.client())
	initial := stream.next(g, "the initial X.509 context").DefaultSVID()
	g.Expect(initial.Certificates).To(HaveLen(2), "the chain is the leaf and the intermediate")

	h.sts.PublishCA()
	roots := h.sts.X509Authorities()
	h.clock.Step(time.Minute)
	h.pass()
	published := stream.next(g, "the X.509 context once the new root is published")
	g.Expect(rotateRoots(g, published.Bundles, td)).To(ConsistOf(rotateDER(roots)), "the stream did not receive both roots")

	h.clock.Step(e2eRenewalStep)
	h.tiers.certs.RenewDue()
	update := stream.next(g, "the renewed X.509 context")
	renewed := update.DefaultSVID()
	g.Expect(renewed.Certificates[0].Raw).ToNot(Equal(initial.Certificates[0].Raw), "the renewal served the same certificate")
	g.Expect(renewed.Certificates).To(HaveLen(2))
	g.Expect(renewed.Certificates[1].Raw).To(Equal(initial.Certificates[1].Raw), "the renewal came from another intermediate")
	g.Expect(rotateChainsTo(td, renewed.Certificates, roots[0], h.clock.Now())).To(Succeed(), "the renewal does not chain to the old root")
	g.Expect(rotateChainsTo(td, renewed.Certificates, roots[1], h.clock.Now())).ToNot(Succeed(), "the renewal came from the unpromoted CA")
	g.Expect(rotateRoots(g, update.Bundles, td)).To(ConsistOf(rotateDER(roots)), "the renewal dropped a published root")
	g.Expect(stream.errors()).To(BeZero(), "the stream reconnected")
}

// TestE2E_BundleRotation_ARefreshWithNoChangeWakesNothing is the dedupe the streams
// owe their clients: a pass that fetches the same authorities again counts no
// bundle change and signals no stream, so a node that never rotates costs its
// workloads no traffic.
func TestE2E_BundleRotation_ARefreshWithNoChangeWakesNothing(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)
	client := h.client()
	svidStream := h.watchX509Context(client)
	bundleStream := h.watchX509Bundles(client)

	svidStream.next(g, "the initial X.509 context")
	bundleStream.next(g, "the initial X.509 bundles")
	fetches := h.sts.Calls(ststest.ActionGetTrustBundles)
	before := rotateCount(g)
	g.Expect(before.notified).To(And(HaveKey(workloadidentity.RPCFetchX509SVID), HaveKey(workloadidentity.RPCFetchX509Bundles)),
		"the hub's notification series are not where this test reads them")

	h.clock.Step(time.Minute)
	h.pass()
	g.Expect(h.sts.Calls(ststest.ActionGetTrustBundles)).To(Equal(fetches+1), "the pass did not refresh the trust bundle")
	delta := rotateCount(g).since(before)
	g.Expect(delta.changes).To(BeZero(), "the bundle tier counted a change in the same authorities")
	g.Expect(delta.notified[workloadidentity.RPCFetchX509SVID]).To(BeZero(), "the pass woke the X.509-SVID stream")
	g.Expect(delta.notified[workloadidentity.RPCFetchX509Bundles]).To(BeZero(), "the pass woke the X.509 bundle stream")
	bundleStream.quiet(g, "a pass fetched the same authorities")
	svidStream.quiet(g, "a pass fetched the same authorities")
}

// TestE2E_BundleRotation_AJWTKeyRollReachesOnlyTheJWTStream adds a second JWT
// authority: the JWT bundle stream is woken and receives both keys, and the two
// X.509 streams are not woken, because a JWT key roll changes nothing an X.509
// verifier reads.
func TestE2E_BundleRotation_AJWTKeyRollReachesOnlyTheJWTStream(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)
	first := rotateNewKey(t)
	h.sts.AddJWTAuthority(rotateFirstKeyID, first.Public())

	client := h.client()
	svidStream := h.watchX509Context(client)
	bundleStream := h.watchX509Bundles(client)
	jwtStream := h.watchJWTBundles(client)
	td := h.sts.TrustDomain()

	svidStream.next(g, "the initial X.509 context")
	bundleStream.next(g, "the initial X.509 bundles")
	g.Expect(rotateJWTKeys(g, jwtStream.next(g, "the initial JWT bundles"), td)).To(HaveKey(rotateFirstKeyID))
	before := rotateCount(g)
	g.Expect(before.notified).To(And(HaveKey(workloadidentity.RPCFetchX509SVID), HaveKey(workloadidentity.RPCFetchX509Bundles)),
		"the hub's notification series are not where this test reads them")

	second := rotateNewKey(t)
	h.sts.AddJWTAuthority(rotateSecondKeyID, second.Public())
	h.clock.Step(time.Minute)
	h.pass()

	// The change counter has no label for which set changed, so the hub's per-RPC
	// count is what tells the JWT stream's signal from an X.509 stream's.
	delta := rotateCount(g).since(before)
	g.Expect(delta.changes).To(Equal(1.0), "the bundle tier did not count the key roll once")
	g.Expect(delta.notified[workloadidentity.RPCFetchJWTBundles]).To(Equal(1.0), "the key roll did not wake the JWT stream once")
	g.Expect(delta.notified[workloadidentity.RPCFetchX509SVID]).To(BeZero(), "the key roll woke the X.509-SVID stream")
	g.Expect(delta.notified[workloadidentity.RPCFetchX509Bundles]).To(BeZero(), "the key roll woke the X.509 bundle stream")

	rolled := rotateJWTKeys(g, jwtStream.next(g, "the JWT bundles after the key roll"), td)
	g.Expect(rolled).To(HaveLen(2), "the JWT stream did not receive both keys")
	g.Expect(rolled).To(HaveKey(rotateFirstKeyID), "the JWT stream dropped the key already in use")
	g.Expect(second.PublicKey.Equal(rolled[rotateSecondKeyID])).To(BeTrue(), "the JWT stream published some other key as the new one")
	svidStream.quiet(g, "only a JWT authority changed")
	bundleStream.quiet(g, "only a JWT authority changed")
}

// rotateCounters is what the bundle tier and the hub have counted in this process:
// authority set changes, and notifications by RPC over both deliveries.
type rotateCounters struct {
	changes  float64
	notified map[string]float64
}

// rotateCount reads both counters from the default registry, where promauto put
// them. They are process-wide, so a test compares two reads rather than a value.
func rotateCount(g Gomega) rotateCounters {
	families, err := prometheus.DefaultGatherer.Gather()
	g.Expect(err).ToNot(HaveOccurred())
	counts := rotateCounters{notified: map[string]float64{}}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			switch family.GetName() {
			case workloadidentity.MetricBundleChangeTotal:
				counts.changes += metric.GetCounter().GetValue()
			case workloadidentity.MetricNotificationTotal:
				for _, pair := range metric.GetLabel() {
					if pair.GetName() == workloadidentity.LabelRPC {
						counts.notified[pair.GetValue()] += metric.GetCounter().GetValue()
					}
				}
			}
		}
	}
	return counts
}

// since is how much each counter moved after before was read.
func (c rotateCounters) since(before rotateCounters) rotateCounters {
	delta := rotateCounters{changes: c.changes - before.changes, notified: map[string]float64{}}
	for rpc, n := range c.notified {
		delta.notified[rpc] = n - before.notified[rpc]
	}
	return delta
}

// rotateRoots is the DER of the trust domain's roots in a streamed set, which holds
// only the provider's own domain here because nothing in the harness federates.
func rotateRoots(g Gomega, set *x509bundle.Set, td spiffeid.TrustDomain) [][]byte {
	g.Expect(set.Bundles()).To(HaveLen(1), "the stream carried bundles for more than the provider's own trust domain")
	bundle, ok := set.Get(td)
	g.Expect(ok).To(BeTrue(), "the stream carried no bundle for %s", td)
	return rotateDER(bundle.X509Authorities())
}

// rotateChainsTo verifies certs against root alone at now, so a test can say which
// CA a certificate came from. Pass the agent's clock: a renewal postdates the wall.
func rotateChainsTo(td spiffeid.TrustDomain, certs []*cryptox509.Certificate, root *cryptox509.Certificate, now time.Time) error {
	_, _, err := x509svid.Verify(certs, x509bundle.FromX509Authorities(td, []*cryptox509.Certificate{root}), x509svid.WithTime(now))
	return err
}

// rotateJWTKeys is the trust domain's JWT authorities out of a streamed set.
func rotateJWTKeys(g Gomega, set *jwtbundle.Set, td spiffeid.TrustDomain) map[string]crypto.PublicKey {
	g.Expect(set.Bundles()).To(HaveLen(1), "the stream carried JWT bundles for more than the provider's own trust domain")
	bundle, ok := set.Get(td)
	g.Expect(ok).To(BeTrue(), "the stream carried no JWT bundle for %s", td)
	return bundle.JWTAuthorities()
}

// rotateDER compares certificates by their bytes, since a parsed certificate holds
// pointers no equality matcher reads.
func rotateDER(certs []*cryptox509.Certificate) [][]byte {
	der := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		der = append(der, cert.Raw)
	}
	return der
}

// rotateNewKey is one JWT authority's key pair; only its public half is published.
func rotateNewKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a JWT authority key: %v", err)
	}
	return key
}
