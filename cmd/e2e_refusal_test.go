package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts/ststest"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// These are the scenarios where the agent says no, and the ones where something
// below it does. A refusal has to reach the caller as a status its SPIFFE library
// can act on, and it has to cost nothing further down: a caller the node cannot
// attest must mint no session and make no STS call at all. The two "something below
// said no" cases are the ones a reader has to tell apart, because one ends the
// stream and the other must not: STS refusing a provider's bundles is settled and
// the stream ends, while a session the agent expects back leaves it waiting.

const (
	// refuseUnknownUID is a pod UID no pod on the node has.
	refuseUnknownUID = "0d9c8b7a-6f5e-4d3c-9b2a-1f0e9d8c7b6a"
	// refuseJWTKeyID is the key ID the provider's JWT authority is published under,
	// and the one every token here names in its header.
	refuseJWTKeyID = "e2e-jwt-key"
	// refuseAudience is the audience every token here is minted for.
	refuseAudience = "spiffe://example.org/aud"
)

// refuseLatePod is a pod on the agent's node that is created only after the agent
// started, in e2ePodA's ServiceAccount, so STS issues it the same identity.
var refuseLatePod = e2ePodSpec{
	uid: "9f8e7d6c-5b4a-4928-9706-f5e4d3c2b1a0", name: "web-1", namespace: e2eNamespace, serviceAccount: e2eServiceAccount,
	spiffeID: spiffeid.RequireFromString(e2eSpiffeID),
}

// TestE2E_Refusal_AnUnattestableCaller_IsRefusedAndMintsNothing connects from a
// process no pod owns. Every in-scope RPC has to refuse it with the reason, and
// nothing below attestation may run: no session, no STS call.
func TestE2E_Refusal_AnUnattestableCaller_IsRefusedAndMintsNothing(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)
	// An empty UID makes the cgroup lookup report the test process as no pod's.
	h.as(e2ePodSpec{})
	client := h.rawClient()
	ctx := h.rawCtx()
	before := refuseAttestationFailures(g)

	calls := []struct {
		name string
		call func() error
	}{
		{"FetchX509SVID", func() error {
			return wiFirstRecv(client.FetchX509SVID(ctx, &workload.X509SVIDRequest{}))
		}},
		{"FetchX509Bundles", func() error {
			return wiFirstRecv(client.FetchX509Bundles(ctx, &workload.X509BundlesRequest{}))
		}},
		{"FetchJWTBundles", func() error {
			return wiFirstRecv(client.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{}))
		}},
		{"FetchJWTSVID", func() error {
			_, err := client.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{refuseAudience}})
			return err
		}},
		{"ValidateJWTSVID", func() error {
			_, err := client.ValidateJWTSVID(ctx, &workload.ValidateJWTSVIDRequest{Audience: refuseAudience, Svid: "not-a-jwt"})
			return err
		}},
	}
	for _, c := range calls {
		err := c.call()
		g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied), "%s: %v", c.name, err)
		g.Expect(status.Convert(err).Message()).To(Equal("attestation refused ("+workloadidentity.ReasonCgroupNoPodUID+")"), c.name)
	}

	g.Expect(refuseCountedSince(before, refuseAttestationFailures(g))).
		To(Equal(map[string]float64{workloadidentity.ReasonCgroupNoPodUID: float64(len(calls))}), "each refusal is counted once, under its reason")
	g.Expect(h.sts.Requests()).To(BeEmpty(), "an unattestable caller reached STS")
	g.Expect(h.sessions.Calls()).To(BeZero(), "an unattestable caller reached the session tier")
}

// TestE2E_Refusal_APodTheStoreDoesNotKnow_IsRefused is the security-relevant
// refusal: a local caller resolves to a pod UID the node's store does not hold,
// which is counted and reported apart from an unreadable cgroup.
func TestE2E_Refusal_APodTheStoreDoesNotKnow_IsRefused(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)
	h.as(e2ePodSpec{uid: refuseUnknownUID})
	client := h.rawClient()
	before := refuseAttestationFailures(g)

	err := wiFirstRecv(client.FetchX509SVID(h.rawCtx(), &workload.X509SVIDRequest{}))

	g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied), "%v", err)
	g.Expect(status.Convert(err).Message()).To(Equal("attestation refused (" + workloadidentity.ReasonPodNotInStore + ")"))
	g.Expect(refuseCountedSince(before, refuseAttestationFailures(g))).
		To(Equal(map[string]float64{workloadidentity.ReasonPodNotInStore: 1}), "the refusal is not counted once under pod_not_in_store alone")
	g.Expect(h.sts.Requests()).To(BeEmpty(), "a caller the store does not know reached STS")
	g.Expect(h.sessions.Calls()).To(BeZero(), "a caller the store does not know reached the session tier")
}

// TestE2E_Refusal_APodAddedAfterStart_IsServedOnceTheWatchDeliversIt covers the
// pod that reaches the agent before the API server has told it about the pod: it
// is refused, then served an SVID once the informer's watch catches up, with no
// restart, no relist and no direct pod read.
func TestE2E_Refusal_APodAddedAfterStart_IsServedOnceTheWatchDeliversIt(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)
	h.enroll(refuseLatePod)
	h.as(refuseLatePod)
	g.Eventually(h.podWatchStarted, e2eWait, 10*time.Millisecond).
		Should(BeTrue(), "the pod store's watch never reached the fake clientset")
	// The reflector lists before it watches, so this is the start-up list.
	listsAtStart, _ := h.kube.podLists()

	client := h.rawClient()
	ctx := h.rawCtx()
	err := wiFirstRecv(client.FetchX509SVID(ctx, &workload.X509SVIDRequest{}))
	g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied), "%v", err)
	g.Expect(status.Convert(err).Message()).To(Equal("attestation refused (" + workloadidentity.ReasonPodNotInStore + ")"))
	g.Expect(h.sessions.Calls()).To(BeZero(), "a refused caller reached the session tier")

	g.Expect(h.kube.Tracker().Add(refuseLatePod.object())).To(Succeed())

	var served *workload.X509SVIDResponse
	g.Eventually(func(g Gomega) {
		stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
		g.Expect(err).ToNot(HaveOccurred())
		served, err = stream.Recv()
		g.Expect(err).ToNot(HaveOccurred())
	}, e2eWait, 50*time.Millisecond).Should(Succeed(), "the pod created after start was never served")
	g.Expect(served.GetSvids()).To(HaveLen(1))
	g.Expect(served.GetSvids()[0].GetSpiffeId()).To(Equal(e2eSpiffeID))
	g.Expect(h.sessions.Workloads()).To(HaveEach(Equal(&workloadidentity.Workload{
		PodUID: refuseLatePod.uid, PodName: refuseLatePod.name, Namespace: refuseLatePod.namespace,
		ServiceAccount: refuseLatePod.serviceAccount, NodeName: wiTestNode,
	})))

	lists, _ := h.kube.podLists()
	g.Expect(lists).To(Equal(listsAtStart), "the pod store relisted to find the late pod")
	for _, action := range h.kube.Actions() {
		g.Expect(action.GetVerb() == "get" && action.GetResource().Resource == "pods").
			To(BeFalse(), "the agent read the pod from the API server rather than its store")
	}
}

// TestE2E_Refusal_ValidateJWTSVID_TakesThePublishedAuthorityAndRefusesAnImpostor
// validates a token against the authorities the real trust bundle tier read from
// STS. The impostor carries the same key ID, so only the signature tells them
// apart, which is the check a hand-written fake bundle would have skipped.
func TestE2E_Refusal_ValidateJWTSVID_TakesThePublishedAuthorityAndRefusesAnImpostor(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)
	authority := refuseES384Key(t)
	// Published before the first call, so the one fetch the tier makes carries it.
	h.sts.AddJWTAuthority(refuseJWTKeyID, authority.Public())
	client := h.client()
	ctx := h.ctx()

	svid, err := client.ValidateJWTSVID(ctx, refuseSignJWT(t, authority, e2eSpiffeID), refuseAudience)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(svid.ID.String()).To(Equal(e2eSpiffeID))
	g.Expect(svid.Audience).To(ConsistOf(refuseAudience))

	_, err = client.ValidateJWTSVID(ctx, refuseSignJWT(t, refuseES384Key(t), e2eSpiffeID), refuseAudience)
	g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument), "a token signed by another key was accepted: %v", err)

	bundles, err := client.FetchJWTBundles(ctx)
	g.Expect(err).ToNot(HaveOccurred())
	bundle, err := bundles.GetJWTBundleForTrustDomain(h.sts.TrustDomain())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(bundle.HasJWTAuthority(refuseJWTKeyID)).To(BeTrue(), "the JWK Set served to the caller is missing the authority it validated against")
	g.Expect(h.sts.Calls(ststest.ActionGetTrustBundles)).To(Equal(1), "every call after the first served the cached bundle")
}

// TestE2E_Refusal_STSRefusingTrustBundles_EndsTheBundleAndSVIDStreams is a
// workload role without sts:GetTrustBundles. The refusal is settled, so both
// streams end with it rather than waiting, the SVID stream included: an identity
// with nothing to verify peers against is not servable.
func TestE2E_Refusal_STSRefusingTrustBundles_EndsTheBundleAndSVIDStreams(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)
	h.sts.SetError(ststest.ActionGetTrustBundles, &ststest.APIError{Status: http.StatusForbidden, Code: "AccessDenied"})
	client := h.client()
	ctx := h.ctx()

	_, err := client.FetchX509Bundles(ctx)
	g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied), "%v", err)
	g.Expect(status.Convert(err).Message()).To(ContainSubstring("GetTrustBundles"))

	_, err = client.FetchX509Context(ctx)
	g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied), "%v", err)
	g.Expect(status.Convert(err).Message()).To(ContainSubstring("was refused"), "the SVID stream ended on something other than the bundle refusal")
	g.Expect(h.sts.Calls(ststest.ActionGetTrustBundles)).To(BeNumerically(">=", 1))
}

// TestE2E_Refusal_ARetryableSessionFailure_BlocksTheStreamThenRecovers is the
// failure that must not look like a refusal. A cold start is multi-hop, so a
// session the agent expects back leaves the stream waiting, and the stream picks
// itself up on its own backoff once the session returns.
func TestE2E_Refusal_ARetryableSessionFailure_BlocksTheStreamThenRecovers(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)
	h.failSessions(wierrors.ErrSessionUnavailable)
	client := h.rawClient()

	stream, err := client.FetchX509SVID(h.rawCtx(), &workload.X509SVIDRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	received := make(chan refuseReceived, 1)
	go func() {
		resp, err := stream.Recv()
		received <- refuseReceived{resp: resp, err: err}
	}()

	// Waiting on the session, not on something before it.
	g.Eventually(h.sessions.Calls, e2eWait, 10*time.Millisecond).Should(BeNumerically(">=", 1), "the stream never asked for a session")
	g.Consistently(received, e2eQuiet, 10*time.Millisecond).
		ShouldNot(Receive(), "the stream answered while the session was unavailable")
	g.Expect(h.sts.Calls(ststest.ActionGetWorkloadIdentityCertificate)).To(BeZero(), "a certificate was issued without a session")

	h.failSessions(nil)

	// The handler retries on its own real-time backoff, about a second at first.
	var got refuseReceived
	g.Eventually(received, e2eWait).Should(Receive(&got), "the stream never recovered after the session returned")
	g.Expect(got.err).ToNot(HaveOccurred())
	g.Expect(got.resp.GetSvids()).To(HaveLen(1))
	g.Expect(got.resp.GetSvids()[0].GetSpiffeId()).To(Equal(e2eSpiffeID))
	keys := h.accessKeys(e2ePodA)
	g.Expect(keys).To(HaveLen(1), "a session was issued while the session tier was failing")
	g.Expect(h.sts.Requests()).ToNot(BeEmpty())
	for _, r := range h.sts.Requests() {
		g.Expect(r.AccessKeyID).To(Equal(keys[0]), "the recovered stream is not on the session issued once it returned")
	}
}

// refuseReceived is one FetchX509SVID message or the error that ended the stream,
// read off the stream by a goroutine so the test can watch a stream that answers
// nothing.
type refuseReceived struct {
	resp *workload.X509SVIDResponse
	err  error
}

// refuseAttestationFailures reads workload_identity_attestation_total's failure
// series by reason from the default registry, where the attestor's promauto
// collector is, so a test sees what an operator's alarm would.
func refuseAttestationFailures(g Gomega) map[string]float64 {
	families, err := prometheus.DefaultGatherer.Gather()
	g.Expect(err).ToNot(HaveOccurred())

	counts := map[string]float64{}
	for _, family := range families {
		if family.GetName() != workloadidentity.MetricAttestationTotal {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := map[string]string{}
			for _, pair := range metric.GetLabel() {
				labels[pair.GetName()] = pair.GetValue()
			}
			if labels[workloadidentity.LabelOutcome] == workloadidentity.OutcomeFailure {
				counts[labels[workloadidentity.LabelReason]] = metric.GetCounter().GetValue()
			}
		}
	}
	return counts
}

// refuseCountedSince is what moved between two reads of the failure series,
// leaving out the reasons that did not, so a test compares against exactly what
// its calls should add.
func refuseCountedSince(before, after map[string]float64) map[string]float64 {
	moved := map[string]float64{}
	for reason, value := range after {
		if delta := value - before[reason]; delta != 0 {
			moved[reason] = delta
		}
	}
	return moved
}

// refuseES384Key is a P-384 key, the ES384 key type STS signs JWT-SVIDs with.
func refuseES384Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a JWT key: %v", err)
	}
	return key
}

// refuseSignJWT signs a JWT-SVID for subject and refuseAudience under
// refuseJWTKeyID, whatever key signs it, so an impostor token differs from a
// genuine one only in its signature. Times are the wall clock's, which jwtsvid
// validates against.
func refuseSignJWT(t *testing.T, key *ecdsa.PrivateKey, subject string) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), refuseJWTKeyID))
	if err != nil {
		t.Fatalf("building a JWT signer: %v", err)
	}
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject:  subject,
		Audience: []string{refuseAudience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}).Serialize()
	if err != nil {
		t.Fatalf("signing a JWT: %v", err)
	}
	return token
}
