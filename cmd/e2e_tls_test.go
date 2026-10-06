package cmd

import (
	"crypto"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	spiffeworkloadapi "github.com/spiffe/go-spiffe/v2/workloadapi"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts/ststest"
)

// tlsRemoteID is a workload in the pods' trust domain on another node, which STS
// issues to through NewPeer and this agent serves nothing.
var tlsRemoteID = spiffeid.RequireFromString("spiffe://example.org/ns/team-c/sa/db")

// TestE2E_PeerVerification_TwoPodsOfOneAgentAuthenticateEachOtherInBothRoles is
// two workloads on one agent meeting over mutual TLS, each holding what its own
// FetchX509Context returned and trusting only the bundles in it. Each reads the
// other's ID, and each SVID is a separate issuance under that pod's own session.
func TestE2E_PeerVerification_TwoPodsOfOneAgentAuthenticateEachOtherInBothRoles(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)

	// FetchX509Context attests when its stream opens, so h.as goes first.
	h.as(e2ePodA)
	ctxA, err := h.client().FetchX509Context(h.ctx())
	g.Expect(err).ToNot(HaveOccurred())
	h.as(e2ePodB)
	ctxB, err := h.client().FetchX509Context(h.ctx())
	g.Expect(err).ToNot(HaveOccurred())

	svidA, svidB := ctxA.DefaultSVID(), ctxB.DefaultSVID()
	g.Expect(svidA.ID.String()).To(Equal(e2ePodA.spiffeID.String()))
	g.Expect(svidB.ID.String()).To(Equal(e2ePodB.spiffeID.String()))
	g.Expect(ctxA.Bundles.Len()).To(Equal(1), "pod A trusts its own trust domain and nothing else")
	g.Expect(ctxB.Bundles.Len()).To(Equal(1), "pod B trusts its own trust domain and nothing else")
	keyA, keyB := svidA.Certificates[0].PublicKey, svidB.Certificates[0].PublicKey
	g.Expect(tlsSameKey(keyA, keyB)).To(BeFalse(), "the two pods hold one key")

	server, client := handshake(t, svidA, ctxA.Bundles, svidB, ctxB.Bundles)
	g.Expect(server.err).ToNot(HaveOccurred(), "pod A serving pod B")
	g.Expect(client.err).ToNot(HaveOccurred(), "pod B dialling pod A")
	g.Expect(server.peer.String()).To(Equal(e2ePodB.spiffeID.String()))
	g.Expect(client.peer.String()).To(Equal(e2ePodA.spiffeID.String()))

	server, client = handshake(t, svidB, ctxB.Bundles, svidA, ctxA.Bundles)
	g.Expect(server.err).ToNot(HaveOccurred(), "pod B serving pod A")
	g.Expect(client.err).ToNot(HaveOccurred(), "pod A dialling pod B")
	g.Expect(server.peer.String()).To(Equal(e2ePodA.spiffeID.String()))
	g.Expect(client.peer.String()).To(Equal(e2ePodB.spiffeID.String()))

	// Each request's CSR key ties it to the SVID it became, and its access key to
	// the session it was signed with.
	g.Expect(h.sts.Issued()).To(HaveLen(2))
	keysA, keysB := h.accessKeys(e2ePodA), h.accessKeys(e2ePodB)
	g.Expect(keysA).To(HaveLen(1))
	g.Expect(keysB).To(HaveLen(1))
	csrKeys := map[string]crypto.PublicKey{}
	for _, r := range h.sts.Requests() {
		if r.Action == ststest.ActionGetWorkloadIdentityCertificate {
			g.Expect(r.CSR).ToNot(BeNil())
			csrKeys[r.AccessKeyID] = r.CSR.PublicKey
		}
	}
	g.Expect(csrKeys).To(HaveLen(2), "two certificate requests under two sessions")
	g.Expect(tlsSameKey(csrKeys[keysA[0]], keyA)).To(BeTrue(), "pod A's SVID was not requested with pod A's session")
	g.Expect(tlsSameKey(csrKeys[keysB[0]], keyB)).To(BeTrue(), "pod B's SVID was not requested with pod B's session")
}

// TestE2E_PeerVerification_APeerFromAnUnrelatedCAIsRefusedInBothRoles is a peer
// whose CA the agent never published. Claiming pod B's ID reaches the bundle the
// pod holds and fails on the chain; another trust domain finds no bundle at all.
// The impostor trusts the pod's bundles, so it hears the pod's alert, not its own.
func TestE2E_PeerVerification_APeerFromAnUnrelatedCAIsRefusedInBothRoles(t *testing.T) {
	h := newE2EHarness(t)
	x509Ctx, err := h.client().FetchX509Context(h.ctx())
	NewWithT(t).Expect(err).ToNot(HaveOccurred())
	svid := x509Ctx.DefaultSVID()

	for _, tc := range []struct {
		name   string
		domain string
		id     string
		// refusal is the error the pod's side ends with, described by why.
		refusal func(error) bool
		why     string
	}{
		{
			name:    "the pod's trust domain under another CA",
			id:      e2ePodB.spiffeID.String(),
			refusal: func(err error) bool { return errors.As(err, new(x509.UnknownAuthorityError)) },
			why:     "signed by an unknown authority",
		},
		{
			name:   "another trust domain",
			domain: "other.example",
			id:     "spiffe://other.example/ns/team-b/sa/api",
			refusal: func(err error) bool {
				return strings.Contains(err.Error(), `no X.509 bundle for trust domain "other.example"`)
			},
			why: "no bundle for other.example",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			opts := ststest.Opts{Now: h.clock.Now}
			if tc.domain != "" {
				opts.TrustDomain = spiffeid.RequireTrustDomainFromString(tc.domain)
			}
			impostor := ststest.New(t, opts).NewPeer(spiffeid.RequireFromString(tc.id))
			matchRefusal := MatchError(tc.refusal, tc.why)
			matchAlert := MatchError(tlsHeardAlert, "a TLS alert from the pod")

			server, client := handshake(t, svid, x509Ctx.Bundles, impostor, x509Ctx.Bundles)
			g.Expect(server.err).To(matchRefusal, "the agent's SVID serving the impostor")
			g.Expect(client.err).To(matchAlert, "the impostor dialling the agent's SVID")

			server, client = handshake(t, impostor, x509Ctx.Bundles, svid, x509Ctx.Bundles)
			g.Expect(client.err).To(matchRefusal, "the agent's SVID dialling the impostor")
			g.Expect(server.err).To(matchAlert, "the impostor serving the agent's SVID")
		})
	}
}

// TestE2E_PeerVerification_AnX509SourceIsTheSVIDAndBundleSourceOfATLSConfig is
// the way most go-spiffe services hold the agent: one X509Source passed to
// tlsconfig as both sources. The peer trusts the roots STS publishes, not
// anything the agent served, so the agent's chain is checked independently.
func TestE2E_PeerVerification_AnX509SourceIsTheSVIDAndBundleSourceOfATLSConfig(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)

	source, err := spiffeworkloadapi.NewX509Source(h.ctx(),
		spiffeworkloadapi.WithClientOptions(spiffeworkloadapi.WithAddr("unix://"+h.path)))
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() { _ = source.Close() })
	peer := h.sts.NewPeer(tlsRemoteID)
	peerTrust := x509bundle.FromX509Authorities(h.sts.TrustDomain(), h.sts.X509Authorities())

	server, client := handshake(t, source, source, peer, peerTrust)
	g.Expect(server.err).ToNot(HaveOccurred(), "the X509Source serving the peer")
	g.Expect(client.err).ToNot(HaveOccurred(), "the peer dialling the X509Source")
	g.Expect(server.peer.String()).To(Equal(tlsRemoteID.String()))
	g.Expect(client.peer.String()).To(Equal(e2eSpiffeID))

	server, client = handshake(t, peer, peerTrust, source, source)
	g.Expect(server.err).ToNot(HaveOccurred(), "the peer serving the X509Source")
	g.Expect(client.err).ToNot(HaveOccurred(), "the X509Source dialling the peer")
	g.Expect(server.peer.String()).To(Equal(e2eSpiffeID))
	g.Expect(client.peer.String()).To(Equal(tlsRemoteID.String()))
}

// tlsSameKey reports whether a and b are one public key. A nil a is no key.
func tlsSameKey(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

// tlsHeardAlert reports whether err is an alert crypto/tls received from the
// peer, rather than a refusal of this side's own.
func tlsHeardAlert(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "remote error"
}
