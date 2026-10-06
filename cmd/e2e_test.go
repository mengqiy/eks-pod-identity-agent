package cmd

import (
	"crypto"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts/ststest"
)

// TestE2E_ColdStart_GoSpiffeObtainsAnSVIDWhoseKeyMatchesTheLeaf is the whole
// issuance path on a pod's first call: attest the test process, take its session,
// issue from the STS fake, read the trust bundle, and serve go-spiffe an
// X.509-SVID that verifies against the bundle in the same response.
func TestE2E_ColdStart_GoSpiffeObtainsAnSVIDWhoseKeyMatchesTheLeaf(t *testing.T) {
	g := NewWithT(t)
	h := newE2EHarness(t)

	x509Ctx, err := h.client().FetchX509Context(h.ctx())
	g.Expect(err).ToNot(HaveOccurred())

	svid := x509Ctx.DefaultSVID()
	g.Expect(svid.ID.String()).To(Equal(e2eSpiffeID))
	pub, ok := svid.PrivateKey.Public().(interface{ Equal(crypto.PublicKey) bool })
	g.Expect(ok).To(BeTrue())
	g.Expect(pub.Equal(svid.Certificates[0].PublicKey)).To(BeTrue(), "the private key does not match the leaf")
	_, _, err = x509svid.Verify(svid.Certificates, x509Ctx.Bundles)
	g.Expect(err).ToNot(HaveOccurred(), "the SVID does not verify against the bundle served with it")

	g.Expect(h.sts.Calls(ststest.ActionGetWorkloadIdentityCertificate)).To(Equal(1))
	keys := h.accessKeys(e2ePodA)
	g.Expect(keys).To(HaveLen(1))
	for _, r := range h.sts.Requests() {
		g.Expect(r.AccessKeyID).To(Equal(keys[0]), "every STS call is signed with the pod's session")
	}
	g.Expect(h.sessions.Workloads()).ToNot(BeEmpty())
	g.Expect(h.sessions.Workloads()[0].PodUID).To(Equal(e2ePodUID))
}
