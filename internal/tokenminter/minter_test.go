package tokenminter

import (
	"context"
	"errors"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

func testWorkload() *workloadidentity.Workload {
	return &workloadidentity.Workload{
		PodUID:         "pod-uid-1",
		PodName:        "web-0",
		Namespace:      "team-a",
		ServiceAccount: "web",
		NodeName:       "ip-10-0-1-23",
	}
}

// tokenReactor installs a create reactor on serviceaccounts that captures the
// TokenRequest the minter sent and returns a canned status. The fake clientset's
// default reactor echoes the object back with an empty status, so a real token
// only appears when a reactor supplies one.
func tokenReactor(client *fake.Clientset, captured **authenticationv1.TokenRequest, token string, expiry time.Time) {
	client.PrependReactor("create", "serviceaccounts",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			create := action.(k8stesting.CreateAction)
			*captured = create.GetObject().(*authenticationv1.TokenRequest)
			return true, &authenticationv1.TokenRequest{
				Status: authenticationv1.TokenRequestStatus{
					Token:               token,
					ExpirationTimestamp: metav1.NewTime(expiry),
				},
			}, nil
		})
}

// TestMint_Success_ReturnsTokenBoundToPod proves a mint returns the API server's
// token and expiry, and that the TokenRequest carries the single EKS Auth
// audience and a pod-bound object reference to the attested pod.
func TestMint_Success_ReturnsTokenBoundToPod(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	var sent *authenticationv1.TokenRequest
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	tokenReactor(client, &sent, "signed-psat", expiry)

	m := newAPIMinter(client)
	w := testWorkload()

	got, err := m.mint(context.Background(), w)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Token).To(Equal("signed-psat"))
	g.Expect(got.ExpiresAt).To(Equal(expiry))

	g.Expect(sent.Spec.Audiences).To(Equal([]string{EKSAuthAudience}))
	g.Expect(sent.Spec.ExpirationSeconds).To(BeNil())
	g.Expect(sent.Spec.BoundObjectRef).NotTo(BeNil())
	g.Expect(sent.Spec.BoundObjectRef.Kind).To(Equal("Pod"))
	g.Expect(sent.Spec.BoundObjectRef.Name).To(Equal(w.PodName))
	g.Expect(string(sent.Spec.BoundObjectRef.UID)).To(Equal(w.PodUID))
}

// TestMint_Forbidden_MapsToForbidden proves an API-server refusal for the EKS
// Auth audience is the not-retryable ErrTokenMintForbidden, which is the signal
// the CSIDriver tokenRequests declaration is missing.
func TestMint_Forbidden_MapsToForbidden(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "serviceaccounts",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Resource: "serviceaccounts"}, "web",
				errors.New("audience not declared"))
		})

	_, err := newAPIMinter(client).mint(context.Background(), testWorkload())

	g.Expect(err).To(MatchError(wierrors.ErrTokenMintForbidden))
	g.Expect(wierrors.IsRetryable(err)).To(BeFalse())
}

// TestMint_ServerError_MapsToFailed proves any non-forbidden API failure is the
// retryable ErrTokenMintFailed.
func TestMint_ServerError_MapsToFailed(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "serviceaccounts",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(errors.New("etcd down"))
		})

	_, err := newAPIMinter(client).mint(context.Background(), testWorkload())

	g.Expect(err).To(MatchError(wierrors.ErrTokenMintFailed))
	g.Expect(wierrors.IsRetryable(err)).To(BeTrue())
}

// TestMint_EmptyToken_MapsToFailed proves a success response carrying no token
// is treated as a failed mint rather than handing back an empty credential.
func TestMint_EmptyToken_MapsToFailed(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	var sent *authenticationv1.TokenRequest
	tokenReactor(client, &sent, "", time.Now().Add(time.Hour))

	_, err := newAPIMinter(client).mint(context.Background(), testWorkload())

	g.Expect(err).To(MatchError(wierrors.ErrTokenMintFailed))
}
