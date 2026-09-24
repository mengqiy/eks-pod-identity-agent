// Package tokenminter mints a pod-bound ServiceAccount token (PSAT) for an
// attested workload via the Kubernetes TokenRequest API and caches it per pod.
// The token is minted with the node credential (the shared internal/kube
// client) and every field comes from the attested Workload, never the caller.
//
// minter.go holds the raw mint; cache.go the caching and renewal; csidriver.go
// the CSIDriver object the mint depends on.
package tokenminter

import (
	"context"

	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// EKSAuthAudience is the only audience the agent mints for. It must also appear
// in the CSIDriver's spec.tokenRequests, or the 1.33 node audience restriction
// refuses the mint (see csidriver.go). Aliased from configuration rather than
// copied: the audience is one half of that contract, and the driver name the
// other.
const EKSAuthAudience = configuration.EksAuthAudience

// boundObjectKind binds the token to the pod, so it is rejected once the pod is
// gone.
const boundObjectKind = "Pod"

// rawMinter mints one token with no caching. It is the seam cache.go wraps and
// tests fake.
type rawMinter interface {
	mint(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error)
}

// apiMinter is the rawMinter backed by the API server, authenticating as the
// node identity (internal/kube.NewNodeClient).
type apiMinter struct {
	client kubernetes.Interface
}

func newAPIMinter(client kubernetes.Interface) *apiMinter {
	return &apiMinter{client: client}
}

// mint requests a pod-bound token scoped to the EKS Auth audience, with no
// expirationSeconds so the cluster default governs the lifetime the cache keys
// renewal off. A refusal is the not-retryable ErrTokenMintForbidden (usually a
// missing CSIDriver tokenRequests declaration); any other failure is the
// retryable ErrTokenMintFailed.
func (m *apiMinter) mint(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
	req := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: []string{EKSAuthAudience},
			BoundObjectRef: &authenticationv1.BoundObjectReference{
				Kind:       boundObjectKind,
				APIVersion: "v1",
				Name:       w.PodName,
				UID:        types.UID(w.PodUID),
			},
		},
	}

	out, err := m.client.CoreV1().ServiceAccounts(w.Namespace).CreateToken(
		ctx, w.ServiceAccount, req, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsForbidden(err) {
			return nil, wierrors.ErrTokenMintForbidden.Wrapf(err,
				"TokenRequest for %s/%s audience %q refused",
				w.Namespace, w.ServiceAccount, EKSAuthAudience)
		}
		return nil, wierrors.ErrTokenMintFailed.Wrapf(err,
			"TokenRequest for %s/%s", w.Namespace, w.ServiceAccount)
	}

	if out.Status.Token == "" {
		return nil, wierrors.ErrTokenMintFailed.Wrapf(nil,
			"TokenRequest for %s/%s returned an empty token", w.Namespace, w.ServiceAccount)
	}

	return &workloadidentity.ProjectedToken{
		Token:     out.Status.Token,
		ExpiresAt: out.Status.ExpirationTimestamp.Time,
	}, nil
}

var _ rawMinter = (*apiMinter)(nil)
