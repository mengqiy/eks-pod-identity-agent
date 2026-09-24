package tokenminter

// Startup wiring for PSAT minting. The clientset is injected, produced once by
// internal/kube and shared with the attestor (T3), mirroring
// attestation.NewAttestor.

import (
	"context"
	"fmt"

	"k8s.io/client-go/kubernetes"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// NewMinter checks the CSIDriver the mint depends on and returns a caching
// TokenMinter over the shared node-credentialed client. A zero opts is
// production-sane.
//
// The check is a pre-flight, not a gate: a missing or misdeclared CSIDriver is
// the chart's to fix and is only logged, so startup fails here only when the API
// server itself could not be reached.
func NewMinter(ctx context.Context, clientset kubernetes.Interface, opts CachedMinterOpts) (workloadidentity.TokenMinter, error) {
	if err := VerifyCSIDriverExists(ctx, clientset); err != nil {
		return nil, fmt.Errorf("checking CSIDriver for token minting: %w", err)
	}
	logger.FromContext(ctx).Infof("token minter: ready, minting audience %q", EKSAuthAudience)
	return newCachedMinter(newAPIMinter(clientset), opts), nil
}
