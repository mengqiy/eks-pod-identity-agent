package tokenminter

// Verifies the spiffe.csi.eks.amazonaws.com CSIDriver, whose spec.tokenRequests
// declaration clears the 1.33 ServiceAccountNodeAudienceRestriction for the EKS
// Auth audience; without it every mint is refused.
//
// The object is cluster-scoped and belongs to the agent's Helm chart, not to the
// agent: one object per cluster, installed and versioned with the chart. The
// agent never creates or mutates it, so nothing here writes. Every node running
// a create would race its peers and the chart over a resource none of them owns.
//
// What is left is a read-only pre-flight, and it is advisory only. A missing or
// misdeclared object is logged once at startup rather than failing it, because
// the agent cannot fix either and because a chart that applies the object after
// the DaemonSet rolls would otherwise crash-loop every node over a race it wins
// seconds later. The condition still surfaces per mint as ErrTokenMintForbidden,
// with the token_mint_forbidden metric label pointing back here.

import (
	"context"
	"fmt"

	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

// CSIDriverName is the driver the enrolled pod mounts for the SPIFFE socket and
// whose tokenRequests declaration clears the node audience restriction. It is
// part of the webhook/CSI/agent contract, so it is aliased from configuration
// rather than copied.
const CSIDriverName = configuration.WorkloadIdentityCSIDriver

// VerifyCSIDriverExists reports whether the CSIDriver the mint depends on exists
// and declares the EKS Auth audience. It is read-only: the object is installed
// by the Helm chart.
//
// Absent, misdeclared, or unreadable is a warning rather than an error — none of
// those are the agent's to fix, and each one surfaces again per mint as
// ErrTokenMintForbidden. Only an unexpected API failure is returned, so startup
// can distinguish a broken API server from a cluster that is merely not set up
// yet.
func VerifyCSIDriverExists(ctx context.Context, client kubernetes.Interface) error {
	log := logger.FromContext(ctx)

	existing, err := client.StorageV1().CSIDrivers().Get(ctx, CSIDriverName, metav1.GetOptions{})
	switch {
	case err == nil:
		if !declaresAudience(existing, EKSAuthAudience) {
			log.Warnf("CSIDriver %q exists but does not declare tokenRequests audience %q; "+
				"mints will be refused until the chart that owns it does",
				CSIDriverName, EKSAuthAudience)
			return nil
		}
		log.Infof("CSIDriver %q declares tokenRequests audience %q", CSIDriverName, EKSAuthAudience)
		return nil
	case apierrors.IsNotFound(err):
		log.Warnf("CSIDriver %q not found; it is installed by the agent's Helm chart and "+
			"mints are refused until it exists", CSIDriverName)
		return nil
	case apierrors.IsForbidden(err):
		log.Warnf("not permitted to read CSIDriver %q (%v); skipping the pre-flight check",
			CSIDriverName, err)
		return nil
	default:
		return fmt.Errorf("getting CSIDriver %q: %w", CSIDriverName, err)
	}
}

// declaresAudience reports whether driver's tokenRequests contains audience.
func declaresAudience(driver *storagev1.CSIDriver, audience string) bool {
	for _, tr := range driver.Spec.TokenRequests {
		if tr.Audience == audience {
			return true
		}
	}
	return false
}
