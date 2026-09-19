package attestation

// This file ties the attestation chain together. Given an accepted connection it
// produces the attested Workload the peer belongs to, or refuses. It implements
// workloadidentity.Attestor.
//
// The order is the security argument, not an implementation detail:
//
//  1. read the kernel-attested peer credentials and pin the process (peercred.go)
//  2. resolve the PID to a pod UID from its cgroup (cgroup.go)
//  3. resolve the pod UID to a pod from the node-scoped store (podstore.go)
//  4. refuse a pod bound to another node
//  5. recheck the pinned process is still the one that connected
//  6. only then return the Workload
//
// Identity comes from the kernel and from API-server state, never from anything
// the caller sends. Every refusal is counted on its own reason so the two
// security-relevant ones (pod not in store, pod on another node) can be alarmed
// apart from the deployment and liveness failures.

import (
	"context"
	"errors"
	"net"
	"time"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// attestor resolves a connection to a Workload. Its collaborators are behind
// interfaces so the whole chain is testable with fakes and no cluster: pods is
// the node-scoped store, cgroup is the PID-to-pod-UID resolver, and newPeer is
// the peer-credential reader, defaulting to the real Unix-socket implementation.
type attestor struct {
	nodeName string
	pods     PodGetter
	cgroup   CgroupResolver
	newPeer  func(net.Conn) (peerConn, error)
}

// New returns an Attestor for the given node, pod store and cgroup resolver.
func New(nodeName string, pods PodGetter, cgroup CgroupResolver) workloadidentity.Attestor {
	return newAttestor(nodeName, pods, cgroup, peerFromConn)
}

// newAttestor is the internal constructor that takes the peer reader as a seam,
// so tests can inject a fake peer to assert the recheck ordering and drive the
// refusal paths without a real socket.
func newAttestor(nodeName string, pods PodGetter, cgroup CgroupResolver, newPeer func(net.Conn) (peerConn, error)) *attestor {
	return &attestor{
		nodeName: nodeName,
		pods:     pods,
		cgroup:   cgroup,
		newPeer:  newPeer,
	}
}

// Attest identifies the workload behind conn, or returns ErrUnattestable.
func (a *attestor) Attest(ctx context.Context, conn net.Conn) (*workloadidentity.Workload, error) {
	start := time.Now()
	log := logger.FromContext(ctx)

	peer, err := a.newPeer(conn)
	if err != nil {
		return nil, a.refuse(start, reasonForPeerErr(err), err)
	}
	defer peer.close()

	podUID, err := a.cgroup.PodUIDForPID(peer.pid())
	if err != nil {
		if errors.Is(err, ErrNoPodUID) {
			return nil, a.refuse(start, workloadidentity.ReasonCgroupNoPodUID, err)
		}
		// A read failure on /proc/<pid>/cgroup means the process is gone.
		return nil, a.refuse(start, workloadidentity.ReasonPeerGone, err)
	}

	pod, ok := a.pods.PodByUID(podUID)
	if !ok {
		// Security-relevant: a local caller resolved to a pod UID the node's
		// store does not hold. Alarmed on separately.
		return nil, a.refuse(start, workloadidentity.ReasonPodNotInStore,
			errors.New("pod UID "+podUID+" not present in node-scoped store"))
	}

	if pod.NodeName != a.nodeName {
		// Security-relevant and redundant given the field selector: a pod bound
		// to another node should never resolve here. Keeping the check turns a
		// selector regression into a refusal rather than a hole.
		return nil, a.refuse(start, workloadidentity.ReasonPodNodeMismatch,
			errors.New("pod bound to node "+pod.NodeName+", agent is on "+a.nodeName))
	}

	// The liveness recheck runs after resolution, not before: it closes the
	// window in which the pinned process could have exited while we resolved it.
	if err := peer.recheck(); err != nil {
		return nil, a.refuse(start, workloadidentity.ReasonLivenessRecheckFailed, err)
	}

	w := &workloadidentity.Workload{
		PodUID:         pod.UID,
		PodName:        pod.Name,
		Namespace:      pod.Namespace,
		ServiceAccount: pod.ServiceAccount,
		NodeName:       pod.NodeName,
	}
	promAttestationTotal.WithLabelValues(workloadidentity.OutcomeSuccess, reasonNone).Inc()
	promAttestationDuration.WithLabelValues(workloadidentity.OutcomeSuccess).Observe(time.Since(start).Seconds())
	log.Debugf("attested pod %s/%s (uid %s, sa %s) on node %s",
		w.Namespace, w.PodName, w.PodUID, w.ServiceAccount, w.NodeName)
	return w, nil
}

// refuse records the failure on both attestation metrics under reason and
// returns ErrUnattestable wrapping the cause. Returning one taxonomy member for
// every refusal keeps the caller's branching simple; the reason lives on the
// metric, not in the returned kind.
func (a *attestor) refuse(start time.Time, reason string, cause error) error {
	promAttestationTotal.WithLabelValues(workloadidentity.OutcomeFailure, reason).Inc()
	promAttestationDuration.WithLabelValues(workloadidentity.OutcomeFailure).Observe(time.Since(start).Seconds())
	return wierrors.ErrUnattestable.Wrapf(cause, "attestation refused (%s)", reason)
}

// reasonForPeerErr maps a peer-credential sentinel onto its metric reason.
func reasonForPeerErr(err error) string {
	switch {
	case errors.Is(err, errNotUnixSocket):
		return workloadidentity.ReasonNotUnixSocket
	case errors.Is(err, errPeerPIDZero):
		return workloadidentity.ReasonPeerPIDZero
	case errors.Is(err, errPeerGone):
		return workloadidentity.ReasonPeerGone
	case errors.Is(err, errLivenessRecheckFailed):
		return workloadidentity.ReasonLivenessRecheckFailed
	default:
		return workloadidentity.ReasonPeerCredFailed
	}
}
