package attestation

// This file covers the pod-resolution link in the attestation chain: turning a
// pod UID into the pod object it belongs to, from a store scoped to this node.
//
// The store is backed by an informer whose list and watch carry a
// spec.nodeName field selector equal to the agent's node. The selector is not an
// optimisation. Under the Node authorizer the agent's node credential can only
// read pods bound to its own node, so the selector is the read authority made
// explicit, and it is what keeps a local caller from ever resolving to a pod on
// another node. The redundant node recheck in the attestor turns a selector
// regression from a security hole into a refused request.

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// podResyncInterval is how often the informer relists. Attestation reads the
// cache, never the API server, so a resync only reconciles against missed
// watch events; a slow, cheap period is right.
const podResyncInterval = 10 * time.Minute

// podByUIDIndex is the informer index that keys pods by their UID, which is the
// identifier the cgroup path yields. The default informer index is by
// namespace/name, which attestation never has.
const podByUIDIndex = "byPodUID"

// PodInfo is the subset of a pod the attestor needs. It is a flat value rather
// than a *corev1.Pod so the store owns the projection and callers cannot reach
// into pod fields the attested identity does not depend on.
type PodInfo struct {
	// UID is the pod's Kubernetes UID.
	UID string
	// Name is the pod's name.
	Name string
	// Namespace is the pod's namespace.
	Namespace string
	// ServiceAccount is the pod's ServiceAccount name.
	ServiceAccount string
	// NodeName is the node the pod is scheduled on.
	NodeName string
}

// PodGetter resolves a pod UID to the pod it belongs to, from the node-scoped
// store. It is a small interface so the attestor is testable with a fake store
// and no cluster.
type PodGetter interface {
	// PodByUID returns the pod with the given UID and true, or false when no pod
	// on this node has that UID.
	PodByUID(uid string) (*PodInfo, bool)
}

// PodStore is a node-scoped view of pods backed by a shared informer.
type PodStore struct {
	indexer cache.Indexer
}

// podUIDIndexFunc keys a pod object by its UID for the byPodUID index.
func podUIDIndexFunc(obj interface{}) ([]string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected *corev1.Pod, got %T", obj)
	}
	return []string{string(pod.UID)}, nil
}

// NewPodStore builds a pod store scoped to nodeName, starts its informer, and
// blocks until the cache has synced or ctx is done. The field selector is what
// scopes the list and watch to this node; it is applied through the informer
// factory so both the initial list and the ongoing watch carry it.
func NewPodStore(ctx context.Context, clientset kubernetes.Interface, nodeName string) (*PodStore, error) {
	if nodeName == "" {
		return nil, fmt.Errorf("node name is required to scope the pod store")
	}

	nodeSelector := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
	factory := informers.NewSharedInformerFactoryWithOptions(
		clientset,
		podResyncInterval,
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = nodeSelector
		}),
	)

	podInformer := factory.Core().V1().Pods().Informer()
	if err := podInformer.AddIndexers(cache.Indexers{podByUIDIndex: podUIDIndexFunc}); err != nil {
		return nil, fmt.Errorf("adding pod UID indexer: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		return nil, fmt.Errorf("pod informer cache failed to sync for node %q", nodeName)
	}

	return &PodStore{indexer: podInformer.GetIndexer()}, nil
}

// newPodStoreFromIndexer wraps a prepopulated indexer. It exists so the lookup
// and projection logic can be tested without an informer or a cluster.
func newPodStoreFromIndexer(indexer cache.Indexer) *PodStore {
	return &PodStore{indexer: indexer}
}

// PodByUID returns the pod with uid from the node-scoped cache. A UID absent
// from the store is a clean miss, which the attestor treats as an unresolvable
// caller rather than an error.
func (s *PodStore) PodByUID(uid string) (*PodInfo, bool) {
	objs, err := s.indexer.ByIndex(podByUIDIndex, uid)
	if err != nil || len(objs) == 0 {
		return nil, false
	}
	pod, ok := objs[0].(*corev1.Pod)
	if !ok {
		return nil, false
	}
	return &PodInfo{
		UID:            string(pod.UID),
		Name:           pod.Name,
		Namespace:      pod.Namespace,
		ServiceAccount: pod.Spec.ServiceAccountName,
		NodeName:       pod.Spec.NodeName,
	}, true
}
