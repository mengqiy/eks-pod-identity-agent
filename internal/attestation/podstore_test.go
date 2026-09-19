package attestation

import (
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// indexerWithPods builds a real UID-indexed cache holding pods, so the store's
// lookup and projection are exercised without an informer or a cluster.
func indexerWithPods(t *testing.T, pods ...*corev1.Pod) cache.Indexer {
	t.Helper()
	g := NewWithT(t)

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{podByUIDIndex: podUIDIndexFunc})
	for _, p := range pods {
		g.Expect(indexer.Add(p)).To(Succeed())
	}
	return indexer
}

func pod(uid, name, ns, sa, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			UID:       types.UID(uid),
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: sa,
			NodeName:           node,
		},
	}
}

// TestPodByUID_FoundAndProjected proves a present pod comes back projected onto
// PodInfo with every field mapped.
func TestPodByUID_FoundAndProjected(t *testing.T) {
	g := NewWithT(t)

	store := newPodStoreFromIndexer(indexerWithPods(t,
		pod(testPodUID, "web-0", "team-a", "web", testNode)))

	got, ok := store.PodByUID(testPodUID)

	g.Expect(ok).To(BeTrue())
	g.Expect(got).To(Equal(&PodInfo{
		UID:            testPodUID,
		Name:           "web-0",
		Namespace:      "team-a",
		ServiceAccount: "web",
		NodeName:       testNode,
	}))
}

// TestPodByUID_Missing proves an absent UID is a clean miss, not an error, so
// the attestor treats it as an unresolvable caller.
func TestPodByUID_Missing(t *testing.T) {
	g := NewWithT(t)

	store := newPodStoreFromIndexer(indexerWithPods(t))

	got, ok := store.PodByUID(testPodUID)

	g.Expect(ok).To(BeFalse())
	g.Expect(got).To(BeNil())
}

// TestNewPodStore_RequiresNodeName proves the store refuses to build without a
// node name, since an empty selector would scope the watch to the whole cluster.
func TestNewPodStore_RequiresNodeName(t *testing.T) {
	g := NewWithT(t)

	_, err := NewPodStore(t.Context(), nil, "")

	g.Expect(err).To(HaveOccurred())
}
