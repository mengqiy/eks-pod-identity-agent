// Package notify is the change notification tier of the workload identity path.
// It lets an open stream learn that the material it is serving has changed,
// without the stream polling and without the tier that produced the change
// knowing which streams exist.
//
// Both serving interfaces are streaming. A SPIFFE library calls FetchX509SVID
// and holds the stream open, expecting a replacement before the current
// credential expires; Envoy does the same over SDS. Neither polls. So something
// has to wake one stream when its workload's certificate is renewed, and the
// right subset of streams when a trust bundle rotates. Keeping that in one
// package is deliberate: the handlers would otherwise each write their own
// fan-out, and only one of them would be correct.
//
// # Delivery semantics
//
// Latest value wins. Each subscription has a channel of depth one and a publish
// drains any pending signal before writing a fresh one, so a slow subscriber
// observes the newest state and never a queue of superseded ones. A buffered
// queue would hand a stream an older credential after a newer one, and a
// workload applying them in order would end up holding the older.
//
// The signal carries no payload. A subscriber wakes and re-reads the current
// value from its source. A payload-carrying channel invites a handler to serve
// what arrived in the notification, which on a slow stream is stale by
// construction. The kind of change is used to decide who is woken and is not
// delivered, so two different changes arriving before a read coalesce safely:
// the handler re-reads everything either way.
//
// Publishing never blocks. Every send is non-blocking, so a renewal loop or a
// bundle refresh is never held up by a subscriber that is not reading.
//
// Release is idempotent and also happens with the context. Streams end abruptly,
// and a leaked subscription is a leaked channel per stream on a node that may
// hold hundreds.
//
// Nothing is required to observe a notification. A subscription released between
// a publish and a read is normal, not an error.
//
// # Routing
//
// One hub serves the whole node, indexed two ways over one set of live
// subscriptions: by pod, for a workload's own material, and by provider, for
// bundle rotations. A node runs one agent and hosts the pods of however many
// identity providers its associations name, so both cardinalities are ordinary:
// many pods to one provider, and several providers at once.
//
// The alternative of one hub per provider was considered and rejected. A stream
// serving SVIDs needs both its pod's renewals and its provider's authorities on
// one channel, and splitting the hub would hand it two and push the fan-in into
// every handler. Per-pod publishing would also have to resolve a pod to its
// provider just to find the right hub, for an event that has nothing to do with
// bundles. And a per-provider hub's lifetime would follow the bundle tier's
// cache eviction rather than the streams it serves.
//
// Keeping a provider's bundles cached and refreshed while a stream waits on it is
// not this package's job. A stream takes a lease on its provider from the bundle
// tier beside its subscription, because a stream that reads only when signalled
// would otherwise look unused to that tier.
//
// This package also does not deduplicate. Only a handler knows what it last put
// on the wire, so suppressing a send that would carry unchanged material belongs
// there.
package notify

import (
	"context"
	"sync"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Hub holds every live subscription on the node and is the publishing side of
// the tier. The material tiers hold it directly, as a
// workloadidentity.BundleNotifier or a workloadidentity.WorkloadNotifier, and
// never see an RPC.
//
// Handlers do not hold it. Each one subscribes through the Subscriber that ForRPC
// returns, which is the read side plus the RPC label its subscription metrics
// carry.
//
// There is one index per publish method, so a publish walks exactly its audience
// and tests nothing as it goes. What a subscription is woken for is decided once,
// by which indexes the subscribe put it in, rather than carried on the
// subscription and re-examined on every signal.
type Hub struct {
	mu sync.Mutex
	// all is every live subscription. Membership is the liveness flag: a
	// subscription is live exactly while it is in this set, which is what makes
	// a release idempotent without a second piece of state to keep in step.
	//
	// Nothing publishes to it. It exists so that release has one authority on
	// whether a subscription is still live, whichever indexes it sits in.
	all map[*subscription]struct{}
	// byPod is the audience of NotifyWorkloadChange: the subscriptions that want
	// their pod's own material. An entry is deleted with its last subscription,
	// so the map does not grow with pod churn.
	byPod map[string]map[*subscription]struct{}
	// byProviderCert is the audience of NotifyCertBundleChange: the
	// subscriptions that want a provider's X.509 authorities, which is both the
	// workload material streams and the cert bundle streams.
	byProviderCert map[string]map[*subscription]struct{}
	// byProviderJWT is the audience of NotifyJWTBundleChange: the subscriptions
	// that want a provider's JWT authorities.
	//
	// Keeping it apart from byProviderCert rather than filtering one index is
	// what makes a JWT key roll cost nothing on the streams serving SVIDs: they
	// are not in this map, so the walk never reaches them.
	byProviderJWT map[string]map[*subscription]struct{}
}

// NewHub returns an empty Hub. It starts no goroutine and needs no shutdown: a
// subscription's lifetime is its own context's, not the hub's.
func NewHub() *Hub {
	return &Hub{
		all:            make(map[*subscription]struct{}),
		byPod:          make(map[string]map[*subscription]struct{}),
		byProviderCert: make(map[string]map[*subscription]struct{}),
		byProviderJWT:  make(map[string]map[*subscription]struct{}),
	}
}

// subscription is one open stream's registration.
//
// The channel is depth one and is never closed. Closing it would make a receive
// succeed forever after release, so a handler racing its own teardown would spin
// re-reading its source instead of returning. Release removes the subscription
// from the hub, which stops delivery; the handler's own context is what ends its
// loop.
// The pod UID and provider ARN are held only so release can find this
// subscription in the indexes it was added to. Nothing reads them to decide
// whether to signal; being in an index is what decides that.
type subscription struct {
	// podUID is the pod whose own changes reach this subscription, empty for a
	// bundle-only subscription.
	podUID string
	// providerArn is the identity provider whose authority rotations reach this
	// subscription, taken from the caller's session.
	providerArn string
	// ch carries the signals. Depth one, drained before each write.
	ch chan struct{}
	// metrics are the collectors for the RPC this subscription was taken out
	// for. Shared by every subscription of that RPC and safe to use
	// concurrently.
	metrics *rpcMetrics
}

// signalLocked delivers one notification. The caller must hold Hub.mu, which is
// what makes the drain and the write a single step with respect to other
// publishers: no other publish can write between them, so the depth-one channel
// cannot end up holding two signals.
//
// A concurrent reader is harmless. It either takes the pending signal before the
// drain, in which case the write lands in an empty channel, or it takes the one
// written here. Either way the subscriber wakes and re-reads the newest state,
// which is the only guarantee this tier makes.
func (s *subscription) signalLocked() {
	// Draining tells a signal that replaced an unread one from a signal the
	// subscriber had nothing pending for. The label is the only thing that
	// distinguishes them; the subscriber cannot tell and does not need to.
	select {
	case <-s.ch:
		s.metrics.coalesced.Inc()
	default:
		s.metrics.signalled.Inc()
	}

	// The default arm cannot be reached while Hub.mu is held, since the drain
	// above leaves room and only a publisher writes. It is here so that a future
	// caller that reaches this without the lock degrades to a dropped signal
	// rather than deadlocking a renewal loop.
	select {
	case s.ch <- struct{}{}:
	default:
	}
}

// Subscriber is the view of a Hub that one RPC's handler subscribes through. It
// satisfies workloadidentity.Subscriber and carries no publishing method, so a
// handler cannot wake another pod's stream or another provider's.
type Subscriber struct {
	hub     *Hub
	metrics *rpcMetrics
}

// ForRPC returns the Subscriber the handler for one RPC subscribes through.
//
// rpc is that RPC's LabelRPC value, one of the workloadidentity RPC constants,
// and is the same value the handler puts on MetricRPCTotal. Binding it once here
// rather than passing it on every Subscribe is what keeps the RPC label off the
// Subscriber interface: a handler that already knows which RPC it is should not
// have to say so on every call, and a label resolved at wiring time cannot be
// wrong on one call path and right on another.
//
// Call it once per RPC at wiring time. It panics on an empty rpc, which is a
// wiring bug and would otherwise produce an unlabelled series that no dashboard
// looks at.
func (h *Hub) ForRPC(rpc string) *Subscriber {
	if rpc == "" {
		panic("notify: ForRPC called with an empty rpc label")
	}
	return &Subscriber{hub: h, metrics: metricsForRPC(rpc)}
}

// SubscribeToWorkloadMaterial registers a subscription woken by the workload's
// own credential changes and by its provider's X.509 authority rotations.
//
// A nil workload, or one with an empty pod UID, yields a subscription that
// receives no per-pod signal. That is a degenerate case rather than a supported
// one: every caller attests before it subscribes, so it has a pod UID to pass.
func (s *Subscriber) SubscribeToWorkloadMaterial(ctx context.Context, w *workloadidentity.Workload, providerArn string) (<-chan struct{}, func()) {
	podUID := ""
	if w != nil {
		podUID = w.PodUID
	}
	// The only subscription that joins two audiences: its pod's own material and
	// the X.509 authorities that verify the peers it serves an SVID to.
	return s.hub.subscribe(ctx, s.metrics, podUID, providerArn, func(h *Hub, sub *subscription) {
		addLocked(h.byPod, podUID, sub)
		addLocked(h.byProviderCert, providerArn, sub)
	})
}

// SubscribeToCertBundles registers a subscription woken only by the provider's
// X.509 authority rotations.
func (s *Subscriber) SubscribeToCertBundles(ctx context.Context, providerArn string) (<-chan struct{}, func()) {
	return s.hub.subscribe(ctx, s.metrics, "", providerArn, func(h *Hub, sub *subscription) {
		addLocked(h.byProviderCert, providerArn, sub)
	})
}

// SubscribeToJWTBundles registers a subscription woken only by the provider's
// JWT authority rotations.
func (s *Subscriber) SubscribeToJWTBundles(ctx context.Context, providerArn string) (<-chan struct{}, func()) {
	return s.hub.subscribe(ctx, s.metrics, "", providerArn, func(h *Hub, sub *subscription) {
		addLocked(h.byProviderJWT, providerArn, sub)
	})
}

// subscribe registers one subscription in the audiences index puts it in, and
// returns its channel and its release func.
//
// Each Subscribe method passes its own index func, which is the only thing that
// differs between them. Nothing is rejected here: a subscribe that cannot fail is
// what keeps the handler's error mapping at the call that produced a missing
// value, which for a missing provider is the session read returning
// ErrNotEnrolled.
//
// The subscription also ends with ctx, through context.AfterFunc rather than a
// goroutine parked on ctx.Done(). A goroutine per subscription would be a
// goroutine per open stream on a node holding hundreds, and AfterFunc costs
// nothing until the context is actually done.
func (h *Hub) subscribe(ctx context.Context, metrics *rpcMetrics, podUID, providerArn string, index func(*Hub, *subscription)) (<-chan struct{}, func()) {
	sub := &subscription{
		podUID:      podUID,
		providerArn: providerArn,
		ch:          make(chan struct{}, 1),
		metrics:     metrics,
	}

	// A subscribe under a done context registers nothing. Its stream is already
	// over, so there is nobody to wake, and registering would put an entry in the
	// indexes for every publish to walk until the context hook got to it.
	//
	// The channel is still returned, never signalled, because a handler selects on
	// it beside its own context and that context is what ends its loop.
	if ctx.Err() != nil {
		return sub.ch, func() {}
	}

	// Prime the channel: the subscription starts with one signal pending, so a
	// handler's loop is wait-then-send and its first pass produces the initial
	// response. Without it a stream would serve nothing until the first real
	// change, which could be hours away.
	//
	// This happens before the subscription is reachable by a publish, which is
	// what makes the unguarded send safe: nothing else can have filled the
	// channel yet. A publish arriving afterwards drains and replaces this signal
	// rather than queueing behind it, so the handler still wakes once and reads
	// the newest state.
	//
	// It is deliberately not counted on the notification metric. The prime is not
	// a change, and counting it would put one signalled per stream open into a
	// counter that is read as a rate of change.
	sub.ch <- struct{}{}

	h.mu.Lock()
	h.all[sub] = struct{}{}
	index(h, sub)
	h.mu.Unlock()

	metrics.active.Inc()

	// stop deregisters the ctx hook, so releasing explicitly does not leave the
	// hook attached to a long-lived context.
	stop := context.AfterFunc(ctx, func() { h.release(sub) })
	release := func() {
		stop()
		h.release(sub)
	}
	return sub.ch, release
}

// release ends one subscription. It is idempotent, and safe to call concurrently
// with a publish, because membership in h.all is both the liveness flag and what
// decides whether there is anything left to remove.
//
// The gauge is decremented outside the lock and only by the call that removed the
// subscription, so an explicit release racing the context hook moves it once.
func (h *Hub) release(sub *subscription) {
	h.mu.Lock()
	_, live := h.all[sub]
	if live {
		delete(h.all, sub)
		// A subscription is in at most one of the two provider indexes, and
		// removeLocked tolerates an absent one, so release does not have to
		// remember which audiences the subscribe chose.
		removeLocked(h.byPod, sub.podUID, sub)
		removeLocked(h.byProviderCert, sub.providerArn, sub)
		removeLocked(h.byProviderJWT, sub.providerArn, sub)
	}
	h.mu.Unlock()

	if !live {
		return
	}

	sub.metrics.active.Dec()

	// Drain whatever was pending. The subscription is out of the indexes, so no
	// publish can refill it, and a handler racing its own teardown then finds the
	// channel empty and waits on its context rather than being woken to re-read a
	// stream it is already returning from.
	select {
	case <-sub.ch:
	default:
	}
}

// NotifyWorkloadChange signals every workload-material subscription taken out
// for the pod. The per-pod material tiers call it when a pod's SVID is renewed.
//
// A pod with no open stream is not an error and costs one map lookup, which is
// the common case for a renewal of a pod whose library is between streams.
func (h *Hub) NotifyWorkloadChange(podUID string) {
	if podUID == "" {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Every subscription in byPod asked for its pod's material, so there is
	// nothing to filter here.
	for sub := range h.byPod[podUID] {
		sub.signalLocked()
	}
}

// NotifyCertBundleChange signals the provider's subscriptions that take X.509
// authorities, which is both the workload material streams and the cert bundle
// streams. The bundle tier calls it once per real change in that set.
func (h *Hub) NotifyCertBundleChange(providerArn string) {
	h.notifyProvider(h.byProviderCert, providerArn)
}

// NotifyJWTBundleChange signals the provider's JWT bundle subscriptions. The
// bundle tier calls it once per real change in that set.
//
// It is separate from NotifyCertBundleChange because the two sets rotate
// independently. A JWT key roll reaches only the streams serving JWT
// authorities, so it does not wake every SVID stream on the node for a change
// none of them can observe. A fetch that changed both sets is two calls, and no
// subscription is in both populations, so neither call wakes the other's
// subscribers.
func (h *Hub) NotifyJWTBundleChange(providerArn string) {
	h.notifyProvider(h.byProviderJWT, providerArn)
}

// notifyProvider signals every subscription index holds for the provider. The
// index is the audience, so there is nothing to test as it is walked.
//
// It walks one provider's entry under the lock and allocates nothing per
// subscription, because a rotation can touch every stream of a provider at once.
// Holding one lock across the fan-out serialises it against concurrent
// subscribes and releases; each signal is a channel drain, a non-blocking send
// and an atomic counter increment, so the walk is short, and a lock per
// subscription would cost more than it saves at the few hundred subscriptions a
// node is expected to hold. If that stops being true the shape to reach for is a
// sharded hub, not copying the index, which would allocate on the path this
// comment exists to keep allocation-free.
func (h *Hub) notifyProvider(index map[string]map[*subscription]struct{}, providerArn string) {
	if providerArn == "" {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	for sub := range index[providerArn] {
		sub.signalLocked()
	}
}

// addLocked records sub under key, creating the key's set on first use. The
// caller holds Hub.mu.
//
// An empty key is dropped rather than indexed. A subscription with no pod UID or
// no provider ARN can never be signalled, since both publish paths refuse an
// empty key, so indexing it would only leave an entry that nothing reads and that
// removeLocked, which also skips an empty key, would never clear.
func addLocked(index map[string]map[*subscription]struct{}, key string, sub *subscription) {
	if key == "" {
		return
	}
	subs := index[key]
	if subs == nil {
		subs = make(map[*subscription]struct{})
		index[key] = subs
	}
	subs[sub] = struct{}{}
}

// removeLocked drops sub from under key and drops the key with its last
// subscription, so neither index grows with pod or provider churn. An empty key,
// or a sub that was never in this index, is a no-op. The caller holds Hub.mu.
func removeLocked(index map[string]map[*subscription]struct{}, key string, sub *subscription) {
	if key == "" {
		return
	}
	subs := index[key]
	if subs == nil {
		return
	}
	delete(subs, sub)
	if len(subs) == 0 {
		delete(index, key)
	}
}

// The hub is the one implementation of all three sides of the tier, handed out
// as the publishing interfaces directly and as the read side through ForRPC.
var (
	_ workloadidentity.BundleNotifier   = (*Hub)(nil)
	_ workloadidentity.WorkloadNotifier = (*Hub)(nil)
	_ workloadidentity.Subscriber       = (*Subscriber)(nil)
)
