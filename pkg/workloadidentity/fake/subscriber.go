package fake

import (
	"context"
	"slices"
	"sync"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// SubscriptionKind is which of the three Subscriber methods handed out a
// Subscription, so a test can tell them apart in Subscriptions().
type SubscriptionKind string

const (
	// KindWorkloadMaterial is a subscription from SubscribeToWorkloadMaterial.
	// It receives NotifyWorkloadChange for its pod and NotifyCertBundleChange
	// for its provider.
	KindWorkloadMaterial SubscriptionKind = "workload_material"
	// KindCertBundles is a subscription from SubscribeToCertBundles. It receives
	// NotifyCertBundleChange for its provider only.
	KindCertBundles SubscriptionKind = "cert_bundles"
	// KindJWTBundles is a subscription from SubscribeToJWTBundles. It receives
	// NotifyJWTBundleChange for its provider only.
	KindJWTBundles SubscriptionKind = "jwt_bundles"
)

// Subscription is one subscription handed out by one of Subscriber's Subscribe
// methods. A test reaches it through Subscriber.Subscriptions.
//
// The channel is behind Chan rather than being an exported field, because the
// fake writes to it from whichever goroutine calls a Notify method while a test
// reads it, and an accessor keeps the fake free to close it under CloseOnCancel
// without a test having captured a stale field. Chan returns the same channel
// that Subscribe returned to the subscriber, so a test can read the signals the
// subscriber would see.
type Subscription struct {
	// Kind is which Subscribe method produced this subscription.
	Kind SubscriptionKind
	// Workload is the workload SubscribeToWorkloadMaterial was called with, nil
	// for a bundle subscription, which has no workload to pass.
	Workload *workloadidentity.Workload
	// ProviderArn is the provider ARN the subscribe was called with.
	ProviderArn string

	mu            sync.Mutex
	ch            chan struct{}
	ctx           context.Context
	cancelled     bool
	closeOnCancel bool
	notified      int
}

// Chan is the channel Subscribe handed to the subscriber.
func (s *Subscription) Chan() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ch
}

// Live reports whether the subscription still receives signals. It stops being
// live once its release func has run or its subscribe ctx is done.
//
// A zero-valued Subscription is one no Subscribe handed out, so it carries no
// ctx and no channel. It reports live and every accessor on it answers instead of
// panicking, but nothing is ever delivered to it, because there is no channel for
// a signal to land in.
func (s *Subscription) Live() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.liveLocked()
}

// Notified reports how many signals landed in the subscription's channel. A
// signal dropped because the buffer was already full is not counted, since the
// pending signal it coalesced into is still there to be read.
func (s *Subscription) Notified() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.notified
}

// liveLocked reports whether the subscription still receives signals. The caller
// must hold s.mu.
func (s *Subscription) liveLocked() bool {
	if s.cancelled {
		return false
	}
	if s.ctx == nil {
		return true
	}
	select {
	case <-s.ctx.Done():
		return false
	default:
		return true
	}
}

// notify performs one non-blocking send and reports whether the signal landed.
func (s *Subscription) notify() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.liveLocked() {
		return false
	}
	select {
	case s.ch <- struct{}{}:
		s.notified++
		return true
	default:
		return false
	}
}

// cancel marks the subscription dead and reports whether this call is the one
// that did it, so a repeated release is a no-op.
func (s *Subscription) cancel() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancelled {
		return false
	}
	s.cancelled = true
	if s.closeOnCancel {
		close(s.ch)
	}
	return true
}

// wantsCertBundle reports whether a change in a provider's X.509 authorities
// reaches this subscription, which is true for the two kinds that serve them.
func (s *Subscription) wantsCertBundle() bool {
	return s.Kind == KindWorkloadMaterial || s.Kind == KindCertBundles
}

// Subscriber is a fake workloadidentity.Subscriber, and also a fake
// WorkloadNotifier and BundleNotifier, so one value can stand in for whichever
// side of the notification tier a test is driving. It hands out a channel per
// subscribe, counts calls, and lets a test signal one pod's subscriptions or one
// provider's.
//
// Set the fields before the fake is used; they are not safe to write once a call
// can be in flight. The fake has no setters because it has no canned return
// value to change: a subscribe cannot fail, and delivery is driven by the Notify
// methods instead.
type Subscriber struct {
	Gate

	// Buffer sizes each subscription's channel. Defaults to 1 when zero, which
	// is the coalescing shape the notification tier uses.
	Buffer int
	// CloseOnCancel closes a subscription's channel when its release func runs.
	// Off by default, because the real tier never closes a subscription channel:
	// a closed channel receives forever, which would spin a handler racing its
	// own teardown. It is here for a test that wants to prove its loop does not
	// depend on that.
	CloseOnCancel bool
	// Func, when non-nil, wins: every subscribe returns whatever it returns and
	// records no Subscription, so Subscriptions, the Notify methods and
	// CancelCalls see nothing of that call. SubscribeCalls still counts it.
	//
	// It is handed the kind, so one Func can serve all three methods, and a nil
	// workload for the two bundle kinds.
	Func func(ctx context.Context, kind SubscriptionKind, w *workloadidentity.Workload, providerArn string) (<-chan struct{}, func())

	mu              sync.Mutex
	subscribeCalls  int
	certBundleCalls int
	jwtBundleCalls  int
	workloadChanges []string
	cancelCalls     int
	subs            []*Subscription
}

// SubscribeToWorkloadMaterial records a KindWorkloadMaterial Subscription for w
// and the provider, and returns its channel and a release func.
func (s *Subscriber) SubscribeToWorkloadMaterial(ctx context.Context, w *workloadidentity.Workload, providerArn string) (<-chan struct{}, func()) {
	return s.subscribe(ctx, KindWorkloadMaterial, w, providerArn)
}

// SubscribeToCertBundles records a KindCertBundles Subscription for the
// provider. Its Workload is nil, which is what tells it apart from a workload
// material subscription in Subscriptions().
func (s *Subscriber) SubscribeToCertBundles(ctx context.Context, providerArn string) (<-chan struct{}, func()) {
	return s.subscribe(ctx, KindCertBundles, nil, providerArn)
}

// SubscribeToJWTBundles records a KindJWTBundles Subscription for the provider.
func (s *Subscriber) SubscribeToJWTBundles(ctx context.Context, providerArn string) (<-chan struct{}, func()) {
	return s.subscribe(ctx, KindJWTBundles, nil, providerArn)
}

// subscribe is what all three Subscribe methods record through.
//
// It parks at the Gate first, so a test can hold a subscribe open. A subscribe
// has no error return, so a Gate error cannot be reported and is discarded: a
// call that arrives with a done ctx, or that is woken by ctx rather than by
// Release, still gets a usable channel and release func. That subscription is
// live until its ctx is observed done, which for an already done ctx means it
// never receives a signal.
//
// The call is counted and its Subscription recorded under one lock, so a test
// polling SubscribeCalls as a synchronisation point can never see the count move
// while Subscriptions and LiveSubscriptions still know nothing of the call. Func
// is invoked after the lock is dropped, so a Func that calls back into the fake
// does not deadlock.
func (s *Subscriber) subscribe(ctx context.Context, kind SubscriptionKind, w *workloadidentity.Workload, providerArn string) (<-chan struct{}, func()) {
	// The Gate error is deliberately ignored; see the doc comment.
	_ = s.enter(ctx)

	s.mu.Lock()
	s.subscribeCalls++
	fn, buffer, closeOnCancel := s.Func, s.Buffer, s.CloseOnCancel
	var sub *Subscription
	if fn == nil {
		if buffer <= 0 {
			buffer = 1
		}
		sub = &Subscription{
			Kind:          kind,
			Workload:      w,
			ProviderArn:   providerArn,
			ch:            make(chan struct{}, buffer),
			ctx:           ctx,
			closeOnCancel: closeOnCancel,
		}
		// A live subscribe comes back primed, as the real tier does, so a handler
		// written as wait-then-send produces its initial response. The prime is
		// not a notification: it does not count on Notified, and a subscribe
		// under a done ctx is not primed, because its stream is already over.
		if ctx == nil || ctx.Err() == nil {
			sub.ch <- struct{}{}
		}
		s.subs = append(s.subs, sub)
	}
	s.mu.Unlock()

	if fn != nil {
		return fn(ctx, kind, w, providerArn)
	}
	return sub.ch, func() { s.cancelSubscription(sub) }
}

// NotifyWorkloadChange signals the live workload material subscriptions for the
// pod, so the fake satisfies workloadidentity.WorkloadNotifier. A test asserting
// on delivery calls NotifyWorkload, which reports how many received the signal.
func (s *Subscriber) NotifyWorkloadChange(podUID string) {
	_ = s.NotifyWorkload(podUID)
}

// NotifyCertBundleChange signals the live subscriptions of the provider that take
// X.509 authorities. A test asserting on delivery calls NotifyCertBundles.
func (s *Subscriber) NotifyCertBundleChange(providerArn string) {
	_ = s.NotifyCertBundles(providerArn)
}

// NotifyJWTBundleChange signals the live JWT bundle subscriptions of the
// provider. A test asserting on delivery calls NotifyJWTBundles.
func (s *Subscriber) NotifyJWTBundleChange(providerArn string) {
	_ = s.NotifyJWTBundles(providerArn)
}

// NotifyWorkload signals only the live workload material subscriptions whose
// workload has the given pod UID, and returns how many received the signal.
//
// A bundle subscription never matches, since it carries no workload, and neither
// does a subscription whose workload is nil. Delivery is a non-blocking send, so
// it coalesces: a subscription whose buffer is already full is not counted, and
// the pending signal it coalesced into is still there to be read.
func (s *Subscriber) NotifyWorkload(podUID string) int {
	s.mu.Lock()
	s.workloadChanges = append(s.workloadChanges, podUID)
	subs := slices.Clone(s.subs)
	s.mu.Unlock()

	return notifyMatching(subs, func(sub *Subscription) bool {
		return sub.Kind == KindWorkloadMaterial && sub.Workload != nil && sub.Workload.PodUID == podUID
	})
}

// NotifyCertBundles signals the live subscriptions of the provider that take
// X.509 authorities, which is both the workload material and the cert bundle
// kinds, and returns how many received the signal.
//
// A JWT bundle subscription never matches, and nor does a subscription of
// another provider. An empty ARN matches the subscriptions that were taken out
// with one, which is a degenerate case the real tier declines to signal at all.
func (s *Subscriber) NotifyCertBundles(providerArn string) int {
	s.mu.Lock()
	s.certBundleCalls++
	subs := slices.Clone(s.subs)
	s.mu.Unlock()

	return notifyMatching(subs, func(sub *Subscription) bool {
		return sub.wantsCertBundle() && sub.ProviderArn == providerArn
	})
}

// NotifyJWTBundles signals the live JWT bundle subscriptions of the provider and
// returns how many received the signal. No other kind matches, which is what
// makes a JWT key roll invisible to the streams serving SVIDs.
func (s *Subscriber) NotifyJWTBundles(providerArn string) int {
	s.mu.Lock()
	s.jwtBundleCalls++
	subs := slices.Clone(s.subs)
	s.mu.Unlock()

	return notifyMatching(subs, func(sub *Subscription) bool {
		return sub.Kind == KindJWTBundles && sub.ProviderArn == providerArn
	})
}

// notifyMatching signals every subscription match reports true for and returns
// how many took the signal.
func notifyMatching(subs []*Subscription, match func(*Subscription) bool) int {
	notified := 0
	for _, sub := range subs {
		if !match(sub) {
			continue
		}
		if sub.notify() {
			notified++
		}
	}
	return notified
}

// Subscriptions returns a copy of the subscriptions handed out so far, in
// subscribe order and including released ones, so it is safe to read while
// another goroutine is calling the fake. The Subscription values themselves are
// shared and safe to use concurrently.
func (s *Subscriber) Subscriptions() []*Subscription {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.subs)
}

// SubscribeCalls reports how many times any of the three Subscribe methods has
// been called, including calls served by Func. A call woken by Release is counted
// when it is next scheduled, not when Release returns. Once it is counted, its
// Subscription is already recorded, because a subscribe does both under one lock.
func (s *Subscriber) SubscribeCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.subscribeCalls
}

// WorkloadChanges reports the pod UID of every per-pod publish, in call order,
// whether it arrived through NotifyWorkloadChange or NotifyWorkload.
//
// It records the UIDs rather than counting calls because that is what the
// material tiers are asserted on: T7 has to publish once per successful store
// with the pod's own UID, and not at all on a failed renewal or an eviction, and
// a count alone cannot tell those apart.
func (s *Subscriber) WorkloadChanges() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.workloadChanges)
}

// CertBundleCalls reports how many times the X.509 authority publish has been
// called, by either NotifyCertBundleChange or NotifyCertBundles.
func (s *Subscriber) CertBundleCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.certBundleCalls
}

// JWTBundleCalls reports how many times the JWT authority publish has been
// called, by either NotifyJWTBundleChange or NotifyJWTBundles.
func (s *Subscriber) JWTBundleCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwtBundleCalls
}

// CancelCalls reports how many subscriptions have been released. The release func
// is idempotent, so releasing the same subscription twice counts once.
func (s *Subscriber) CancelCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cancelCalls
}

// LiveSubscriptions reports how many subscriptions still receive signals, that
// is, how many are neither released nor carrying a done ctx.
func (s *Subscriber) LiveSubscriptions() int {
	s.mu.Lock()
	subs := slices.Clone(s.subs)
	s.mu.Unlock()

	live := 0
	for _, sub := range subs {
		if sub.Live() {
			live++
		}
	}
	return live
}

// cancelSubscription is what the release func returned by a subscribe runs. It is
// idempotent, stops all further delivery to that subscription, and is safe to
// call concurrently with the Notify methods. The subscription's lock is released
// before the fake's, so releasing never nests the two.
func (s *Subscriber) cancelSubscription(sub *Subscription) {
	if !sub.cancel() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancelCalls++
}

// The fake serves all three sides of the notification tier, so one value can
// stand in for the read side a handler holds and for either publishing side a
// material tier holds.
var (
	_ workloadidentity.Subscriber       = &Subscriber{}
	_ workloadidentity.BundleNotifier   = &Subscriber{}
	_ workloadidentity.WorkloadNotifier = &Subscriber{}
)
