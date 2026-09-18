package fake

import (
	"context"
	"slices"
	"sync"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Subscription is one subscription handed out by Subscriber.Subscribe. A test
// reaches it through Subscriber.Subscriptions.
//
// The channel is behind Chan rather than being an exported field, because the
// fake writes to it from whichever goroutine calls Notify or
// BroadcastBundleChange while a test reads it, and an accessor keeps the fake
// free to close it under CloseOnCancel without a test having captured a stale
// field. Chan returns the same channel that Subscribe returned to the
// subscriber, so a test can read the signals the subscriber would see.
type Subscription struct {
	// Workload is the workload Subscribe was called with. It is written before
	// the subscription is visible to any other goroutine and never written
	// again, so it is safe to read.
	Workload *workloadidentity.Workload

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
// live once its cancel func has run or its Subscribe ctx is done.
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
// that did it, so a repeated cancel is a no-op.
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

// Subscriber is a fake workloadidentity.Subscriber. It hands out a channel per
// Subscribe, counts subscribes, broadcasts and cancels, and lets a test signal
// every subscription or only the ones for one pod.
//
// Set the fields before the fake is used; they are not safe to write once a call
// can be in flight. The fake has no setters because it has no canned return
// value to change: Subscribe cannot fail, and delivery is driven by Notify and
// BroadcastBundleChange instead.
type Subscriber struct {
	Gate

	// Buffer sizes each subscription's channel. Defaults to 1 when zero, which
	// is the coalescing shape the notification tier is expected to use.
	Buffer int
	// CloseOnCancel closes a subscription's channel when its cancel func runs.
	// Off by default: the notification tier settles the real semantics and this
	// fake stays neutral.
	CloseOnCancel bool
	// Func, when non-nil, wins: Subscribe returns whatever it returns and
	// records no Subscription, so Subscriptions, Notify,
	// BroadcastBundleChange and CancelCalls see nothing of that call.
	// SubscribeCalls still counts it.
	Func func(ctx context.Context, w *workloadidentity.Workload) (<-chan struct{}, func())

	mu             sync.Mutex
	subscribeCalls int
	broadcastCalls int
	cancelCalls    int
	subs           []*Subscription
}

// Subscribe records a Subscription for w and returns its channel and a cancel
// func.
//
// It parks at the Gate first, so a test can hold a subscribe open. Subscribe has
// no error return, so a Gate error cannot be reported and is discarded: a call
// that arrives with a done ctx, or that is woken by ctx rather than by Release,
// still gets a usable channel and cancel func. That subscription is live until
// its ctx is observed done, which for an already done ctx means it never receives
// a signal.
//
// The call is counted and its Subscription recorded under one lock, so a test
// polling SubscribeCalls as a synchronisation point can never see the count move
// while Subscriptions and LiveSubscriptions still know nothing of the call. Func
// is invoked after the lock is dropped, so a Func that calls back into the fake
// does not deadlock.
func (s *Subscriber) Subscribe(ctx context.Context, w *workloadidentity.Workload) (<-chan struct{}, func()) {
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
			Workload:      w,
			ch:            make(chan struct{}, buffer),
			ctx:           ctx,
			closeOnCancel: closeOnCancel,
		}
		s.subs = append(s.subs, sub)
	}
	s.mu.Unlock()

	if fn != nil {
		return fn(ctx, w)
	}
	return sub.ch, func() { s.cancelSubscription(sub) }
}

// BroadcastBundleChange signals every live subscription. It takes no ctx, so it
// does not go through the Gate and only counts.
//
// Delivery is a non-blocking send, so a broadcast with nobody reading never
// blocks the fake. With the default buffer of 1 that coalesces: a second
// broadcast before the subscriber reads is dropped, which is the semantics the
// notification tier is expected to want.
func (s *Subscriber) BroadcastBundleChange() {
	s.mu.Lock()
	s.broadcastCalls++
	subs := slices.Clone(s.subs)
	s.mu.Unlock()

	for _, sub := range subs {
		sub.notify()
	}
}

// Notify signals only the live subscriptions whose workload has the given pod
// UID and returns how many received the signal. A subscription with a nil
// workload never matches. Delivery coalesces exactly as in
// BroadcastBundleChange, so a subscription whose buffer is already full is not
// counted.
func (s *Subscriber) Notify(podUID string) int {
	s.mu.Lock()
	subs := slices.Clone(s.subs)
	s.mu.Unlock()

	notified := 0
	for _, sub := range subs {
		if sub.Workload == nil || sub.Workload.PodUID != podUID {
			continue
		}
		if sub.notify() {
			notified++
		}
	}
	return notified
}

// Subscriptions returns a copy of the subscriptions handed out so far, in
// subscribe order and including cancelled ones, so it is safe to read while
// another goroutine is calling the fake. The Subscription values themselves are
// shared and safe to use concurrently.
func (s *Subscriber) Subscriptions() []*Subscription {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.subs)
}

// SubscribeCalls reports how many times Subscribe has been called, including
// calls served by Func. A call woken by Release is counted when it is next
// scheduled, not when Release returns. Once it is counted, its Subscription is
// already recorded, because Subscribe does both under one lock.
func (s *Subscriber) SubscribeCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.subscribeCalls
}

// BroadcastCalls reports how many times BroadcastBundleChange has been called.
func (s *Subscriber) BroadcastCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.broadcastCalls
}

// CancelCalls reports how many subscriptions have been cancelled. The cancel func
// is idempotent, so cancelling the same subscription twice counts once.
func (s *Subscriber) CancelCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cancelCalls
}

// LiveSubscriptions reports how many subscriptions still receive signals, that
// is, how many are neither cancelled nor carrying a done ctx.
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

// cancelSubscription is what the cancel func returned by Subscribe runs. It is
// idempotent, stops all further delivery to that subscription, and is safe to
// call concurrently with Notify and BroadcastBundleChange. The subscription's
// lock is released before the fake's, so cancelling never nests the two.
func (s *Subscriber) cancelSubscription(sub *Subscription) {
	if !sub.cancel() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancelCalls++
}

var _ workloadidentity.Subscriber = &Subscriber{}
