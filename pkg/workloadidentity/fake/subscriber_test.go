package fake

import (
	"context"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// subscriberTestTimeout bounds every wait in this file, so a fake that never
// releases a parked call, or that blocks on delivery, fails the test instead of
// hanging the suite.
const subscriberTestTimeout = 2 * time.Second

// subscriberTestWorkload is the attested caller the default subscription is for.
var subscriberTestWorkload = &workloadidentity.Workload{
	PodUID:         "pod-uid-1",
	PodName:        "my-pod",
	Namespace:      "my-namespace",
	ServiceAccount: "my-service-account",
	NodeName:       "my-node",
}

// subscriberSubscribeResult is what a Subscribe call running in another goroutine
// hands back to the test.
type subscriberSubscribeResult struct {
	ch     <-chan struct{}
	cancel func()
}

// subscriberWorkload builds a workload for one pod UID, so a test can hold
// several subscriptions apart.
func subscriberWorkload(podUID string) *workloadidentity.Workload {
	return &workloadidentity.Workload{
		PodUID:         podUID,
		PodName:        podUID + "-pod",
		Namespace:      "my-namespace",
		ServiceAccount: "my-service-account",
		NodeName:       "my-node",
	}
}

// subscriberSignals drains and counts the signals pending in ch. It must not be
// used on a channel the fake has closed, which a closed channel test asserts
// directly instead.
func subscriberSignals(ch <-chan struct{}) int {
	signals := 0
	for {
		select {
		case <-ch:
			signals++
		default:
			return signals
		}
	}
}

// subscriberDo runs fn in another goroutine and fails the test if it has not
// returned before the timeout, so a fake that blocks fails instead of hanging.
func subscriberDo(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(subscriberTestTimeout):
		t.Fatalf("call did not return within %v", subscriberTestTimeout)
	}
}

func TestSubscriptionLive_ZeroValue_IsLiveAndReceivesNothing(t *testing.T) {
	g := NewWithT(t)

	// Subscription is exported, so a consumer can build one the fake never handed
	// out. It carries no ctx and no channel, and every accessor has to answer for
	// it rather than dereference what is not there.
	sub := &Subscription{}

	g.Expect(sub.Live()).To(BeTrue())
	g.Expect(sub.Chan()).To(BeNil())
	g.Expect(sub.Notified()).To(Equal(0))

	// A delivery attempt finds no channel for the signal to land in, so it reports
	// no signal and counts none, exactly as a full buffer does.
	g.Expect(sub.notify()).To(BeFalse())
	g.Expect(sub.Notified()).To(Equal(0))
	g.Expect(sub.Live()).To(BeTrue())
}

func TestSubscriberSubscribe_Called_ReturnsChannelAndCancelFunc(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{}

	ch, cancel := subscriber.Subscribe(context.Background(), subscriberTestWorkload)

	g.Expect(ch).To(Not(BeNil()))
	g.Expect(cancel).To(Not(BeNil()))
	g.Expect(subscriber.SubscribeCalls()).To(Equal(1))
	g.Expect(subscriber.BroadcastCalls()).To(Equal(0))
	g.Expect(subscriber.CancelCalls()).To(Equal(0))
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(1))

	subs := subscriber.Subscriptions()
	g.Expect(subs).To(HaveLen(1))
	g.Expect(subs[0].Workload).To(BeIdenticalTo(subscriberTestWorkload))
	g.Expect(*subs[0].Workload).To(Equal(*subscriberTestWorkload))
	g.Expect(subs[0].Chan()).To(BeIdenticalTo(ch))
	g.Expect(subs[0].Live()).To(BeTrue())
	g.Expect(subs[0].Notified()).To(Equal(0))
	g.Expect(subscriberSignals(ch)).To(Equal(0))
}

func TestSubscriberSubscribe_CalledRepeatedly_RecordsSubscriptionsInOrder(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{}
	first := subscriberWorkload("pod-a")
	second := subscriberWorkload("pod-b")

	firstCh, firstCancel := subscriber.Subscribe(context.Background(), first)
	secondCh, _ := subscriber.Subscribe(context.Background(), second)

	g.Expect(subscriber.SubscribeCalls()).To(Equal(2))
	subs := subscriber.Subscriptions()
	g.Expect(subs).To(HaveLen(2))
	g.Expect(subs[0].Workload).To(BeIdenticalTo(first))
	g.Expect(subs[0].Chan()).To(BeIdenticalTo(firstCh))
	g.Expect(subs[1].Workload).To(BeIdenticalTo(second))
	g.Expect(subs[1].Chan()).To(BeIdenticalTo(secondCh))

	// Subscriptions keeps cancelled subscriptions, in subscribe order, and hands
	// back a copy of the slice.
	firstCancel()
	kept := subscriber.Subscriptions()
	g.Expect(kept).To(HaveLen(2))
	g.Expect(kept[0]).To(BeIdenticalTo(subs[0]))
	g.Expect(kept[0].Live()).To(BeFalse())
	g.Expect(kept[1].Live()).To(BeTrue())
	kept[0] = nil
	g.Expect(subscriber.Subscriptions()[0]).To(BeIdenticalTo(subs[0]))
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(1))
}

func TestSubscriberBroadcastBundleChange_Called_SignalsEveryLiveSubscription(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{}
	liveCtx, cancelLive := context.WithCancel(context.Background())
	t.Cleanup(cancelLive)
	doneCtx, cancelDone := context.WithCancel(context.Background())

	firstCh, _ := subscriber.Subscribe(liveCtx, subscriberWorkload("pod-a"))
	secondCh, _ := subscriber.Subscribe(liveCtx, subscriberWorkload("pod-b"))
	cancelledCh, cancelThird := subscriber.Subscribe(liveCtx, subscriberWorkload("pod-c"))
	doneCh, _ := subscriber.Subscribe(doneCtx, subscriberWorkload("pod-d"))
	cancelThird()
	cancelDone()

	g.Expect(subscriber.LiveSubscriptions()).To(Equal(2))

	subscriberDo(t, subscriber.BroadcastBundleChange)

	g.Expect(subscriber.BroadcastCalls()).To(Equal(1))
	g.Expect(subscriberSignals(firstCh)).To(Equal(1))
	g.Expect(subscriberSignals(secondCh)).To(Equal(1))
	g.Expect(subscriberSignals(cancelledCh)).To(Equal(0))
	g.Expect(subscriberSignals(doneCh)).To(Equal(0))

	subs := subscriber.Subscriptions()
	g.Expect(subs).To(HaveLen(4))
	g.Expect(subs[0].Notified()).To(Equal(1))
	g.Expect(subs[1].Notified()).To(Equal(1))
	g.Expect(subs[2].Notified()).To(Equal(0))
	g.Expect(subs[3].Notified()).To(Equal(0))
}

func TestSubscriberNotify_MatchingPodUID_SignalsOnlyThatPodsSubscriptions(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{}
	firstCh, _ := subscriber.Subscribe(context.Background(), subscriberWorkload("pod-a"))
	secondCh, _ := subscriber.Subscribe(context.Background(), subscriberWorkload("pod-a"))
	otherCh, _ := subscriber.Subscribe(context.Background(), subscriberWorkload("pod-b"))
	nilCh, _ := subscriber.Subscribe(context.Background(), nil)

	g.Expect(subscriber.Notify("pod-a")).To(Equal(2))
	g.Expect(subscriberSignals(firstCh)).To(Equal(1))
	g.Expect(subscriberSignals(secondCh)).To(Equal(1))
	g.Expect(subscriberSignals(otherCh)).To(Equal(0))
	g.Expect(subscriberSignals(nilCh)).To(Equal(0))

	g.Expect(subscriber.Notify("pod-b")).To(Equal(1))
	g.Expect(subscriberSignals(otherCh)).To(Equal(1))

	g.Expect(subscriber.Notify("pod-unknown")).To(Equal(0))
	g.Expect(subscriber.Notify("")).To(Equal(0))
	g.Expect(subscriber.BroadcastCalls()).To(Equal(0))
}

func TestSubscriberNotify_BufferAlreadyFull_CoalescesAndReportsNoSignal(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{}
	ch, _ := subscriber.Subscribe(context.Background(), subscriberTestWorkload)

	g.Expect(subscriber.Notify("pod-uid-1")).To(Equal(1))
	g.Expect(subscriber.Notify("pod-uid-1")).To(Equal(0))
	g.Expect(subscriberSignals(ch)).To(Equal(1))

	// Once the pending signal is read the next one lands again.
	g.Expect(subscriber.Notify("pod-uid-1")).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(1))
	g.Expect(subscriber.Subscriptions()[0].Notified()).To(Equal(2))
}

func TestSubscriberBroadcastBundleChange_NoReader_CoalescesWithoutBlocking(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{}
	ch, _ := subscriber.Subscribe(context.Background(), subscriberTestWorkload)

	subscriberDo(t, func() {
		for range 5 {
			subscriber.BroadcastBundleChange()
		}
	})

	g.Expect(subscriber.BroadcastCalls()).To(Equal(5))
	g.Expect(subscriber.Subscriptions()[0].Notified()).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(1))
}

func TestSubscriberSubscribe_BufferSet_AcceptsThatManyPendingSignals(t *testing.T) {
	testCases := []struct {
		name     string
		buffer   int
		expected int
	}{
		{name: "zero buffer defaults to one", buffer: 0, expected: 1},
		{name: "negative buffer defaults to one", buffer: -3, expected: 1},
		{name: "explicit buffer of one", buffer: 1, expected: 1},
		{name: "explicit buffer of three", buffer: 3, expected: 3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			subscriber := &Subscriber{Buffer: tc.buffer}
			ch, _ := subscriber.Subscribe(context.Background(), subscriberTestWorkload)

			subscriberDo(t, func() {
				for range 5 {
					subscriber.BroadcastBundleChange()
				}
			})

			g.Expect(subscriber.Subscriptions()[0].Notified()).To(Equal(tc.expected))
			g.Expect(subscriberSignals(ch)).To(Equal(tc.expected))
		})
	}
}

func TestSubscriberCancel_CalledTwice_CountsOnceAndStopsDelivery(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{}
	ch, cancel := subscriber.Subscribe(context.Background(), subscriberTestWorkload)

	g.Expect(subscriber.Notify("pod-uid-1")).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(1))

	cancel()
	cancel()

	g.Expect(subscriber.CancelCalls()).To(Equal(1))
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(0))

	sub := subscriber.Subscriptions()[0]
	g.Expect(sub.Live()).To(BeFalse())

	g.Expect(subscriber.Notify("pod-uid-1")).To(Equal(0))
	subscriberDo(t, subscriber.BroadcastBundleChange)

	g.Expect(sub.Notified()).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(0))
}

func TestSubscriberCancel_CloseOnCancelSet_ClosesChannel(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{CloseOnCancel: true}
	ch, cancel := subscriber.Subscribe(context.Background(), subscriberTestWorkload)

	select {
	case <-ch:
		t.Fatal("channel was signalled or closed before cancel")
	default:
	}

	cancel()
	cancel()

	g.Expect(subscriber.CancelCalls()).To(Equal(1))
	select {
	case _, ok := <-ch:
		g.Expect(ok).To(BeFalse())
	default:
		t.Fatal("channel was not closed by cancel")
	}

	// Delivery to a closed channel would panic, so a broadcast after cancel has
	// to stay a no-op.
	subscriberDo(t, subscriber.BroadcastBundleChange)
	g.Expect(subscriber.Notify("pod-uid-1")).To(Equal(0))
	g.Expect(subscriber.Subscriptions()[0].Notified()).To(Equal(0))
}

func TestSubscriberCancel_CloseOnCancelUnset_LeavesChannelOpen(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{}
	ch, cancel := subscriber.Subscribe(context.Background(), subscriberTestWorkload)

	cancel()

	select {
	case <-ch:
		t.Fatal("channel was signalled or closed by cancel")
	default:
	}
	g.Expect(subscriber.CancelCalls()).To(Equal(1))
}

func TestSubscriberSubscribe_ContextAlreadyDone_SubscriptionIsNeverLive(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{}
	ctx, cancelCtx := context.WithCancel(context.Background())
	cancelCtx()

	ch, cancel := subscriber.Subscribe(ctx, subscriberTestWorkload)

	g.Expect(ch).To(Not(BeNil()))
	g.Expect(cancel).To(Not(BeNil()))
	g.Expect(subscriber.SubscribeCalls()).To(Equal(1))
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(0))

	sub := subscriber.Subscriptions()[0]
	g.Expect(sub.Live()).To(BeFalse())

	g.Expect(subscriber.Notify("pod-uid-1")).To(Equal(0))
	subscriberDo(t, subscriber.BroadcastBundleChange)

	g.Expect(sub.Notified()).To(Equal(0))
	g.Expect(subscriberSignals(ch)).To(Equal(0))
}

func TestSubscriberSubscribe_ContextCancelledAfterSubscribe_StopsReceiving(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{}
	ctx, cancelCtx := context.WithCancel(context.Background())
	t.Cleanup(cancelCtx)

	ch, _ := subscriber.Subscribe(ctx, subscriberTestWorkload)

	g.Expect(subscriber.Notify("pod-uid-1")).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(1))

	cancelCtx()

	g.Expect(subscriber.LiveSubscriptions()).To(Equal(0))
	g.Expect(subscriber.Notify("pod-uid-1")).To(Equal(0))
	subscriberDo(t, subscriber.BroadcastBundleChange)

	sub := subscriber.Subscriptions()[0]
	g.Expect(sub.Live()).To(BeFalse())
	g.Expect(sub.Notified()).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(0))
	// The subscription's ctx being done does not count as a cancel.
	g.Expect(subscriber.CancelCalls()).To(Equal(0))
}

func TestSubscriberSubscribe_GateBlocked_ReturnsUsableSubscriptionAfterRelease(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{}
	subscriber.Block()

	ctx, cancel := context.WithTimeout(context.Background(), subscriberTestTimeout)
	t.Cleanup(cancel)

	done := make(chan subscriberSubscribeResult, 1)
	go func() {
		ch, cancelSub := subscriber.Subscribe(ctx, subscriberTestWorkload)
		done <- subscriberSubscribeResult{ch: ch, cancel: cancelSub}
	}()

	g.Expect(subscriber.WaitForBlocked(ctx, 1)).To(Succeed())
	g.Expect(subscriber.Blocked()).To(Equal(1))
	g.Expect(done).To(Not(Receive()))
	g.Expect(subscriber.SubscribeCalls()).To(Equal(0))
	g.Expect(subscriber.Subscriptions()).To(BeEmpty())

	subscriber.Release()

	var got subscriberSubscribeResult
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatalf("Subscribe did not return after Release: %v", ctx.Err())
	}

	g.Expect(got.ch).To(Not(BeNil()))
	g.Expect(got.cancel).To(Not(BeNil()))
	g.Expect(subscriber.SubscribeCalls()).To(Equal(1))
	g.Expect(subscriber.Blocked()).To(Equal(0))

	subs := subscriber.Subscriptions()
	g.Expect(subs).To(HaveLen(1))
	g.Expect(subs[0].Workload).To(BeIdenticalTo(subscriberTestWorkload))
	g.Expect(subs[0].Chan()).To(BeIdenticalTo(got.ch))
	g.Expect(subs[0].Live()).To(BeTrue())

	g.Expect(subscriber.Notify("pod-uid-1")).To(Equal(1))
	g.Expect(subscriberSignals(got.ch)).To(Equal(1))

	got.cancel()
	g.Expect(subscriber.CancelCalls()).To(Equal(1))
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(0))
}

func TestSubscriberSubscribe_ParkedCallContextCancelled_ReturnsSubscriptionThatIsNotLive(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{}
	subscriber.Block()
	t.Cleanup(subscriber.Release)

	waitCtx, cancelWait := context.WithTimeout(context.Background(), subscriberTestTimeout)
	t.Cleanup(cancelWait)
	callCtx, cancelCall := context.WithCancel(context.Background())
	t.Cleanup(cancelCall)

	done := make(chan subscriberSubscribeResult, 1)
	go func() {
		ch, cancelSub := subscriber.Subscribe(callCtx, subscriberTestWorkload)
		done <- subscriberSubscribeResult{ch: ch, cancel: cancelSub}
	}()

	g.Expect(subscriber.WaitForBlocked(waitCtx, 1)).To(Succeed())
	cancelCall()

	var got subscriberSubscribeResult
	select {
	case got = <-done:
	case <-waitCtx.Done():
		t.Fatalf("Subscribe did not return after its context was cancelled: %v", waitCtx.Err())
	}

	// Subscribe cannot report the gate error, so it still hands back a usable
	// channel and cancel func, for a subscription that is never live.
	g.Expect(got.ch).To(Not(BeNil()))
	g.Expect(got.cancel).To(Not(BeNil()))
	g.Expect(subscriber.SubscribeCalls()).To(Equal(1))
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(0))
	g.Expect(subscriber.Blocked()).To(Equal(0))

	sub := subscriber.Subscriptions()[0]
	g.Expect(sub.Live()).To(BeFalse())
	g.Expect(subscriber.Notify("pod-uid-1")).To(Equal(0))
	g.Expect(sub.Notified()).To(Equal(0))
	g.Expect(subscriberSignals(got.ch)).To(Equal(0))
}

func TestSubscriberSubscribe_FuncSet_ReturnsItsChannelAndRecordsNoSubscription(t *testing.T) {
	g := NewWithT(t)

	canned := make(chan struct{}, 1)
	cancels := 0
	subscriber := &Subscriber{
		Func: func(_ context.Context, _ *workloadidentity.Workload) (<-chan struct{}, func()) {
			return canned, func() { cancels++ }
		},
	}

	ch, cancel := subscriber.Subscribe(context.Background(), subscriberTestWorkload)

	g.Expect(ch).To(BeIdenticalTo((<-chan struct{})(canned)))
	g.Expect(subscriber.SubscribeCalls()).To(Equal(1))
	g.Expect(subscriber.Subscriptions()).To(BeEmpty())
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(0))

	// The cancel func is returned unwrapped, so it is neither counted nor made
	// idempotent by the fake.
	cancel()
	cancel()
	g.Expect(cancels).To(Equal(2))
	g.Expect(subscriber.CancelCalls()).To(Equal(0))

	// Nothing was recorded, so neither delivery path reaches the canned channel.
	g.Expect(subscriber.Notify("pod-uid-1")).To(Equal(0))
	subscriberDo(t, subscriber.BroadcastBundleChange)
	g.Expect(subscriber.BroadcastCalls()).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(0))
}

func TestSubscriberBroadcastBundleChange_ConcurrentWithCancel_DeliversWithoutRacing(t *testing.T) {
	g := NewWithT(t)

	const subscriptions = 5
	subscriber := &Subscriber{CloseOnCancel: true}

	cancels := make([]func(), 0, subscriptions)
	for range subscriptions {
		_, cancel := subscriber.Subscribe(context.Background(), subscriberWorkload("pod-a"))
		cancels = append(cancels, cancel)
	}

	var wg sync.WaitGroup
	for _, cancel := range cancels {
		wg.Add(2)
		go func() {
			defer wg.Done()
			cancel()
			cancel()
		}()
		go func() {
			defer wg.Done()
			subscriber.BroadcastBundleChange()
			subscriber.Notify("pod-a")
		}()
	}

	subscriberDo(t, wg.Wait)

	g.Expect(subscriber.SubscribeCalls()).To(Equal(subscriptions))
	g.Expect(subscriber.BroadcastCalls()).To(Equal(subscriptions))
	g.Expect(subscriber.CancelCalls()).To(Equal(subscriptions))
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(0))

	for _, sub := range subscriber.Subscriptions() {
		g.Expect(sub.Live()).To(BeFalse())
		g.Expect(sub.Notified()).To(BeNumerically("<=", 1))
		select {
		case _, ok := <-sub.Chan():
			// Either the signal that landed before the cancel, or the close.
			_ = ok
		default:
			t.Fatal("a cancelled subscription's channel was neither signalled nor closed")
		}
	}
}
