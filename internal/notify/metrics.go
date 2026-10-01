package notify

// T9 collectors for the subscription and notification metric names declared in
// pkg/workloadidentity/metrics.go. Names, labels and values are taken from that
// package so a rename there is a compile error here.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

var (
	// promSubscriptionsActive gauges open subscriptions by RPC. It is the number
	// of streams the node is holding open, so a value that climbs without
	// bound is a handler that is not releasing on client disconnect.
	promSubscriptionsActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: workloadidentity.MetricSubscriptionsActive,
		Help: "Open workload identity stream subscriptions, by RPC.",
	}, []string{workloadidentity.LabelRPC})

	// promNotificationTotal counts notifications by RPC and how they were
	// delivered. Both delivery values are normal; a sustained coalesced rate for
	// one RPC says its streams are reading slower than the material changes.
	promNotificationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: workloadidentity.MetricNotificationTotal,
		Help: "Count of change notifications delivered to workload identity streams, by RPC and delivery.",
	}, []string{workloadidentity.LabelRPC, workloadidentity.LabelDelivery})
)

// rpcMetrics are the collectors for one RPC, with the RPC label already applied.
//
// Resolving the label values once per RPC at wiring time rather than per
// notification is what keeps the publish path free of a map lookup and a slice
// allocation per subscription, which matters because a bundle rotation touches
// every subscription on the node at once. The values are safe to use
// concurrently.
type rpcMetrics struct {
	// active is the subscription gauge for this RPC.
	active prometheus.Gauge
	// signalled counts notifications that landed in an empty channel.
	signalled prometheus.Counter
	// coalesced counts notifications that replaced an unread one.
	coalesced prometheus.Counter
}

// metricsForRPC binds the collectors for one RPC label value.
func metricsForRPC(rpc string) *rpcMetrics {
	return &rpcMetrics{
		active:    promSubscriptionsActive.WithLabelValues(rpc),
		signalled: promNotificationTotal.WithLabelValues(rpc, workloadidentity.DeliverySignalled),
		coalesced: promNotificationTotal.WithLabelValues(rpc, workloadidentity.DeliveryCoalesced),
	}
}
