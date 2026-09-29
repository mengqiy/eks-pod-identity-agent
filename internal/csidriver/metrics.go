package csidriver

// T12 owns the collector for the volume mount metric name declared in
// pkg/workloadidentity/metrics.go. Names and labels are taken from there, so a rename is
// a compile error rather than a silent divergence.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// promVolumeMountTotal counts publishes and unpublishes by outcome. No pod label, per the
// cardinality rule: the pod is in the log line next to it. Publish failures are what an
// operator alarms on, and they appear as a rate because the kubelet retries.
var promVolumeMountTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: workloadidentity.MetricVolumeMountTotal,
	Help: "Count of CSI volume publishes and unpublishes of the workload identity socket directory, by operation and outcome.",
}, []string{workloadidentity.LabelOperation, workloadidentity.LabelOutcome})

// recordMountOutcome emits the outcome of one publish or unpublish. The error is mapped
// to an outcome rather than carried as a label: these are gRPC statuses rather than
// members of the pkg/errors taxonomy, so an error label would be "unknown" every time.
func recordMountOutcome(operation string, err error) {
	outcome := workloadidentity.OutcomeSuccess
	if err != nil {
		outcome = workloadidentity.OutcomeFailure
	}
	promVolumeMountTotal.WithLabelValues(operation, outcome).Inc()
}
