package csidriver

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	pluginregistration "k8s.io/kubelet/pkg/apis/pluginregistration/v1"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Each field fails differently: wrong type goes to the device plugin machinery, wrong name
// never resolves the volume, wrong endpoint registers a plugin nothing calls.
func TestGetInfo_ReportsACSIPluginAtThePluginSocket(t *testing.T) {
	g := NewWithT(t)

	registration := newRegistrationServer(configuration.WorkloadIdentityCSIDriver, configuration.KubeletPluginSocketPath)

	info, err := registration.GetInfo(context.Background(), &pluginregistration.InfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(info.GetType()).To(Equal(pluginregistration.CSIPlugin))
	g.Expect(info.GetName()).To(Equal(configuration.WorkloadIdentityCSIDriver))
	g.Expect(info.GetEndpoint()).To(Equal(configuration.KubeletPluginSocketPath))
	g.Expect(info.GetSupportedVersions()).To(Equal([]string{csiPluginAPIVersion}))
}

// The namespace check: the kubelet opens the endpoint in the host namespace, the agent
// binds it in its own, and they match only because the chart mounts the plugin directory at
// its host path. Getting this wrong registers a plugin nothing ever calls.
func TestGetInfo_TheReportedEndpoint_IsThePathTheAgentBinds(t *testing.T) {
	g := NewWithT(t)

	g.Expect(configuration.KubeletPluginSocketPath).To(HavePrefix(configuration.KubeletPluginDir+"/"),
		"the plugin socket has to live in the directory the chart mounts for it")
	g.Expect(configuration.KubeletPluginDir).To(HaveSuffix("/"+configuration.WorkloadIdentityCSIDriver),
		"the kubelet convention is one directory per driver, named after the driver")
	g.Expect(configuration.KubeletRegistrationSocketPath).To(HavePrefix(configuration.KubeletPluginRegistrationDir+"/"),
		"the kubelet only watches its own registration directory")
}

func TestNotifyRegistrationStatus_Registered_IsAcknowledgedAndCounted(t *testing.T) {
	g := NewWithT(t)

	before := testutil.ToFloat64(promRegistrationTotal.WithLabelValues(workloadidentity.OutcomeSuccess))

	registration := newRegistrationServer(configuration.WorkloadIdentityCSIDriver, configuration.KubeletPluginSocketPath)

	resp, err := registration.NotifyRegistrationStatus(context.Background(),
		&pluginregistration.RegistrationStatus{PluginRegistered: true})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp).ToNot(BeNil())

	after := testutil.ToFloat64(promRegistrationTotal.WithLabelValues(workloadidentity.OutcomeSuccess))
	g.Expect(after - before).To(Equal(1.0))
}

// The kubelet is reporting a decision it already made and does nothing with an error in
// reply, so the refusal is surfaced rather than returned: an error here would reach the
// kubelet, not the agent. The counter is the alarmable half of that, since no mount
// follows a refusal and the agent's own logs stay healthy-looking.
func TestNotifyRegistrationStatus_Refused_IsAcknowledgedAndCountedRatherThanReturnedAsAnError(t *testing.T) {
	g := NewWithT(t)

	before := testutil.ToFloat64(promRegistrationTotal.WithLabelValues(workloadidentity.OutcomeFailure))

	registration := newRegistrationServer(configuration.WorkloadIdentityCSIDriver, configuration.KubeletPluginSocketPath)

	resp, err := registration.NotifyRegistrationStatus(context.Background(),
		&pluginregistration.RegistrationStatus{PluginRegistered: false, Error: "plugin name mismatch"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp).ToNot(BeNil())

	after := testutil.ToFloat64(promRegistrationTotal.WithLabelValues(workloadidentity.OutcomeFailure))
	g.Expect(after-before).To(Equal(1.0),
		"a refusal has to be countable: it is terminal for the node and the log line is not alarmable")
}
