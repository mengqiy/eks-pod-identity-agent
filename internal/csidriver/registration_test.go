package csidriver

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"
	pluginregistration "k8s.io/kubelet/pkg/apis/pluginregistration/v1"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
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

func TestNotifyRegistrationStatus_Registered_IsAcknowledged(t *testing.T) {
	g := NewWithT(t)

	registration := newRegistrationServer(configuration.WorkloadIdentityCSIDriver, configuration.KubeletPluginSocketPath)

	resp, err := registration.NotifyRegistrationStatus(context.Background(),
		&pluginregistration.RegistrationStatus{PluginRegistered: true})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp).ToNot(BeNil())
}

// The kubelet is reporting a decision it already made and does nothing with an error in
// reply. The refusal's value is the log line; no mount is attempted afterwards.
func TestNotifyRegistrationStatus_Refused_IsAcknowledgedRatherThanReturnedAsAnError(t *testing.T) {
	g := NewWithT(t)

	registration := newRegistrationServer(configuration.WorkloadIdentityCSIDriver, configuration.KubeletPluginSocketPath)

	resp, err := registration.NotifyRegistrationStatus(context.Background(),
		&pluginregistration.RegistrationStatus{PluginRegistered: false, Error: "plugin name mismatch"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp).ToNot(BeNil())
}
