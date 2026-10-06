package csidriver

import (
	"context"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	. "github.com/onsi/gomega"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// The kubelet refuses the plugin if this name differs from the one registration reported,
// and the chart's CSIDriver object has to carry it too. All three come from
// configuration.WorkloadIdentityCSIDriver.
func TestGetPluginInfo_ReportsTheDriverNameFromConfiguration(t *testing.T) {
	g := NewWithT(t)

	identity := newIdentityServer(configuration.WorkloadIdentityCSIDriver, "v1.2.3")

	resp, err := identity.GetPluginInfo(context.Background(), &csi.GetPluginInfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.GetName()).To(Equal(configuration.WorkloadIdentityCSIDriver))
	g.Expect(resp.GetName()).To(Equal("spiffe.csi.eks.amazonaws.com"),
		"the driver name is a frozen contract with the Pod Identity webhook and the CSIDriver object")
	g.Expect(resp.GetVendorVersion()).To(Equal("v1.2.3"))
}

// A local build links in no version, and vendor_version is required by the CSI spec.
func TestGetPluginInfo_UnstampedBuild_ReportsAVendorVersionAnyway(t *testing.T) {
	g := NewWithT(t)

	identity := newIdentityServer(configuration.WorkloadIdentityCSIDriver, "")

	resp, err := identity.GetPluginInfo(context.Background(), &csi.GetPluginInfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.GetVendorVersion()).To(Equal(unknownVendorVersion))
}

// No CONTROLLER_SERVICE, the same statement attachRequired: false makes. Declaring it
// would have the attach/detach controller wait for a VolumeAttachment nothing creates.
func TestGetPluginCapabilities_ReportsNone(t *testing.T) {
	g := NewWithT(t)

	identity := newIdentityServer(configuration.WorkloadIdentityCSIDriver, "v1.2.3")

	resp, err := identity.GetPluginCapabilities(context.Background(), &csi.GetPluginCapabilitiesRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.GetCapabilities()).To(BeEmpty())
}

// Readiness is not tied to the workload identity socket: the mount is valid before the
// agent accepts on it, so not-ready would hold up pod starts for nothing.
func TestProbe_IsReady(t *testing.T) {
	g := NewWithT(t)

	identity := newIdentityServer(configuration.WorkloadIdentityCSIDriver, "v1.2.3")

	resp, err := identity.Probe(context.Background(), &csi.ProbeRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.GetReady().GetValue()).To(BeTrue())
}
