package csidriver

import (
	"context"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

// unknownVendorVersion is reported for a build without a version stamp. GetPluginInfo's
// vendor_version is required by the CSI specification, so it cannot be empty.
const unknownVendorVersion = "unknown"

// identityServer answers what the kubelet asks before it will use a plugin: who are you,
// what can you do, are you ready. All three answers are constant — this driver publishes
// a node-local directory and has nothing to initialise.
type identityServer struct {
	csi.UnimplementedIdentityServer

	driverName    string
	vendorVersion string
}

func newIdentityServer(driverName, vendorVersion string) *identityServer {
	if vendorVersion == "" {
		vendorVersion = unknownVendorVersion
	}
	return &identityServer{driverName: driverName, vendorVersion: vendorVersion}
}

// GetPluginInfo returns the driver's name and version. The kubelet compares this name
// with the one registration reported and refuses the plugin on a mismatch; both come
// from configuration.WorkloadIdentityCSIDriver.
func (s *identityServer) GetPluginInfo(_ context.Context, _ *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	return &csi.GetPluginInfoResponse{
		Name:          s.driverName,
		VendorVersion: s.vendorVersion,
	}, nil
}

// GetPluginCapabilities reports none, which is accurate rather than a stub.
// CONTROLLER_SERVICE: nothing is provisioned, as attachRequired: false also says.
// VOLUME_ACCESSIBILITY_CONSTRAINTS: every node running the agent can publish this, so
// there is no topology.
func (s *identityServer) GetPluginCapabilities(_ context.Context, _ *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	return &csi.GetPluginCapabilitiesResponse{}, nil
}

// Probe always reports ready, deliberately not tied to the workload identity socket
// being served. The mount is valid either way, since the pod resolves the socket inside
// it on every dial, so reporting not-ready would hold up pod starts — and every pod
// starting during an agent restart — for a condition that resolves itself.
func (s *identityServer) Probe(ctx context.Context, _ *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	logger.FromContext(ctx).Debug("CSI Probe: ready")
	return &csi.ProbeResponse{Ready: wrapperspb.Bool(true)}, nil
}
