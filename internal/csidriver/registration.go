package csidriver

import (
	"context"

	pluginregistration "k8s.io/kubelet/pkg/apis/pluginregistration/v1"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

// csiPluginAPIVersion is the version of the registration handshake, not of the CSI
// specification, which is why it is 1.0.0 while the CSI dependency is later. The kubelet
// checks it against the versions it can drive a CSI plugin with; every upstream driver
// reports 1.0.0, node-driver-registrar included.
const csiPluginAPIVersion = "1.0.0"

// registrationServer tells the kubelet this node has a CSI plugin and where to call it.
//
// Served in-process rather than by the node-driver-registrar sidecar: the sidecar's whole
// job is these two methods, and it costs another image to build, scan and mirror per
// region on a managed add-on. What it also gives is a loud failure on a refused
// registration, which NotifyRegistrationStatus reproduces.
type registrationServer struct {
	pluginregistration.UnimplementedRegistrationServer

	driverName string
	endpoint   string
}

func newRegistrationServer(driverName, endpoint string) *registrationServer {
	return &registrationServer{driverName: driverName, endpoint: endpoint}
}

// GetInfo answers the kubelet's question about the socket it just found.
//
// The endpoint is the plugin socket as the kubelet will open it, in the host mount
// namespace. It is the same string the agent bound in its own only because the chart
// mounts the plugin directory at its host path; see configuration.KubeletPluginDir.
// Reporting a path valid in one namespace and not the other is the classic failure here,
// and it presents as a plugin that registers and is never called.
func (s *registrationServer) GetInfo(ctx context.Context, _ *pluginregistration.InfoRequest) (*pluginregistration.PluginInfo, error) {
	logger.FromContext(ctx).Infof("Kubelet asked for plugin info, reporting driver %s at %s", s.driverName, s.endpoint)

	return &pluginregistration.PluginInfo{
		Type:              pluginregistration.CSIPlugin,
		Name:              s.driverName,
		Endpoint:          s.endpoint,
		SupportedVersions: []string{csiPluginAPIVersion},
	}, nil
}

// NotifyRegistrationStatus records what the kubelet decided.
//
// A rejection is logged at error and counted because it is the one moment the kubelet
// says why, it is not retried, and every downstream symptom is remote: no mount is
// attempted, so the first enrolled pod sits in ContainerCreating with healthy-looking
// agent logs.
//
// No error is returned on either path. The kubelet is the caller, so an error here
// reaches it rather than anything in the agent, and it is already the party that decided:
// its own notifyPlugin returns the refusal reason whatever this answers. On the success
// path an error is worse than useless, since the kubelet responds by deregistering the
// plugin it just registered.
func (s *registrationServer) NotifyRegistrationStatus(ctx context.Context, status *pluginregistration.RegistrationStatus) (*pluginregistration.RegistrationStatusResponse, error) {
	log := logger.FromContext(ctx)

	recordRegistrationOutcome(status.GetPluginRegistered())

	if status.GetPluginRegistered() {
		log.Infof("Kubelet registered CSI driver %s", s.driverName)
		return &pluginregistration.RegistrationStatusResponse{}, nil
	}

	log.Errorf("Kubelet refused to register CSI driver %s, so no enrolled pod on this node can be given the "+
		"workload identity socket and each will wait in ContainerCreating: %s", s.driverName, status.GetError())

	return &pluginregistration.RegistrationStatusResponse{}, nil
}
