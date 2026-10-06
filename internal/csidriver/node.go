package csidriver

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

const (
	// ephemeralVolumeContextKey is set to "true" by the kubelet for an inline ephemeral
	// volume. The kubelet owns the csi.storage.k8s.io/ prefix and these names.
	ephemeralVolumeContextKey = "csi.storage.k8s.io/ephemeral"

	// Pod identity keys, populated because the CSIDriver object sets podInfoOnMount.
	// Logging only: a caller is attested by its kernel peer credentials, never by
	// anything the mount path said.
	podNameVolumeContextKey      = "csi.storage.k8s.io/pod.name"
	podNamespaceVolumeContextKey = "csi.storage.k8s.io/pod.namespace"

	// targetPathMode is the target directory's mode. The kubelet creates only its parent.
	// The pod sees this directory at WorkloadIdentitySocketMountPath and may run as any UID,
	// so it needs the search bit; the write bit is withheld, as for grpcserver's socket
	// directory.
	targetPathMode os.FileMode = 0o755
)

// nodeServer publishes the workload identity socket into an enrolled pod by serving one
// inside the pod's target directory; see podSockets. Nothing is mounted.
//
// There is nothing to provision, attach, format or stage, and every method beyond the
// publish is left to the embedded UnimplementedNodeServer.
type nodeServer struct {
	csi.UnimplementedNodeServer

	// sockets serves the socket in each published target.
	sockets *podSockets
	// nodeName is reported as the CSI node ID; see Opts.NodeName.
	nodeName string
	// podsDir is the root every target path must be inside.
	podsDir string
}

func newNodeServer(sockets *podSockets, nodeName, podsDir string) *nodeServer {
	return &nodeServer{sockets: sockets, nodeName: nodeName, podsDir: podsDir}
}

// NodePublishVolume serves the workload identity socket in the kubelet's target path.
//
// Idempotent: the kubelet repeats a publish whose reply it never got.
func (s *nodeServer) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	resp, err := s.publish(ctx, req)
	recordMountOutcome(workloadidentity.OperationPublish, err)
	return resp, err
}

func (s *nodeServer) publish(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	log := logger.FromContext(ctx)

	if req.GetVolumeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}
	target := req.GetTargetPath()
	if target == "" {
		return nil, status.Error(codes.InvalidArgument, "target path is required")
	}

	if err := validateVolumeCapability(req.GetVolumeCapability()); err != nil {
		return nil, err
	}
	if err := validateReadOnly(req.GetReadonly()); err != nil {
		return nil, err
	}
	if err := validateEphemeral(req.GetVolumeContext()); err != nil {
		return nil, err
	}
	if err := validateTargetPath(target, s.podsDir); err != nil {
		return nil, err
	}

	log = log.WithFields(map[string]any{
		"volume-id":     req.GetVolumeId(),
		"target-path":   target,
		"pod-namespace": req.GetVolumeContext()[podNamespaceVolumeContextKey],
		"pod-name":      req.GetVolumeContext()[podNameVolumeContextKey],
	})

	// MkdirAll and a chmod: the kubelet creates only the parent, and the mode must not
	// depend on the umask.
	if err := os.MkdirAll(target, targetPathMode); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to create target path %s: %v", target, err)
	}
	if err := os.Chmod(target, targetPathMode); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to set mode %04o on target path %s: %v",
			targetPathMode, target, err)
	}

	created, err := s.sockets.publish(target)
	if errors.Is(err, errPodSocketsClosed) {
		return nil, status.Errorf(codes.Unavailable, "unable to serve the workload identity socket in %s: %v", target, err)
	}
	if err != nil {
		log.Errorf("CSI NodePublishVolume: unable to serve the workload identity socket: %v", err)
		return nil, status.Errorf(codes.Internal, "unable to serve the workload identity socket in %s: %v", target, err)
	}
	if !created {
		// Debug, so a kubelet retrying in a loop does not bury the rest of the log.
		log.Debug("CSI NodePublishVolume: already serving the socket in this target, nothing to do")
		return &csi.NodePublishVolumeResponse{}, nil
	}

	log.Infof("CSI NodePublishVolume: serving %s", filepath.Join(target, podSocketName))
	return &csi.NodePublishVolumeResponse{}, nil
}

// NodeUnpublishVolume stops serving the target's socket and removes the target.
//
// Idempotent: the kubelet repeats this during teardown, so an error for a volume already
// gone would leave the pod stuck terminating.
func (s *nodeServer) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	resp, err := s.unpublish(ctx, req)
	recordMountOutcome(workloadidentity.OperationUnpublish, err)
	return resp, err
}

func (s *nodeServer) unpublish(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	log := logger.FromContext(ctx)

	if req.GetVolumeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}
	target := req.GetTargetPath()
	if target == "" {
		return nil, status.Error(codes.InvalidArgument, "target path is required")
	}
	// Checked here too: an unpublish deletes, so a target outside the kubelet's pods
	// directory is a request to remove something that was never ours.
	if err := validateTargetPath(target, s.podsDir); err != nil {
		return nil, err
	}

	log = log.WithFields(map[string]any{"volume-id": req.GetVolumeId(), "target-path": target})

	if err := s.sockets.unpublish(target); err != nil {
		log.Errorf("CSI NodeUnpublishVolume: unable to remove the workload identity socket: %v", err)
		return nil, status.Errorf(codes.Internal, "unable to unpublish %s: %v", target, err)
	}

	// os.Remove rather than RemoveAll: without the socket this is the empty directory the
	// publish created, and a non-empty one holds something that was not ours.
	if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Errorf("CSI NodeUnpublishVolume: unable to remove the target path: %v", err)
		return nil, status.Errorf(codes.Internal, "unable to remove target path %s: %v", target, err)
	}

	log.Info("CSI NodeUnpublishVolume: unpublished")
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

// NodeGetInfo reports the node ID the kubelet records in the node's CSINode object.
// Nothing routes on it: there is no controller service and no topology.
func (s *nodeServer) NodeGetInfo(_ context.Context, _ *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{NodeId: s.nodeName}, nil
}

// NodeGetCapabilities reports none. STAGE_UNSTAGE_VOLUME would make the kubelet call
// NodeStageVolume, which is Unimplemented here, and every mount would fail. There is
// nothing to share between pods anyway: a socket per pod is the whole work.
func (s *nodeServer) NodeGetCapabilities(_ context.Context, _ *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return &csi.NodeGetCapabilitiesResponse{}, nil
}

// validateVolumeCapability refuses anything that is not a plain directory volume. A block
// volume asks for a raw device, which this driver has none of, and a mount carrying a
// filesystem type or mount flags asks for handling it has none of either. Same set of
// checks as upstream spiffe-csi.
func validateVolumeCapability(capability *csi.VolumeCapability) error {
	if capability == nil {
		return status.Error(codes.InvalidArgument, "volume capability is required")
	}
	if capability.GetBlock() != nil {
		return status.Error(codes.InvalidArgument,
			"block volumes are not supported: this driver publishes a directory")
	}

	// Nil for a capability with no access type, which the CSI specification requires,
	// and for an access type a later specification adds that this driver has no handling
	// for.
	mount := capability.GetMount()
	if mount == nil {
		return status.Error(codes.InvalidArgument,
			"volume capability access type is required and has to be a mount")
	}

	// Refused rather than ignored. The publish creates a socket in a plain directory, so
	// there is no filesystem to create and nothing to pass mount flags to; accepting either
	// would publish something other than what was asked for.
	//
	// The kubelet sends neither for the volume the Pod Identity webhook injects: it takes
	// the filesystem type from the volume's own csi.fsType, which the webhook leaves
	// unset, and mount flags only from a PersistentVolume's mountOptions, which an inline
	// ephemeral volume has none of. The one other way a flag appears is the SELinux mount
	// option, which the kubelet adds only for a driver whose CSIDriver object sets
	// seLinuxMount; ours does not, and adding it would have to come with a change here.
	if mount.GetFsType() != "" {
		return status.Errorf(codes.InvalidArgument,
			"volume capability names filesystem type %q: this driver publishes a socket in a plain "+
				"directory and formats nothing", mount.GetFsType())
	}
	if len(mount.GetMountFlags()) != 0 {
		return status.Errorf(codes.InvalidArgument,
			"volume capability carries mount flags %v: this driver's publish mounts nothing",
			mount.GetMountFlags())
	}

	// Not in tension with the read-only volume validateReadOnly requires: that governs
	// whether the kubelet mounts the volume writable inside the pod, while the access
	// mode says how many nodes may use the volume and how. For an inline ephemeral volume
	// the kubelet has no PersistentVolume to take access modes from and sends
	// SINGLE_NODE_WRITER, so a reader-only mode means this did not come from one.
	accessMode := capability.GetAccessMode()
	if accessMode == nil {
		return status.Error(codes.InvalidArgument, "volume capability access mode is required")
	}
	if accessMode.GetMode() == csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY {
		return status.Errorf(codes.InvalidArgument,
			"volume capability access mode is %s: the kubelet sends SINGLE_NODE_WRITER for an inline ephemeral "+
				"volume, so this request did not come from one", accessMode.GetMode())
	}

	return nil
}

// validateReadOnly refuses a volume the pod did not ask for read-only. The kubelet turns
// readOnly into a read-only mount in the container, which keeps the workload from replacing
// its socket, and on an SELinux node keeps the runtime from relabelling the target to the
// pod's own label. The Pod Identity webhook sets csi.readOnly on the volume it injects, so a
// false here means that contract broke.
func validateReadOnly(readOnly bool) error {
	if !readOnly {
		return status.Error(codes.InvalidArgument,
			"pod.spec.volumes[].csi.readOnly must be true: the kubelet is what mounts this volume read-only into "+
				"the pod, and a writable socket directory would let the workload replace its socket")
	}
	return nil
}

// validateEphemeral refuses a volume that did not arrive as an inline ephemeral one.
//
// The CSIDriver object declares Ephemeral only, so the other way in is a
// PersistentVolume naming this driver: an attempt to publish the socket into a
// pod the webhook never enrolled.
func validateEphemeral(volumeContext map[string]string) error {
	if volumeContext[ephemeralVolumeContextKey] != "true" {
		return status.Errorf(codes.InvalidArgument,
			"only inline ephemeral volumes are supported: %s is %q, so this is not an inline volume injected by the "+
				"Pod Identity webhook",
			ephemeralVolumeContextKey, volumeContext[ephemeralVolumeContextKey])
	}
	return nil
}

// validateTargetPath refuses a target outside the kubelet's pods directory, the only place
// the kubelet asks for one. An accepted target is a directory the node service creates and
// later deletes. Defence in depth, since reaching the 0600 plugin socket already means root.
// An unclean path is refused rather than cleaned: the kubelet sends clean absolute paths.
func validateTargetPath(target, podsDir string) error {
	if !filepath.IsAbs(target) {
		return status.Errorf(codes.InvalidArgument, "target path %s is not absolute", target)
	}
	if filepath.Clean(target) != target {
		return status.Errorf(codes.InvalidArgument, "target path %s is not a clean path", target)
	}

	relative, err := filepath.Rel(podsDir, target)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "target path %s is not under %s", target, podsDir)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || relative == "." {
		return status.Errorf(codes.InvalidArgument, "target path %s is not under %s", target, podsDir)
	}

	return nil
}

// A CSI dependency bump that adds a method fails here rather than at the registration.
var (
	_ csi.NodeServer     = (*nodeServer)(nil)
	_ csi.IdentityServer = (*identityServer)(nil)
)
