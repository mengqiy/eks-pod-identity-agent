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

	// targetPathMode is the mode of the target directory when the node service has to
	// create it; the kubelet normally has already.
	targetPathMode os.FileMode = 0o755
)

// nodeServer publishes the agent's socket directory into an enrolled pod.
//
// The volume is a directory that already exists on the node, so there is nothing to
// provision, attach, format or stage, and every method beyond a bind mount is left to
// the embedded UnimplementedNodeServer.
//
// The source is fixed at construction and never taken from the request. A CSI driver
// ordinarily derives what to mount from the request; this one must not, or a caller on
// this socket could use a privileged process as a general purpose mount service.
type nodeServer struct {
	csi.UnimplementedNodeServer

	mounter Mounter
	// nodeName is reported as the CSI node ID; see Opts.NodeName.
	nodeName string
	// source is the published directory, configuration.WorkloadIdentitySocketMountPath
	// in production.
	source string
	// podsDir is the root every target path must be inside.
	podsDir string
}

func newNodeServer(mounter Mounter, nodeName, source, podsDir string) *nodeServer {
	return &nodeServer{mounter: mounter, nodeName: nodeName, source: source, podsDir: podsDir}
}

// NodePublishVolume mounts the socket directory at the kubelet's target path.
//
// Idempotent: the kubelet repeats a publish whose reply it never got, and a second mount
// on one target would stack where the unpublish unwinds one.
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

	mounted, err := s.mounter.IsMountPoint(target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to tell whether %s is already a mount point: %v", target, err)
	}
	if mounted {
		// Debug, so a kubelet retrying in a loop does not bury the rest of the log.
		log.Debug("CSI NodePublishVolume: target is already mounted, nothing to do")
		return &csi.NodePublishVolumeResponse{}, nil
	}

	// MkdirAll covers the kubelet not having created the target yet.
	if err := os.MkdirAll(target, targetPathMode); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to create target path %s: %v", target, err)
	}

	// Read-write, because this mount is the agent's own view and the kubelet is what
	// makes the pod's read-only; see validateReadOnly and Mounter.BindMountRW.
	if err := s.mounter.BindMountRW(s.source, target); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to publish %s at %s: %v", s.source, target, err)
	}

	log.Infof("CSI NodePublishVolume: published %s", s.source)
	return &csi.NodePublishVolumeResponse{}, nil
}

// NodeUnpublishVolume removes the mount and the directory the kubelet created for it.
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
	// Checked here too: an unpublish unmounts and deletes, so a target outside the
	// kubelet's pods directory is a request to remove something that was never ours.
	if err := validateTargetPath(target, s.podsDir); err != nil {
		return nil, err
	}

	log = log.WithFields(map[string]any{"volume-id": req.GetVolumeId(), "target-path": target})

	if err := s.mounter.Unmount(target); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to unpublish %s: %v", target, err)
	}

	// os.Remove rather than RemoveAll: after the unmount this is the empty directory the
	// kubelet created, and a non-empty one holds something that was not part of the
	// mount.
	if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
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
// nothing to share between pods anyway: a bind mount per pod is the whole work.
func (s *nodeServer) NodeGetCapabilities(_ context.Context, _ *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return &csi.NodeGetCapabilitiesResponse{}, nil
}

// validateVolumeCapability refuses anything that is not the plain directory mount this
// driver performs. A block volume asks for a raw device, which this driver has none of,
// and a mount carrying a filesystem type or mount flags asks for handling it has none of
// either. Same set of checks as upstream spiffe-csi.
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

	// Refused rather than ignored. The publish is a bind mount of a directory that
	// already exists, so there is no filesystem to create and nothing to pass mount flags
	// to; accepting either would mount something other than what was asked for.
	//
	// The kubelet sends neither for the volume the Pod Identity webhook injects: it takes
	// the filesystem type from the volume's own csi.fsType, which the webhook leaves
	// unset, and mount flags only from a PersistentVolume's mountOptions, which an inline
	// ephemeral volume has none of. The one other way a flag appears is the SELinux mount
	// option, which the kubelet adds only for a driver whose CSIDriver object sets
	// seLinuxMount; ours does not, and adding it would have to come with a change here.
	if mount.GetFsType() != "" {
		return status.Errorf(codes.InvalidArgument,
			"volume capability names filesystem type %q: this driver bind mounts an existing directory "+
				"and formats nothing", mount.GetFsType())
	}
	if len(mount.GetMountFlags()) != 0 {
		return status.Errorf(codes.InvalidArgument,
			"volume capability carries mount flags %v: this driver's publish is a plain bind mount",
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

// validateReadOnly refuses a volume the pod did not ask for read-only.
//
// This is the whole of the driver's protection against a workload unlinking the agent's
// socket and binding its own, which every enrolled pod on the node would then dial. The
// node service cannot provide it: a read-only bind needs a second MS_REMOUNT syscall
// whose flag change does not propagate out of the agent's mount namespace, so the pod's
// mount stays read-write however this one is flagged. What does work is readOnly on the
// volume, which the kubelet turns into a read-only mount in the container.
//
// So it is required rather than inferred. The Pod Identity webhook sets
// pod.spec.volumes[].csi.readOnly on the volume it injects, and the kubelet forwards that
// as this field; a false here means that contract broke, and failing the publish puts the
// first enrolled pod in ContainerCreating instead of handing every pod on the node a
// writable socket directory.
func validateReadOnly(readOnly bool) error {
	if !readOnly {
		return status.Error(codes.InvalidArgument,
			"pod.spec.volumes[].csi.readOnly must be true: the kubelet is what mounts this volume read-only into "+
				"the pod, and a writable socket directory would let the workload replace the agent's socket")
	}
	return nil
}

// validateEphemeral refuses a volume that did not arrive as an inline ephemeral one.
//
// The CSIDriver object declares Ephemeral only, so the other way in is a
// PersistentVolume naming this driver: an attempt to mount the socket directory into a
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

// validateTargetPath refuses a target outside the kubelet's pods directory.
//
// The process serving these calls can mount, so an accepted target is a path it will
// shadow — over /etc, or over another pod's volume. The kubelet only ever asks for a
// path under its own pods directory. Defence in depth, since the socket is 0600 and
// reaching it already means root, but it costs one comparison.
//
// An unclean path is refused rather than cleaned: the kubelet sends clean absolute
// paths, so normalising one would hide where it came from.
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
