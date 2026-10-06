package main

// Pins the DaemonSet's side of the CSI node service against the paths the agent binds and
// the privilege it does without. Nothing else would notice if they drifted: the agent's
// tests use temporary directories, and the goldens only prove the chart still renders what
// it rendered yesterday.
//
// Unmarshals strictly, which also checks field names. A misspelled field renders fine and
// is dropped by the API server.

import (
	"os"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
)

// renderedChartPaths is every scenario make helm-verify renders that gets the CSI wiring.
// A hybrid node runs the same binary and kubelet layout, so it carries it too. The isolated
// region rendering is deliberately absent and is asserted against separately.
var renderedChartPaths = []string{
	"hack/testdata/expected_eks_pod_identity_agent_default_helm_template.yaml",
	"hack/testdata/expected_eks_pod_identity_agent_hybrid_helm_template.yaml",
	"hack/testdata/expected_eks_pod_identity_agent_hybrid_bottlerocket_helm_template.yaml",
}

func daemonSetsFromRenderedChart(t *testing.T, path string) []appsv1.DaemonSet {
	t.Helper()

	rendered, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading rendered chart %s: %v", path, err)
	}

	var daemonSets []appsv1.DaemonSet
	for _, doc := range strings.Split(string(rendered), "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var meta struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatalf("unmarshalling a document of %s: %v", path, err)
		}
		if meta.Kind != "DaemonSet" {
			continue
		}

		var daemonSet appsv1.DaemonSet
		if err := yaml.UnmarshalStrict([]byte(doc), &daemonSet); err != nil {
			t.Fatalf("unmarshalling a DaemonSet of %s: %v", path, err)
		}
		daemonSets = append(daemonSets, daemonSet)
	}

	if len(daemonSets) == 0 {
		t.Fatalf("no DaemonSet in %s", path)
	}
	return daemonSets
}

func agentContainer(t *testing.T, daemonSet appsv1.DaemonSet) corev1.Container {
	t.Helper()

	for _, container := range daemonSet.Spec.Template.Spec.Containers {
		if strings.HasPrefix(container.Name, "eks-pod-identity-agent") {
			return container
		}
	}
	t.Fatalf("DaemonSet %s has no agent container", daemonSet.Name)
	return corev1.Container{}
}

// TestChartDaemonSetMountsTheCSIPathsAtTheirHostPaths is the one that matters most. Each
// path is mounted at its host path, which is what makes the endpoint reported at
// registration openable by the kubelet: the agent binds it in its own mount namespace and
// the kubelet opens it in the host's. Mounting elsewhere gives a plugin that registers and
// is never called, which looks like nothing at all in the agent's logs.
func TestChartDaemonSetMountsTheCSIPathsAtTheirHostPaths(t *testing.T) {
	expected := []string{
		configuration.KubeletPluginDir,
		configuration.KubeletPluginRegistrationDir,
		configuration.KubeletPodsDir,
	}

	for _, chartPath := range renderedChartPaths {
		for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
			container := agentContainer(t, daemonSet)

			mountPaths := map[string]string{} // mount path -> volume name
			for _, mount := range container.VolumeMounts {
				mountPaths[mount.MountPath] = mount.Name
			}
			hostPaths := map[string]string{} // volume name -> host path
			for _, volume := range daemonSet.Spec.Template.Spec.Volumes {
				if volume.HostPath != nil {
					hostPaths[volume.Name] = volume.HostPath.Path
				}
			}

			// The socket directory is no longer a host path: each pod's socket lives in its own
			// volume directory, so a host mount here would only be unused host access.
			if _, mounted := mountPaths[configuration.WorkloadIdentitySocketMountPath]; mounted {
				t.Errorf("%s: DaemonSet %s mounts %s, which nothing in the agent uses any more",
					chartPath, daemonSet.Name, configuration.WorkloadIdentitySocketMountPath)
			}

			for _, path := range expected {
				volumeName, mounted := mountPaths[path]
				if !mounted {
					t.Errorf("%s: DaemonSet %s does not mount %s, which the agent binds or publishes in",
						chartPath, daemonSet.Name, path)
					continue
				}
				if hostPaths[volumeName] != path {
					t.Errorf("%s: DaemonSet %s mounts volume %s at %s but its host path is %q: the two have to be "+
						"equal or the endpoint the agent reports to the kubelet is a path the kubelet cannot open",
						chartPath, daemonSet.Name, volumeName, path, hostPaths[volumeName])
				}
			}
		}
	}
}

// TestChartDaemonSetMountsThePodsDirectoryWithoutBidirectionalPropagation keeps the publish
// mount-free. The node service creates a socket in the pod's volume directory, which the
// host sees without propagation; Bidirectional would only be there for a mount, and
// Kubernetes admits it only on a privileged container.
func TestChartDaemonSetMountsThePodsDirectoryWithoutBidirectionalPropagation(t *testing.T) {
	for _, chartPath := range renderedChartPaths {
		for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
			container := agentContainer(t, daemonSet)

			var found bool
			for _, mount := range container.VolumeMounts {
				if mount.MountPath != configuration.KubeletPodsDir {
					continue
				}
				found = true
				if mount.MountPropagation != nil && *mount.MountPropagation == corev1.MountPropagationBidirectional {
					t.Errorf("%s: DaemonSet %s mounts %s with Bidirectional propagation, which the publish does "+
						"not need and which forces the container privileged", chartPath, daemonSet.Name, mount.MountPath)
				}
			}
			if !found {
				t.Errorf("%s: DaemonSet %s does not mount %s", chartPath, daemonSet.Name, configuration.KubeletPodsDir)
			}
		}
	}
}

// TestChartDaemonSetDoesNotRunTheAgentPrivileged pins the point of publishing without a
// mount: the long-running container, which every pod on the node talks to, keeps only the
// capability it had before the CSI node service.
func TestChartDaemonSetDoesNotRunTheAgentPrivileged(t *testing.T) {
	for _, chartPath := range append([]string{isolatedRegionChartPath}, renderedChartPaths...) {
		for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
			container := agentContainer(t, daemonSet)

			securityContext := container.SecurityContext
			if securityContext == nil {
				t.Errorf("%s: DaemonSet %s sets no security context on the agent", chartPath, daemonSet.Name)
				continue
			}
			if securityContext.Privileged != nil && *securityContext.Privileged {
				t.Errorf("%s: DaemonSet %s runs the agent privileged, which nothing in it needs",
					chartPath, daemonSet.Name)
			}
			if securityContext.Capabilities == nil ||
				len(securityContext.Capabilities.Add) != 1 || securityContext.Capabilities.Add[0] != "CAP_NET_BIND_SERVICE" {
				t.Errorf("%s: DaemonSet %s adds capabilities %v to the agent; only CAP_NET_BIND_SERVICE is needed",
					chartPath, daemonSet.Name, securityContext.Capabilities)
			}
		}
	}
}

// TestChartDaemonSetSetsTheNodeNameFromTheDownwardAPI keeps the ordinary path off the
// agent's hostname fallback.
func TestChartDaemonSetSetsTheNodeNameFromTheDownwardAPI(t *testing.T) {
	for _, chartPath := range renderedChartPaths {
		for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
			container := agentContainer(t, daemonSet)

			var found bool
			for _, env := range container.Env {
				if env.Name != "NODE_NAME" {
					continue
				}
				found = true
				if env.ValueFrom == nil || env.ValueFrom.FieldRef == nil ||
					env.ValueFrom.FieldRef.FieldPath != "spec.nodeName" {
					t.Errorf("%s: DaemonSet %s sets NODE_NAME from %v rather than from spec.nodeName",
						chartPath, daemonSet.Name, env.ValueFrom)
				}
			}
			if !found {
				t.Errorf("%s: DaemonSet %s does not set NODE_NAME, so the agent falls back to the hostname for its "+
					"CSI node ID", chartPath, daemonSet.Name)
			}
		}
	}
}

// TestChartDaemonSetOmitsTheCSIWiringInAnIsolatedRegion is the DaemonSet half of the region
// gate. Nothing there runs the node service, so the three kubelet mounts and NODE_NAME come
// off: a region that cannot use the feature should not carry host access for it.
func TestChartDaemonSetOmitsTheCSIWiringInAnIsolatedRegion(t *testing.T) {
	const chartPath = isolatedRegionChartPath

	absent := []string{
		configuration.KubeletPluginDir,
		configuration.KubeletPluginRegistrationDir,
		configuration.KubeletPodsDir,
	}

	for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
		container := agentContainer(t, daemonSet)

		for _, mount := range container.VolumeMounts {
			for _, path := range absent {
				if mount.MountPath == path {
					t.Errorf("%s: DaemonSet %s mounts %s, which only the CSI node service needs and which "+
						"is not started in an isolated region", chartPath, daemonSet.Name, path)
				}
			}
		}

		for _, volume := range daemonSet.Spec.Template.Spec.Volumes {
			if volume.HostPath == nil {
				continue
			}
			for _, path := range absent {
				if volume.HostPath.Path == path {
					t.Errorf("%s: DaemonSet %s declares host volume %s for %s, which nothing in this "+
						"rendering consumes", chartPath, daemonSet.Name, volume.Name, path)
				}
			}
		}

		for _, env := range container.Env {
			if env.Name == "NODE_NAME" {
				t.Errorf("%s: DaemonSet %s sets NODE_NAME, which is only the CSI node ID",
					chartPath, daemonSet.Name)
			}
		}
	}
}
