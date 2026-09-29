package main

// Pins the DaemonSet's side of the CSI node service against the paths the agent binds and
// the permissions the mount needs. Nothing else would notice if they drifted: the agent's
// tests use temporary directories, and the goldens only prove the chart still renders what
// it rendered yesterday.
//
// Unmarshals strictly, which also checks field names. A misspelled mountPropagation
// renders fine, is dropped by the API server, and produces a publish into a directory the
// kubelet sees as empty.

import (
	"os"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
)

// renderedChartPaths is every scenario make helm-verify renders. The CSI wiring is
// unconditional, so each must carry it: a hybrid node runs the same binary and kubelet
// layout.
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
		configuration.WorkloadIdentitySocketMountPath,
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

			for _, path := range expected {
				volumeName, mounted := mountPaths[path]
				if !mounted {
					t.Errorf("%s: DaemonSet %s does not mount %s, which the agent binds or publishes into",
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

// TestChartDaemonSetPublishesWithBidirectionalPropagation covers what makes the mount
// visible outside the agent's namespace. With any other propagation the publish reports
// success, the kubelet finds an empty directory, and the pod starts with no socket — a
// failure with no error in it.
func TestChartDaemonSetPublishesWithBidirectionalPropagation(t *testing.T) {
	for _, chartPath := range renderedChartPaths {
		for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
			container := agentContainer(t, daemonSet)

			var found bool
			for _, mount := range container.VolumeMounts {
				if mount.MountPath != configuration.KubeletPodsDir {
					continue
				}
				found = true
				if mount.MountPropagation == nil || *mount.MountPropagation != corev1.MountPropagationBidirectional {
					t.Errorf("%s: DaemonSet %s mounts %s with propagation %v, which does not reach the host mount "+
						"namespace, so a published mount is invisible to the kubelet",
						chartPath, daemonSet.Name, mount.MountPath, mount.MountPropagation)
				}
			}
			if !found {
				t.Errorf("%s: DaemonSet %s does not mount %s", chartPath, daemonSet.Name, configuration.KubeletPodsDir)
			}
		}
	}
}

// TestChartDaemonSetRunsTheAgentPrivileged records the cost of the above rather than
// endorsing it: Kubernetes allows Bidirectional propagation only for a privileged
// container. A change that drops privileged fails here, next to the reason, rather than on
// a node as a pod that cannot start.
func TestChartDaemonSetRunsTheAgentPrivileged(t *testing.T) {
	for _, chartPath := range renderedChartPaths {
		for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
			container := agentContainer(t, daemonSet)

			securityContext := container.SecurityContext
			if securityContext == nil || securityContext.Privileged == nil || !*securityContext.Privileged {
				t.Errorf("%s: DaemonSet %s does not run the agent privileged, which Kubernetes requires for the "+
					"Bidirectional mount propagation the CSI publish depends on", chartPath, daemonSet.Name)
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
