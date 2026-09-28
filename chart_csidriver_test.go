package main

// This file pins the workload identity CSIDriver object the Helm chart installs against
// the agent's own constants and against the shape the API server requires.
//
// The object is a contract with three parties outside this chart: the Pod Identity
// webhook, which names the driver on an enrolled pod's inline volume; the agent, which
// listens on the socket in the directory the driver publishes; and the API server, whose
// node audience restriction consults the driver's declared tokenRequests before it
// permits the agent's TokenRequest. Nothing in Helm can see a Go constant, so the chart
// carries the strings as literals and this test is what keeps the two in step. Drift is
// a cluster-wide failure — every enrolled pod stops getting credentials — and it would
// otherwise only surface on a live cluster.
//
// It asserts on the checked-in rendered template rather than invoking Helm, because
// make helm-verify already proves the golden files match the chart, and a Go test that
// shells out to a downloaded Helm binary would not run under plain `go test ./...`.

import (
	"os"
	"strings"
	"testing"

	storagev1 "k8s.io/api/storage/v1"
	"sigs.k8s.io/yaml"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
)

// renderedChartPath is the default rendering of the chart, which is what an EKS cluster
// gets. The workload identity CSIDriver object has no values knob, so it appears in this
// file unconditionally.
const renderedChartPath = "hack/testdata/expected_eks_pod_identity_agent_default_helm_template.yaml"

// csiDriverFromRenderedChart pulls the single CSIDriver document out of the rendered
// chart. A missing object fails the test rather than skipping it: the chart is the
// installer of record, so "no CSIDriver rendered" is exactly the regression worth
// catching.
func csiDriverFromRenderedChart(t *testing.T) *storagev1.CSIDriver {
	t.Helper()

	rendered, err := os.ReadFile(renderedChartPath)
	if err != nil {
		t.Fatalf("reading rendered chart %s: %v", renderedChartPath, err)
	}

	var found *storagev1.CSIDriver
	for _, doc := range strings.Split(string(rendered), "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}

		// Decode only the kind first. The rendered chart holds DaemonSets and other
		// kinds whose fields would not survive being unmarshalled into a CSIDriver.
		var meta struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatalf("unmarshalling a document of %s: %v", renderedChartPath, err)
		}
		if meta.Kind != "CSIDriver" {
			continue
		}

		var driver storagev1.CSIDriver
		if err := yaml.UnmarshalStrict([]byte(doc), &driver); err != nil {
			t.Fatalf("unmarshalling the CSIDriver document of %s: %v", renderedChartPath, err)
		}
		if found != nil {
			t.Fatalf("the chart renders more than one CSIDriver object; there is exactly one driver")
		}
		found = &driver
	}

	if found == nil {
		t.Fatalf("no CSIDriver object in %s: the chart is what installs it, and without it "+
			"the agent's TokenRequest for %s is refused by the node audience restriction",
			renderedChartPath, configuration.EksAuthAudience)
	}
	return found
}

// TestChartCSIDriverMatchesFrozenContract covers the two strings that are shared with
// something outside this repository.
func TestChartCSIDriverMatchesFrozenContract(t *testing.T) {
	driver := csiDriverFromRenderedChart(t)

	if driver.Name != configuration.WorkloadIdentityCSIDriver {
		t.Errorf("chart installs CSIDriver %q, agent expects configuration.WorkloadIdentityCSIDriver %q: "+
			"the webhook names this driver on an enrolled pod's volume, so a mismatch means the volume "+
			"never mounts", driver.Name, configuration.WorkloadIdentityCSIDriver)
	}

	// The audience is the whole reason the object exists. The API server permits a node
	// identity's TokenRequest only for an audience the target pod already references,
	// and for an enrolled pod that reference is this declaration.
	audiences := make([]string, 0, len(driver.Spec.TokenRequests))
	for _, request := range driver.Spec.TokenRequests {
		audiences = append(audiences, request.Audience)
	}
	if len(audiences) != 1 || audiences[0] != configuration.EksAuthAudience {
		t.Errorf("chart declares tokenRequests audiences %v, agent mints for configuration.EksAuthAudience %q: "+
			"a mismatch makes every mint fail with ErrTokenMintForbidden",
			audiences, configuration.EksAuthAudience)
	}
}

// TestChartCSIDriverSpecMatchesTheNodeServiceItDescribes covers the fields that describe
// how kubelet should drive the driver. attachRequired and podInfoOnMount are called out
// because Kubernetes makes them immutable after creation: getting them wrong here is not
// a later edit but a delete-and-recreate migration on every existing cluster.
func TestChartCSIDriverSpecMatchesTheNodeServiceItDescribes(t *testing.T) {
	driver := csiDriverFromRenderedChart(t)

	if driver.Spec.AttachRequired == nil || *driver.Spec.AttachRequired {
		t.Errorf("attachRequired must be false: the node service bind-mounts a node-local "+
			"directory and there is nothing for the attach/detach controller to do (immutable "+
			"once created), got %v", driver.Spec.AttachRequired)
	}

	if driver.Spec.PodInfoOnMount == nil || !*driver.Spec.PodInfoOnMount {
		t.Errorf("podInfoOnMount must be true: the node service needs the pod's identity in the "+
			"volume context to publish the right socket directory (immutable once created), got %v",
			driver.Spec.PodInfoOnMount)
	}

	modes := driver.Spec.VolumeLifecycleModes
	if len(modes) != 1 || modes[0] != storagev1.VolumeLifecycleEphemeral {
		t.Errorf("volumeLifecycleModes must be exactly [Ephemeral]: the webhook injects an inline "+
			"volume and this driver has no PersistentVolume path, got %v", modes)
	}
}
