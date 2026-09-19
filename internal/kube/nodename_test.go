package kube

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

const testNode = "ip-10-0-1-23.us-west-2.compute.internal"

// clientReturningUsername builds a fake clientset whose SelfSubjectReview create
// reports the given authenticated username, which is how the API server tells
// the agent which identity it presented.
func clientReturningUsername(username string) *fake.Clientset {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "selfsubjectreviews",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, &authenticationv1.SelfSubjectReview{
				Status: authenticationv1.SelfSubjectReviewStatus{
					UserInfo: authenticationv1.UserInfo{Username: username},
				},
			}, nil
		})
	return client
}

// TestResolveNodeName_StripsNodePrefix proves the node name is the username with
// the system:node: prefix removed, which is the identity the API server will
// authorize the pod watch against.
func TestResolveNodeName_StripsNodePrefix(t *testing.T) {
	g := NewWithT(t)

	client := clientReturningUsername("system:node:" + testNode)

	name, err := ResolveNodeName(context.Background(), client)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(name).To(Equal(testNode))
}

// TestResolveNodeName_RejectsNonNodeIdentity proves a username that is not a node
// identity is a hard error, not a silently stripped value: it means the agent is
// not authenticating as the node and the node-scoped design does not hold.
func TestResolveNodeName_RejectsNonNodeIdentity(t *testing.T) {
	testCases := []struct {
		name     string
		username string
	}{
		{name: "service account", username: "system:serviceaccount:kube-system:pod-identity-agent"},
		{name: "empty node name", username: "system:node:"},
		{name: "anonymous", username: "system:anonymous"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			client := clientReturningUsername(tc.username)

			_, err := ResolveNodeName(context.Background(), client)

			g.Expect(err).To(HaveOccurred())
		})
	}
}
