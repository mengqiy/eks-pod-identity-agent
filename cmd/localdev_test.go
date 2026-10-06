//go:build localdev

package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts/ststest"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

// TestLocalDevAgent serves the workload identity socket locally until interrupted,
// for trying a SPIFFE client against it by hand. It wires the real handler, trust
// bundle and X.509-SVID tiers and SO_PEERCRED attestation over the e2e fakes: a
// fake API server, the ststest STS, and a session stand-in for T5. Any local
// process attests as e2ePodA. Settings come from WI_LOCAL_* environment variables.
func TestLocalDevAgent(t *testing.T) {
	logger.Initialize(envOr("WI_LOCAL_LOG_LEVEL", "info"))
	socket := envOr("WI_LOCAL_SOCKET", "/tmp/wi-local/agent.sock")
	lifetime := envDuration(t, "WI_LOCAL_SVID_LIFETIME", 12*time.Hour)
	rotateEvery := envDuration(t, "WI_LOCAL_ROTATE_EVERY", 0)

	stsFake := ststest.New(t, ststest.Opts{RefreshHint: time.Minute, MaxLifetime: lifetime})
	creds := aws.Credentials{AccessKeyID: "ASIALOCALDEV", SecretAccessKey: "local-secret", SessionToken: "local-token"}
	stsFake.Register(creds, e2ePodA.spiffeID)
	jwtKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the JWT authority: %v", err)
	}
	stsFake.AddJWTAuthority(localdevKeyID, jwtKey.Public())

	kube := newWINodeClientset("system:node:" + wiTestNode)
	if err := kube.Tracker().Add(e2ePodA.object()); err != nil {
		t.Fatalf("seeding the pod: %v", err)
	}
	sessions := &fake.SessionProvider{Result: &workloadidentity.WorkloadSession{
		Credentials: creds, ProviderArn: stsFake.ProviderArn(), ExpiresAt: time.Now().Add(24 * time.Hour),
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tiers, err := buildWorkloadIdentityTiers(ctx, wiOpts, tierDeps{
		clientset: kube,
		sts:       sts.NewService(stsFake.Config()),
		cgroup:    localdevCgroup{},
		sessions:  sessions,
	})
	if err != nil {
		t.Fatalf("building the tiers: %v", err)
	}
	server, err := serveWorkloadIdentity(tiers, socket)
	if err != nil {
		t.Fatalf("serving %s: %v", socket, err)
	}
	if rotateEvery > 0 {
		go localdevRotate(ctx, stsFake, rotateEvery)
	}

	token := localdevToken(t, jwtKey, filepath.Join(filepath.Dir(socket), "demo.jwt"))
	fmt.Printf(`
Local workload identity agent is serving.
  socket:       %[1]s
  export:       export SPIFFE_ENDPOINT_SOCKET=unix://%[1]s
  identity:     %[2]s (any local process attests as pod %[3]s/%[4]s)
  SVID life:    %[5]s, CA rotation every %[6]s (0 means never)
  demo JWT:     %[7]s (subject %[8]s, audience %[9]s)
  try:          go run ./hack/spiffe-client -validate %[7]s -watch
Stop with Ctrl-C.
`, socket, e2ePodA.spiffeID, e2ePodA.namespace, e2ePodA.name, lifetime, rotateEvery, token, localdevPeer, localdevAudience)

	runServersUntilShutdown(ctx, []runnable{server, backgroundLoop{name: "trust-bundle-refresh", run: tiers.bundleSource.Run}})
}

const (
	// localdevKeyID is the JWT authority's key ID in the published bundle.
	localdevKeyID = "localdev-1"
	// localdevPeer and localdevAudience are the demo token's subject and audience.
	localdevPeer     = "spiffe://example.org/ns/team-b/sa/api"
	localdevAudience = "spiffe://example.org/demo"
)

// localdevCgroup attests every local caller as e2ePodA, since no local process
// is in a pod. SO_PEERCRED and the liveness recheck still run for real.
type localdevCgroup struct{}

func (localdevCgroup) PodUIDForPID(int) (string, error) { return e2ePodA.uid, nil }

// localdevRotate rotates the STS fake's CA every interval, so an open stream shows
// a bundle change once the trust bundle tier next refreshes.
func localdevRotate(ctx context.Context, s *ststest.Server, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.RotateCA()
			fmt.Printf("rotated the STS CA at %s\n", time.Now().Format(time.TimeOnly))
		}
	}
}

// localdevToken writes a JWT-SVID signed by the published authority to path, for
// a client to check with ValidateJWTSVID, and returns the path.
func localdevToken(t *testing.T, key *ecdsa.PrivateKey, path string) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), localdevKeyID))
	if err != nil {
		t.Fatalf("building the JWT signer: %v", err)
	}
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject:  spiffeid.RequireFromString(localdevPeer).String(),
		Audience: jwt.Audience{localdevAudience},
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).Serialize()
	if err != nil {
		t.Fatalf("signing the demo JWT: %v", err)
	}
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatalf("writing the demo JWT: %v", err)
	}
	return path
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envDuration(t *testing.T, name string, fallback time.Duration) time.Duration {
	t.Helper()

	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return d
}
