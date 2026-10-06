package x509

// Test scaffolding: a certificate authority that signs the agent's real requests,
// and a fake issuer that records what it was asked for.
//
// The CA signs actual CSRs and produces actual certificates rather than returning
// canned PEM, because most of what this tier has to get right is in the round trip:
// the request carries only a public key, the leaf that comes back carries the key
// and one URI SAN, and the validity window the schedule is derived from is the one
// on the certificate rather than the one that was asked for.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptox509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/require"
	clocktesting "k8s.io/utils/clock/testing"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

const (
	testSpiffeID = "spiffe://example.aws/eks/cluster/default/payments"
	testPodUID   = "pod-uid-1"
)

// testCA is a two level certificate authority: a root and an intermediate that
// signs leaves, so a response carries a chain with something in it and the tests
// can assert the root is not part of what STS returns.
type testCA struct {
	rootKey  crypto.Signer
	rootCert *cryptox509.Certificate
	rootDER  []byte

	interKey  crypto.Signer
	interCert *cryptox509.Certificate
	interDER  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              cryptox509.KeyUsageCertSign,
	}
	rootDER, err := cryptox509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	require.NoError(t, err)
	rootCert, err := cryptox509.ParseCertificate(rootDER)
	require.NoError(t, err)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	interTemplate := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              cryptox509.KeyUsageCertSign,
	}
	interDER, err := cryptox509.CreateCertificate(rand.Reader, interTemplate, rootCert, interKey.Public(), rootKey)
	require.NoError(t, err)
	interCert, err := cryptox509.ParseCertificate(interDER)
	require.NoError(t, err)

	return &testCA{
		rootKey: rootKey, rootCert: rootCert, rootDER: rootDER,
		interKey: interKey, interCert: interCert, interDER: interDER,
	}
}

// issue signs csrPEM into a leaf carrying spiffeID as its single URI SAN and the
// given validity window, and returns it shaped as an STS response.
//
// The chain holds the intermediate and deliberately not the root, which is what
// STS returns: a verifier takes the root from the trust bundle.
func (ca *testCA) issue(t *testing.T, csrPEM, spiffeID string, notBefore, notAfter time.Time) *sts.IssuedCertificate {
	t.Helper()

	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block, "the request the tier sent is not PEM")
	csr, err := cryptox509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	uri, err := url.Parse(spiffeID)
	require.NoError(t, err)

	leafDER, err := cryptox509.CreateCertificate(rand.Reader, &cryptox509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     cryptox509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []cryptox509.ExtKeyUsage{cryptox509.ExtKeyUsageClientAuth, cryptox509.ExtKeyUsageServerAuth},
		// The identity is supplied by the issuer, never taken from the request,
		// which is the division of responsibility the real call has.
		URIs: []*url.URL{uri},
	}, ca.interCert, csr.PublicKey, ca.interKey)
	require.NoError(t, err)

	return &sts.IssuedCertificate{
		CertificatePEM:      encodeCertPEM(leafDER),
		CertificateChainPEM: encodeCertPEM(ca.interDER),
		NotBefore:           notBefore.UTC(),
		NotAfter:            notAfter.UTC(),
		Subject:             spiffeID,
	}
}

func encodeCertPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der}))
}

// fakeIssuer records every request and answers from a function the test supplies.
type fakeIssuer struct {
	mu       sync.Mutex
	requests []sts.CertificateRequest
	creds    []aws.Credentials
	// respond answers one call. attempt counts from one.
	respond func(attempt int, req sts.CertificateRequest) (*sts.IssuedCertificate, error)
	// block, when non-nil, is waited on before responding, so a test can hold a
	// call open and observe coalescing.
	block chan struct{}
}

func (f *fakeIssuer) GetWorkloadIdentityCertificate(ctx context.Context, creds aws.Credentials, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.creds = append(f.creds, creds)
	attempt := len(f.requests)
	block, respond := f.block, f.respond
	f.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return respond(attempt, req)
}

func (f *fakeIssuer) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeIssuer) lastRequest(t *testing.T) sts.CertificateRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.requests, "the tier made no issuance call")
	return f.requests[len(f.requests)-1]
}

// testWorkload is an attested workload with the given pod UID.
func testWorkload(podUID string) *workloadidentity.Workload {
	return &workloadidentity.Workload{
		PodUID:         podUID,
		PodName:        "payments-" + podUID,
		Namespace:      "default",
		ServiceAccount: "payments",
		NodeName:       "node-1",
	}
}

// testSessions is a session provider returning credentials that expire at the
// given time, which is what the "do not clamp to the session" test varies.
func testSessions(expiresAt time.Time) *fake.SessionProvider {
	return &fake.SessionProvider{
		Result: &workloadidentity.WorkloadSession{
			Credentials: aws.Credentials{
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret",
				SessionToken:    "token",
				CanExpire:       true,
				Expires:         expiresAt,
			},
			ProviderArn: "arn:aws:iam::111122223333:workload-identity-provider/example",
			ExpiresAt:   expiresAt,
		},
	}
}

// newTestSource builds a Source with no janitor, time from now and jitter from draw.
// Nothing renews unless the test calls onRefresh, which skips the due check but still
// spends a RefreshQPS token (the default allows two while now stands still), or RenewDue,
// which runs the whole sweep by now.
func newTestSource(t *testing.T, issuer Issuer, sessions workloadidentity.SessionProvider, now func() time.Time, draw func() float64) *Source {
	t.Helper()
	s, err := New(Opts{
		Issuer:          issuer,
		SessionProvider: sessions,
		Notifier:        &fake.Subscriber{},
		MaxCacheSize:    10,
		Duration:        6 * time.Hour,
		RenewFraction:   0.5,
		RenewJitter:     0.1,
		// Negative disables the janitor goroutine.
		CleanupInterval: -1,
		Now:             now,
		Draw:            draw,
	})
	require.NoError(t, err)
	return s
}

// clockAt returns a clock the test advances by writing through the pointer.
func clockAt(at *time.Time) func() time.Time {
	return func() time.Time { return *at }
}

// clockStart is years behind the wall clock. A deadline the tier checks against
// time.Now instead of Opts.Now has long passed, so it fires early; one computed from
// time.Now lies years ahead of the fake clock, so it never comes due.
var clockStart = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// testMinRemaining is the MinRemaining newClockedSource sets. It is not the default,
// so a test that checks the cut-off names the value it depends on.
const testMinRemaining = 2 * time.Minute

// newClockedSource builds a Source through Opts alone, as a caller outside the
// package would: no janitor, time from clock, and the jitter draw mid-band so a
// six hour certificate renews at exactly three hours.
func newClockedSource(t *testing.T, issuer Issuer, notifier workloadidentity.WorkloadNotifier, clock *clocktesting.FakeClock) *Source {
	t.Helper()
	s, err := New(Opts{
		Issuer:          issuer,
		SessionProvider: testSessions(clockStart.Add(100 * time.Hour)),
		Notifier:        notifier,
		MaxCacheSize:    10,
		Duration:        6 * time.Hour,
		RenewFraction:   0.5,
		RenewJitter:     0.1,
		MinRemaining:    testMinRemaining,
		CleanupInterval: -1,
		Now:             clock.Now,
		Draw:            func() float64 { return 0.5 },
	})
	require.NoError(t, err)
	return s
}
