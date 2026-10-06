package ststest_test

// These tests drive the fake through the real client in internal/cloud/sts, so
// what they establish is what the agent's tiers see over the wire.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	clocktesting "k8s.io/utils/clock/testing"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts/ststest"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/material/bundle"
	x509source "go.amzn.com/eks/eks-pod-identity-agent/internal/material/x509"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

// testTimeout bounds every call in this file, so a fake that fails to answer
// fails the test instead of hanging the suite.
const testTimeout = 10 * time.Second

var (
	workloadID    = spiffeid.RequireFromString("spiffe://example.org/ns/default/sa/example-sa")
	workloadCreds = aws.Credentials{
		AccessKeyID:     "ASIASTSTESTWORKLOAD1",
		SecretAccessKey: "ststest-workload-secret-access-key",
		SessionToken:    "ststest-workload-session-token",
	}
)

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// newServer is a fake with workloadCreds registered for workloadID.
func newServer(t *testing.T, opts ststest.Opts) *ststest.Server {
	t.Helper()
	s := ststest.New(t, opts)
	s.Register(workloadCreds, workloadID)
	return s
}

func newECKey(t *testing.T, curve elliptic.Curve) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	return key
}

func newRSAKey(t *testing.T, bits int) crypto.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	return key
}

// newCSR is the PEM certificate request the agent sends: no name, signed by key.
func newCSR(t *testing.T, key crypto.Signer) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("creating a CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func issue(t *testing.T, s *ststest.Server, creds aws.Credentials, csr string, maxDuration time.Duration) (*sts.IssuedCertificate, error) {
	t.Helper()
	return sts.NewService(s.Config()).GetWorkloadIdentityCertificate(testContext(t), creds, sts.CertificateRequest{
		CertificateSigningRequestPEM: csr,
		MaxDuration:                  maxDuration,
	})
}

func mustIssue(t *testing.T, s *ststest.Server, key crypto.Signer) *sts.IssuedCertificate {
	t.Helper()
	issued, err := issue(t, s, workloadCreds, newCSR(t, key), 0)
	if err != nil {
		t.Fatalf("GetWorkloadIdentityCertificate: %v", err)
	}
	return issued
}

func parseCertificates(t *testing.T, text string) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing a certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	if strings.TrimSpace(string(rest)) != "" {
		t.Fatalf("trailing data after the certificates: %q", rest)
	}
	return certs
}

// chainOf is the issued leaf followed by its chain, as the agent serves it.
func chainOf(t *testing.T, issued *sts.IssuedCertificate) []*x509.Certificate {
	t.Helper()
	return append(parseCertificates(t, issued.CertificatePEM), parseCertificates(t, issued.CertificateChainPEM)...)
}

func fetchBundle(t *testing.T, s *ststest.Server) *spiffebundle.Bundle {
	t.Helper()
	entries, err := sts.NewService(s.Config()).GetTrustBundles(testContext(t), workloadCreds, s.ProviderArn())
	if err != nil {
		t.Fatalf("GetTrustBundles: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("GetTrustBundles returned %d entries, expected 1", len(entries))
	}
	document, err := spiffebundle.Parse(spiffeid.RequireTrustDomainFromString(entries[0].TrustDomain), []byte(entries[0].Bundle))
	if err != nil {
		t.Fatalf("parsing the bundle document: %v", err)
	}
	return document
}

func raw(certs []*x509.Certificate) [][]byte {
	out := make([][]byte, len(certs))
	for i, cert := range certs {
		out[i] = cert.Raw
	}
	return out
}

// expectAPIError asserts err is the awsQuery error code at status, as the
// tiers classify it.
func expectAPIError(g Gomega, err error, code string, status int) {
	g.Expect(err).To(HaveOccurred())
	var apiErr smithy.APIError
	g.Expect(errors.As(err, &apiErr)).To(BeTrue(), "%v is not an API error", err)
	g.Expect(apiErr.ErrorCode()).To(Equal(code))
	var responseErr *awshttp.ResponseError
	g.Expect(errors.As(err, &responseErr)).To(BeTrue())
	g.Expect(responseErr.HTTPStatusCode()).To(Equal(status))
	g.Expect(responseErr.ServiceRequestID()).To(HavePrefix("ststest-"))
}

func TestServer_IssuesAnSVIDForTheRegisteredIdentity(t *testing.T) {
	tests := []struct {
		name     string
		key      func(*testing.T) crypto.Signer
		keyUsage x509.KeyUsage
	}{
		{"P-256", func(t *testing.T) crypto.Signer { return newECKey(t, elliptic.P256()) }, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement},
		{"P-384", func(t *testing.T) crypto.Signer { return newECKey(t, elliptic.P384()) }, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement},
		{"RSA-2048", func(t *testing.T) crypto.Signer { return newRSAKey(t, 2048) }, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			s := newServer(t, ststest.Opts{})
			key := tc.key(t)

			issued := mustIssue(t, s, key)

			// go-spiffe accepts it as an X509-SVID for the key the CSR carried, and
			// it chains to the published roots.
			certs := chainOf(t, issued)
			keyDER, err := x509.MarshalPKCS8PrivateKey(key)
			g.Expect(err).ToNot(HaveOccurred())
			var certDER []byte
			for _, cert := range certs {
				certDER = append(certDER, cert.Raw...)
			}
			svid, err := x509svid.ParseRaw(certDER, keyDER)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(svid.ID).To(Equal(workloadID))
			id, _, err := x509svid.Verify(certs, x509bundle.FromX509Authorities(s.TrustDomain(), s.X509Authorities()))
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(id).To(Equal(workloadID))

			leaf := certs[0]
			g.Expect(leaf.URIs).To(HaveLen(1))
			g.Expect(leaf.IsCA).To(BeFalse())
			g.Expect(leaf.KeyUsage).To(Equal(tc.keyUsage))
			g.Expect(leaf.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth))
			g.Expect(issued.Subject).To(Equal(workloadID.String()))
			g.Expect(certs).To(HaveLen(2), "the chain holds the intermediate only")
			g.Expect(raw(s.X509Authorities())).ToNot(ContainElement(certs[1].Raw))
			g.Expect(raw(s.Issued())).To(Equal([][]byte{leaf.Raw}))

			requests := s.Requests()
			g.Expect(requests).To(HaveLen(1))
			g.Expect(requests[0].Action).To(Equal(ststest.ActionGetWorkloadIdentityCertificate))
			g.Expect(requests[0].AccessKeyID).To(Equal(workloadCreds.AccessKeyID))
			g.Expect(requests[0].CSR).ToNot(BeNil())
			g.Expect(key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(requests[0].CSR.PublicKey)).To(BeTrue())
			g.Expect(s.Calls(ststest.ActionGetWorkloadIdentityCertificate)).To(Equal(1))
			g.Expect(s.Calls(ststest.ActionGetTrustBundles)).To(Equal(0))
		})
	}
}

func TestServer_IssuedLifetimeIsTheLeastOfTheRequestAndMaxLifetime(t *testing.T) {
	tests := []struct {
		name        string
		maxDuration time.Duration
		maxLifetime time.Duration
		want        time.Duration
	}{
		{name: "STS's default", want: 12 * time.Hour},
		{name: "the requested duration", maxDuration: 6 * time.Hour, want: 6 * time.Hour},
		{name: "MaxLifetime below the request", maxDuration: 6 * time.Hour, maxLifetime: time.Hour, want: time.Hour},
		{name: "MaxLifetime below the default", maxLifetime: 30 * time.Minute, want: 30 * time.Minute},
		{name: "the request below MaxLifetime", maxDuration: 2 * time.Hour, maxLifetime: 3 * time.Hour, want: 2 * time.Hour},
		{name: "MaxLifetime truncated to the second", maxLifetime: 1500 * time.Millisecond, want: time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			// Off the second, and nowhere near the wall clock.
			clock := clocktesting.NewFakeClock(time.Date(2031, 3, 4, 5, 6, 7, 500_000_000, time.UTC))
			s := newServer(t, ststest.Opts{Now: clock.Now, MaxLifetime: tc.maxLifetime})

			issued, err := issue(t, s, workloadCreds, newCSR(t, newECKey(t, elliptic.P256())), tc.maxDuration)
			g.Expect(err).ToNot(HaveOccurred())

			leaf := chainOf(t, issued)[0]
			start := time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)
			g.Expect(leaf.NotBefore).To(BeTemporally("==", start))
			g.Expect(leaf.NotAfter).To(BeTemporally("==", start.Add(tc.want)))
			g.Expect(issued.NotBefore).To(BeTemporally("==", leaf.NotBefore))
			g.Expect(issued.NotAfter).To(BeTemporally("==", leaf.NotAfter))
			_, _, err = x509svid.Verify(chainOf(t, issued), x509bundle.FromX509Authorities(s.TrustDomain(), s.X509Authorities()),
				x509svid.WithTime(clock.Now()))
			g.Expect(err).ToNot(HaveOccurred())

			// The next certificate starts wherever the clock has moved to.
			clock.Step(3 * time.Hour)
			issued, err = issue(t, s, workloadCreds, newCSR(t, newECKey(t, elliptic.P256())), tc.maxDuration)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(issued.NotBefore).To(BeTemporally("==", start.Add(3*time.Hour)))
		})
	}
}

// fatalRecorder is a testing.TB whose Fatalf records the message and ends the
// goroutine, as testing.T's does, without failing the test.
type fatalRecorder struct {
	testing.TB
	fatal string
}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.fatal = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func TestNew_FailsOnAnOptOutOfRange(t *testing.T) {
	tests := []struct {
		name    string
		opts    ststest.Opts
		message string
	}{
		{"a negative MaxLifetime", ststest.Opts{MaxLifetime: -time.Second}, "must not be negative"},
		{"a negative RefreshHint", ststest.Opts{RefreshHint: -time.Second}, "must not be negative"},
		{"a MaxLifetime under a second", ststest.Opts{MaxLifetime: 999 * time.Millisecond}, "under a second"},
		{"a MaxLifetime of a nanosecond", ststest.Opts{MaxLifetime: time.Nanosecond}, "under a second"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			recorder := &fatalRecorder{TB: t}
			done := make(chan struct{})
			go func() {
				defer close(done)
				ststest.New(recorder, tc.opts)
				t.Error("New returned")
			}()
			<-done

			g.Expect(recorder.fatal).To(ContainSubstring(tc.message))
		})
	}
}

func TestServer_MaxDurationOutsideTheModelRange_IsAValidationError(t *testing.T) {
	for _, maxDuration := range []time.Duration{30 * time.Minute, 13 * time.Hour} {
		t.Run(maxDuration.String(), func(t *testing.T) {
			g := NewWithT(t)
			s := newServer(t, ststest.Opts{})

			_, err := issue(t, s, workloadCreds, newCSR(t, newECKey(t, elliptic.P256())), maxDuration)

			expectAPIError(g, err, "ValidationError", http.StatusBadRequest)
			g.Expect(s.Issued()).To(BeEmpty())
		})
	}
}

func TestServer_RefusesAMalformedCSR(t *testing.T) {
	tamper := func(t *testing.T) string {
		block, _ := pem.Decode([]byte(newCSR(t, newECKey(t, elliptic.P256()))))
		// The last byte is inside the signature, so the CSR still parses but no
		// longer verifies.
		block.Bytes[len(block.Bytes)-1] ^= 0xff
		return string(pem.EncodeToMemory(block))
	}
	ed25519CSR := func(t *testing.T) string {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating a key: %v", err)
		}
		return newCSR(t, key)
	}
	tests := []struct {
		name    string
		csr     func(*testing.T) string
		parsed  bool
		message string
	}{
		{"not PEM", func(*testing.T) string { return "not a certificate request" }, false, "not a PEM CERTIFICATE REQUEST"},
		{"a certificate", func(t *testing.T) string {
			return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}))
		}, false, "not a PEM CERTIFICATE REQUEST"},
		{"a bad signature", tamper, true, "does not verify"},
		{"a weak RSA key", func(t *testing.T) string { return newCSR(t, newRSAKey(t, 1024)) }, true, "1024 bits"},
		{"an Ed25519 key", ed25519CSR, true, "not ECDSA or RSA"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			s := newServer(t, ststest.Opts{})

			_, err := issue(t, s, workloadCreds, tc.csr(t), 0)

			expectAPIError(g, err, "MalformedCertificateSigningRequestException", http.StatusBadRequest)
			g.Expect(err).To(MatchError(ContainSubstring(tc.message)))
			g.Expect(s.Issued()).To(BeEmpty())
			g.Expect(s.Requests()[0].CSR != nil).To(Equal(tc.parsed))
		})
	}
}

func TestServer_TrustBundles_PublishTheOwnDomainDocument(t *testing.T) {
	g := NewWithT(t)
	trustDomain := spiffeid.RequireTrustDomainFromString("corp.example.com")
	providerArn := "arn:aws:iam::444455556666:workload-identity-provider/corp"
	s := ststest.New(t, ststest.Opts{TrustDomain: trustDomain, ProviderArn: providerArn, RefreshHint: 90 * time.Second})
	s.Register(workloadCreds, spiffeid.RequireFromPath(trustDomain, "/workload"))
	jwtKey := newECKey(t, elliptic.P256())
	s.AddJWTAuthority("k1", jwtKey.Public())
	rsaKey := newRSAKey(t, 2048)
	s.AddJWTAuthority("k2", rsaKey.Public())

	entries, err := sts.NewService(s.Config()).GetTrustBundles(testContext(t), workloadCreds, providerArn)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(entries).To(HaveLen(1))
	g.Expect(entries[0].TrustDomain).To(Equal("corp.example.com"))
	document, err := spiffebundle.Parse(trustDomain, []byte(entries[0].Bundle))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(raw(document.X509Authorities())).To(Equal(raw(s.X509Authorities())))
	g.Expect(s.X509Authorities()).To(HaveLen(1))
	authority, found := document.FindJWTAuthority("k1")
	g.Expect(found).To(BeTrue())
	g.Expect(jwtKey.Public().(*ecdsa.PublicKey).Equal(authority)).To(BeTrue())
	authority, found = document.FindJWTAuthority("k2")
	g.Expect(found).To(BeTrue())
	g.Expect(rsaKey.Public().(*rsa.PublicKey).Equal(authority)).To(BeTrue())
	hint, ok := document.RefreshHint()
	g.Expect(ok).To(BeTrue())
	g.Expect(hint).To(Equal(90 * time.Second))
	g.Expect(s.Requests()[0].Form.Get("ProviderArn")).To(Equal(providerArn))
	g.Expect(s.Calls(ststest.ActionGetTrustBundles)).To(Equal(1))
}

func TestServer_TrustBundles_DefaultsAndNoRefreshHint(t *testing.T) {
	g := NewWithT(t)
	s := newServer(t, ststest.Opts{})

	document := fetchBundle(t, s)

	g.Expect(s.ProviderArn()).To(Equal(ststest.DefaultProviderArn))
	g.Expect(s.TrustDomain()).To(Equal(spiffeid.RequireTrustDomainFromString("example.org")))
	g.Expect(document.TrustDomain()).To(Equal(s.TrustDomain()))
	_, ok := document.RefreshHint()
	g.Expect(ok).To(BeFalse())
	g.Expect(document.JWTAuthorities()).To(BeEmpty())
}

func TestServer_RotateCA_PublishesBesideTheOldRootsUntilRetired(t *testing.T) {
	g := NewWithT(t)
	s := newServer(t, ststest.Opts{})
	before := chainOf(t, mustIssue(t, s, newECKey(t, elliptic.P256())))
	oldRoots := s.X509Authorities()

	s.RotateCA()

	roots := s.X509Authorities()
	g.Expect(roots).To(HaveLen(2))
	g.Expect(roots[0].Raw).To(Equal(oldRoots[0].Raw))
	g.Expect(raw(fetchBundle(t, s).X509Authorities())).To(ConsistOf(raw(roots)))
	after := chainOf(t, mustIssue(t, s, newECKey(t, elliptic.P256())))
	g.Expect(after[1].Raw).ToNot(Equal(before[1].Raw), "issued from the new intermediate")

	both := x509bundle.FromX509Authorities(s.TrustDomain(), roots)
	oldOnly := x509bundle.FromX509Authorities(s.TrustDomain(), oldRoots)
	_, _, err := x509svid.Verify(after, both)
	g.Expect(err).ToNot(HaveOccurred())
	_, _, err = x509svid.Verify(before, both)
	g.Expect(err).ToNot(HaveOccurred())
	_, _, err = x509svid.Verify(after, oldOnly)
	g.Expect(err).To(HaveOccurred(), "a verifier with the old bundle doesn't trust the new CA yet")

	s.RetireOldCAs()

	g.Expect(raw(s.X509Authorities())).To(Equal([][]byte{roots[1].Raw}))
	current := fetchBundle(t, s)
	g.Expect(raw(current.X509Authorities())).To(Equal([][]byte{roots[1].Raw}))
	_, _, err = x509svid.Verify(before, current)
	g.Expect(err).To(HaveOccurred(), "the retired root no longer verifies")
	_, _, err = x509svid.Verify(after, current)
	g.Expect(err).ToNot(HaveOccurred())
}

// TestServer_PublishThenPromote_KeepsTheOldCAIssuingUntilPromoted pins the
// two-step rotation: a published root is trusted before anything chains to it,
// and retiring after the promotion keeps only the promoted root.
func TestServer_PublishThenPromote_KeepsTheOldCAIssuingUntilPromoted(t *testing.T) {
	g := NewWithT(t)
	s := newServer(t, ststest.Opts{})
	before := chainOf(t, mustIssue(t, s, newECKey(t, elliptic.P256())))
	oldRoots := s.X509Authorities()

	s.PublishCA()

	roots := s.X509Authorities()
	g.Expect(roots).To(HaveLen(2))
	g.Expect(raw(fetchBundle(t, s).X509Authorities())).To(ConsistOf(raw(roots)))
	published := chainOf(t, mustIssue(t, s, newECKey(t, elliptic.P256())))
	g.Expect(published[1].Raw).To(Equal(before[1].Raw), "the old CA still issues until the new one is promoted")
	_, _, err := x509svid.Verify(published, x509bundle.FromX509Authorities(s.TrustDomain(), oldRoots))
	g.Expect(err).ToNot(HaveOccurred())

	s.PromoteCA()

	promoted := chainOf(t, mustIssue(t, s, newECKey(t, elliptic.P256())))
	g.Expect(promoted[1].Raw).ToNot(Equal(before[1].Raw), "issued from the new intermediate")
	_, _, err = x509svid.Verify(promoted, x509bundle.FromX509Authorities(s.TrustDomain(), roots[1:]))
	g.Expect(err).ToNot(HaveOccurred())

	s.RetireOldCAs()

	g.Expect(raw(s.X509Authorities())).To(Equal([][]byte{roots[1].Raw}))
}

func TestServer_RefusesWhatSTSWould(t *testing.T) {
	tests := []struct {
		name   string
		call   func(*testing.T, *ststest.Server) error
		code   string
		status int
	}{
		{
			name: "an unknown provider",
			call: func(t *testing.T, s *ststest.Server) error {
				_, err := sts.NewService(s.Config()).GetTrustBundles(testContext(t), workloadCreds, "arn:aws:iam::111122223333:workload-identity-provider/other")
				return err
			},
			code:   "ResourceNotFoundException",
			status: http.StatusNotFound,
		},
		{
			name: "an unknown access key, for a certificate",
			call: func(t *testing.T, s *ststest.Server) error {
				creds := workloadCreds
				creds.AccessKeyID = "ASIASTSTESTUNKNOWN01"
				_, err := issue(t, s, creds, newCSR(t, newECKey(t, elliptic.P256())), 0)
				return err
			},
			code:   "InvalidClientTokenId",
			status: http.StatusForbidden,
		},
		{
			name: "an unknown access key, for the bundles",
			call: func(t *testing.T, s *ststest.Server) error {
				creds := workloadCreds
				creds.AccessKeyID = "ASIASTSTESTUNKNOWN01"
				_, err := sts.NewService(s.Config()).GetTrustBundles(testContext(t), creds, s.ProviderArn())
				return err
			},
			code:   "InvalidClientTokenId",
			status: http.StatusForbidden,
		},
		{
			name: "another session's token",
			call: func(t *testing.T, s *ststest.Server) error {
				creds := workloadCreds
				creds.SessionToken = "another-session-token"
				_, err := issue(t, s, creds, newCSR(t, newECKey(t, elliptic.P256())), 0)
				return err
			},
			code:   "InvalidClientTokenId",
			status: http.StatusForbidden,
		},
		{
			name: "a signature with the wrong secret",
			call: func(t *testing.T, s *ststest.Server) error {
				creds := workloadCreds
				creds.SecretAccessKey = "not-the-secret"
				_, err := issue(t, s, creds, newCSR(t, newECKey(t, elliptic.P256())), 0)
				return err
			},
			code:   "SignatureDoesNotMatch",
			status: http.StatusForbidden,
		},
		{
			name: "a signature for another region",
			call: func(t *testing.T, s *ststest.Server) error {
				cfg := s.Config()
				cfg.Region = "eu-west-1"
				_, err := sts.NewService(cfg).GetTrustBundles(testContext(t), workloadCreds, s.ProviderArn())
				return err
			},
			code:   "SignatureDoesNotMatch",
			status: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			s := newServer(t, ststest.Opts{})

			expectAPIError(g, tc.call(t, s), tc.code, tc.status)
			g.Expect(s.Issued()).To(BeEmpty())
			g.Expect(s.Requests()).To(HaveLen(1), "a refused request is still recorded")
		})
	}
}

func TestServer_ExpiredCredentials_AreRefusedWithExpiredToken(t *testing.T) {
	g := NewWithT(t)
	ctx := testContext(t)
	clock := clocktesting.NewFakeClock(time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC))
	s := ststest.New(t, ststest.Opts{Now: clock.Now})
	creds := workloadCreds
	creds.CanExpire = true
	creds.Expires = clock.Now().Add(time.Hour)
	s.Register(creds, workloadID)
	client := sts.NewService(s.Config())

	clock.Step(time.Hour - time.Nanosecond)
	_, err := issue(t, s, creds, newCSR(t, newECKey(t, elliptic.P256())), 0)
	g.Expect(err).ToNot(HaveOccurred())
	_, err = client.GetTrustBundles(ctx, creds, s.ProviderArn())
	g.Expect(err).ToNot(HaveOccurred())

	clock.Step(time.Nanosecond)
	_, err = issue(t, s, creds, newCSR(t, newECKey(t, elliptic.P256())), 0)
	expectAPIError(g, err, "ExpiredToken", http.StatusBadRequest)
	_, err = client.GetTrustBundles(ctx, creds, s.ProviderArn())
	expectAPIError(g, err, "ExpiredToken", http.StatusBadRequest)
	// The signature is checked first, as STS does.
	wrongSecret := creds
	wrongSecret.SecretAccessKey = "not-the-secret"
	_, err = issue(t, s, wrongSecret, newCSR(t, newECKey(t, elliptic.P256())), 0)
	expectAPIError(g, err, "SignatureDoesNotMatch", http.StatusForbidden)
	g.Expect(s.Issued()).To(HaveLen(1))
}

func TestServer_IssuesEachSignerItsOwnIdentity(t *testing.T) {
	g := NewWithT(t)
	s := newServer(t, ststest.Opts{})
	otherID := spiffeid.RequireFromString("spiffe://example.org/ns/other/sa/other-sa")
	otherCreds := aws.Credentials{
		AccessKeyID:     "ASIASTSTESTWORKLOAD2",
		SecretAccessKey: "ststest-other-secret-access-key",
		SessionToken:    "ststest-other-session-token",
	}
	s.Register(otherCreds, otherID)
	roots := x509bundle.FromX509Authorities(s.TrustDomain(), s.X509Authorities())
	signers := []struct {
		creds, other aws.Credentials
		id           spiffeid.ID
	}{
		{workloadCreds, otherCreds, workloadID},
		{otherCreds, workloadCreds, otherID},
	}

	for _, signer := range signers {
		issued, err := issue(t, s, signer.creds, newCSR(t, newECKey(t, elliptic.P256())), 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(issued.Subject).To(Equal(signer.id.String()))
		id, _, err := x509svid.Verify(chainOf(t, issued), roots)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(id).To(Equal(signer.id))

		// This key's ID and session token, signed with the other key's secret.
		crossed := signer.creds
		crossed.SecretAccessKey = signer.other.SecretAccessKey
		_, err = issue(t, s, crossed, newCSR(t, newECKey(t, elliptic.P256())), 0)
		expectAPIError(g, err, "SignatureDoesNotMatch", http.StatusForbidden)
	}

	g.Expect(s.Issued()).To(HaveLen(2))
	var accessKeyIDs []string
	for _, r := range s.Requests() {
		accessKeyIDs = append(accessKeyIDs, r.AccessKeyID)
	}
	g.Expect(accessKeyIDs).To(Equal([]string{
		workloadCreds.AccessKeyID, workloadCreds.AccessKeyID, otherCreds.AccessKeyID, otherCreds.AccessKeyID,
	}))
}

func TestServer_SetError_FailsOneActionUntilCleared(t *testing.T) {
	g := NewWithT(t)
	s := newServer(t, ststest.Opts{})
	s.SetError(ststest.ActionGetWorkloadIdentityCertificate, &ststest.APIError{Status: http.StatusTooManyRequests, Code: "Throttling", Message: "Rate exceeded"})

	_, err := issue(t, s, workloadCreds, newCSR(t, newECKey(t, elliptic.P256())), 0)
	expectAPIError(g, err, "Throttling", http.StatusTooManyRequests)
	g.Expect(err).To(MatchError(ContainSubstring("Rate exceeded")))
	// Before the signature is checked, so any caller gets it.
	unknown := aws.Credentials{AccessKeyID: "ASIASTSTESTUNKNOWN01", SecretAccessKey: "secret"}
	_, err = issue(t, s, unknown, newCSR(t, newECKey(t, elliptic.P256())), 0)
	expectAPIError(g, err, "Throttling", http.StatusTooManyRequests)
	// The other action is untouched.
	fetchBundle(t, s)

	s.SetError(ststest.ActionGetTrustBundles, &ststest.APIError{Status: http.StatusInternalServerError, Code: "InternalFailure"})
	_, err = sts.NewService(s.Config()).GetTrustBundles(testContext(t), workloadCreds, s.ProviderArn())
	expectAPIError(g, err, "InternalFailure", http.StatusInternalServerError)
	var apiErr smithy.APIError
	g.Expect(errors.As(err, &apiErr)).To(BeTrue())
	g.Expect(apiErr.ErrorFault()).To(Equal(smithy.FaultServer))

	s.SetError(ststest.ActionGetWorkloadIdentityCertificate, nil)
	s.SetError(ststest.ActionGetTrustBundles, nil)
	mustIssue(t, s, newECKey(t, elliptic.P256()))
	fetchBundle(t, s)
	g.Expect(s.Issued()).To(HaveLen(1))
	g.Expect(s.Calls(ststest.ActionGetWorkloadIdentityCertificate)).To(Equal(3))
	g.Expect(s.Calls(ststest.ActionGetTrustBundles)).To(Equal(3))
}

func TestServer_AnswersAnUnknownActionWithInvalidAction(t *testing.T) {
	g := NewWithT(t)
	s := newServer(t, ststest.Opts{})

	resp, err := http.PostForm(s.URL(), url.Values{"Action": {"AssumeRole"}, "Version": {"2011-06-15"}})
	g.Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
	g.Expect(string(body)).To(ContainSubstring("<Code>InvalidAction</Code>"))
	g.Expect(s.Requests()[0].Action).To(Equal("AssumeRole"))
}

func TestServer_NewPeer_ChainsToTheCurrentCA(t *testing.T) {
	g := NewWithT(t)
	s := newServer(t, ststest.Opts{MaxLifetime: time.Hour})
	peerID := spiffeid.RequireFromString("spiffe://example.org/ns/other/sa/peer")
	s.RotateCA()

	peer := s.NewPeer(peerID)

	g.Expect(peer.ID).To(Equal(peerID))
	g.Expect(peer.Certificates).To(HaveLen(2))
	id, chains, err := x509svid.Verify(peer.Certificates, x509bundle.FromX509Authorities(s.TrustDomain(), s.X509Authorities()))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(id).To(Equal(peerID))
	g.Expect(chains[0][len(chains[0])-1].Raw).To(Equal(s.X509Authorities()[1].Raw))
	g.Expect(peer.Certificates[0].NotAfter.Sub(peer.Certificates[0].NotBefore)).To(Equal(time.Hour))
	certDER, keyDER, err := peer.MarshalRaw()
	g.Expect(err).ToNot(HaveOccurred())
	_, err = x509svid.ParseRaw(certDER, keyDER)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(s.Issued()).To(BeEmpty())
}

func TestServer_PanicsOnMisuse(t *testing.T) {
	g := NewWithT(t)
	s := newServer(t, ststest.Opts{})
	foreign := spiffeid.RequireFromString("spiffe://other.example/workload")

	g.Expect(func() { s.Register(aws.Credentials{}, workloadID) }).To(Panic())
	g.Expect(func() { s.Register(workloadCreds, foreign) }).To(Panic())
	g.Expect(func() { s.NewPeer(foreign) }).To(Panic())
	g.Expect(func() { s.AddJWTAuthority("k1", newECKey(t, elliptic.P256())) }).To(Panic(), "a private key")
	ed25519Key, _, err := ed25519.GenerateKey(rand.Reader)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(func() { s.AddJWTAuthority("k1", ed25519Key) }).To(Panic(), "a key the bundle tier refuses")
	g.Expect(func() { s.AddJWTAuthority("", newECKey(t, elliptic.P256()).Public()) }).To(Panic())
	g.Expect(func() { s.SetError("AssumeRole", &ststest.APIError{}) }).To(Panic())
}

func TestServer_IsSafeForConcurrentUse(t *testing.T) {
	g := NewWithT(t)
	ctx := testContext(t)
	s := newServer(t, ststest.Opts{})
	const callers, calls = 4, 3
	// Built here, since a helper that fails the test must run on its goroutine.
	csrs := make([]string, callers*calls)
	for i := range csrs {
		csrs[i] = newCSR(t, newECKey(t, elliptic.P256()))
	}

	var wg sync.WaitGroup
	errs := make(chan error, callers*calls*2)
	for caller := range callers {
		wg.Go(func() {
			client := sts.NewService(s.Config())
			for call := range calls {
				_, err := client.GetWorkloadIdentityCertificate(ctx, workloadCreds, sts.CertificateRequest{
					CertificateSigningRequestPEM: csrs[caller*calls+call],
				})
				errs <- err
				_, err = client.GetTrustBundles(ctx, workloadCreds, s.ProviderArn())
				errs <- err
			}
		})
	}
	for i := range calls {
		s.RotateCA()
		s.AddJWTAuthority("k"+strconv.Itoa(i), newECKey(t, elliptic.P256()).Public())
		s.NewPeer(workloadID)
		_ = s.Requests()
		_ = s.Issued()
	}
	s.RetireOldCAs()
	wg.Wait()
	close(errs)

	for err := range errs {
		g.Expect(err).ToNot(HaveOccurred())
	}
	g.Expect(s.Issued()).To(HaveLen(callers * calls))
	g.Expect(s.Calls(ststest.ActionGetTrustBundles)).To(Equal(callers * calls))
}

// TestServer_ServesTheBundleAndX509Tiers runs the real trust bundle and X.509
// tiers over the real client against the fake, the way the agent wires them:
// the bundle tier learns the own trust domain, and a certificate the X.509 tier
// obtained verifies against the bundle the bundle tier serves.
func TestServer_ServesTheBundleAndX509Tiers(t *testing.T) {
	g := NewWithT(t)
	ctx := testContext(t)
	s := newServer(t, ststest.Opts{})
	sessions := &fake.SessionProvider{Result: &workloadidentity.WorkloadSession{
		Credentials: workloadCreds,
		ProviderArn: s.ProviderArn(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}}
	client := sts.NewService(s.Config())
	bundles, err := bundle.New(bundle.Opts{
		Fetcher:   client,
		Notifier:  &fake.Subscriber{},
		Providers: workloadidentity.SessionProviderArns(sessions),
		Signer:    bundle.WorkloadSessionSigner(sessions),
	})
	g.Expect(err).ToNot(HaveOccurred())
	certs, err := x509source.New(x509source.Opts{
		Issuer:          client,
		SessionProvider: sessions,
		Notifier:        &fake.Subscriber{},
		MaxCacheSize:    8,
		CleanupInterval: -1,
	})
	g.Expect(err).ToNot(HaveOccurred())
	pod := &workloadidentity.Workload{PodUID: "pod-uid", PodName: "example", Namespace: "default", ServiceAccount: "example-sa"}

	g.Expect(bundles.OwnTrustDomain(ctx, pod)).To(Equal(s.TrustDomain()))
	x509Bundles, err := bundles.X509Bundles(ctx, pod)
	g.Expect(err).ToNot(HaveOccurred())
	svids, err := certs.X509SVIDs(ctx, pod)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(svids).To(HaveLen(1))
	g.Expect(svids[0].ID).To(Equal(workloadID))
	id, _, err := x509svid.Verify(svids[0].Certificates, x509Bundles)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(id).To(Equal(workloadID))
	g.Expect(s.Calls(ststest.ActionGetTrustBundles)).To(Equal(1))
	g.Expect(s.Calls(ststest.ActionGetWorkloadIdentityCertificate)).To(Equal(1))
}
