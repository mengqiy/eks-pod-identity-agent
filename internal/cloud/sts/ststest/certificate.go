package ststest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	// minDurationSeconds and maxDurationSeconds are the range the API model
	// gives MaxDurationSeconds.
	minDurationSeconds = 3600
	maxDurationSeconds = 43200
	// caBackdate and caLifetime are a new CA's validity around Now: backdated
	// so a verifier a little behind still accepts it, and long enough that no
	// test outlives it.
	caBackdate = time.Hour
	caLifetime = 10 * 365 * 24 * time.Hour
	// minRSABits is the weakest RSA key the fake signs for.
	minRSABits = 2048
)

// authority is one CA: a self-signed root, which is published, and the
// intermediate it signed, which signs leaves and is sent as the chain.
type authority struct {
	root            *x509.Certificate
	intermediate    *x509.Certificate
	intermediateKey crypto.Signer
}

// newAuthority makes the generation'th CA for trustDomain, valid around now.
// Each generation has its own subject, so a verifier never mistakes one
// generation's intermediate for another's.
func newAuthority(trustDomain spiffeid.TrustDomain, now time.Time, generation int) *authority {
	rootKey := mustGenerateKey()
	rootTemplate := caTemplate(trustDomain, now, fmt.Sprintf("ststest root CA %d", generation))
	root := mustCreateCertificate(rootTemplate, rootTemplate, rootKey.Public(), rootKey)

	intermediateKey := mustGenerateKey()
	intermediateTemplate := caTemplate(trustDomain, now, fmt.Sprintf("ststest intermediate CA %d", generation))
	intermediateTemplate.MaxPathLenZero = true
	intermediate := mustCreateCertificate(intermediateTemplate, root, intermediateKey.Public(), rootKey)
	return &authority{root: root, intermediate: intermediate, intermediateKey: intermediateKey}
}

// caTemplate is a CA certificate carrying the trust domain's SPIFFE ID, which
// the X509-SVID specification allows a signing certificate.
func caTemplate(trustDomain spiffeid.TrustDomain, now time.Time, commonName string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{Organization: []string{"ststest"}, CommonName: commonName},
		URIs:                  []*url.URL{trustDomain.ID().URL()},
		NotBefore:             now.Add(-caBackdate),
		NotAfter:              now.Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

// issueLeaf signs an X509-SVID for id over pub with ca's intermediate, valid
// from notBefore for lifetime. Its subject is empty, so the URI SAN is critical.
func issueLeaf(ca *authority, id spiffeid.ID, pub crypto.PublicKey, notBefore time.Time, lifetime time.Duration) (*x509.Certificate, error) {
	usage := x509.KeyUsageDigitalSignature
	switch pub.(type) {
	case *rsa.PublicKey:
		usage |= x509.KeyUsageKeyEncipherment
	case *ecdsa.PublicKey:
		usage |= x509.KeyUsageKeyAgreement
	}
	template := &x509.Certificate{
		SerialNumber:          newSerial(),
		URIs:                  []*url.URL{id.URL()},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(lifetime),
		KeyUsage:              usage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.intermediate, pub, ca.intermediateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// PublishCA makes a new CA and publishes its root beside the roots already
// published, while the current CA keeps issuing: the first half of a
// publish-then-promote rotation, the window a verifier must already trust both in.
func (s *Server) PublishCA() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generation++
	s.authorities = append(s.authorities, newAuthority(s.trustDomain, s.now(), s.generation))
}

// PromoteCA makes the newest published CA the one that issues.
func (s *Server) PromoteCA() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issuing = len(s.authorities) - 1
}

// RotateCA publishes a new CA and promotes it at once, so a verifier holding a
// bundle fetched before RotateCA rejects a certificate issued after it until it
// fetches again.
func (s *Server) RotateCA() {
	s.PublishCA()
	s.PromoteCA()
}

// RetireOldCAs stops publishing every root older than the issuing one, keeping
// any published since.
func (s *Server) RetireOldCAs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorities = s.authorities[s.issuing:]
	s.issuing = 0
}

// X509Authorities returns the roots the trust domain's bundle publishes now,
// oldest first.
func (s *Server) X509Authorities() []*x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rootsLocked()
}

// NewPeer issues an X509-SVID for id from the current CA, as STS would for a
// workload the agent doesn't serve, with a new P-256 key and the fake's default
// lifetime. Its chain holds the leaf and the intermediate. It isn't recorded in
// Issued. It panics on an id outside the trust domain.
func (s *Server) NewPeer(id spiffeid.ID) *x509svid.SVID {
	s.mustBeMember(id)
	key := mustGenerateKey()
	ca := func() *authority {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.currentLocked()
	}()
	leaf, err := issueLeaf(ca, id, key.Public(), s.now().UTC().Truncate(time.Second), min(defaultLifetime, s.maxLifetime))
	if err != nil {
		panic(fmt.Sprintf("ststest: issuing a peer certificate: %v", err))
	}
	return &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{leaf, ca.intermediate}, PrivateKey: key}
}

// currentLocked is the CA that issues. The caller must hold s.mu.
func (s *Server) currentLocked() *authority {
	return s.authorities[s.issuing]
}

// rootsLocked returns the published roots. The caller must hold s.mu.
func (s *Server) rootsLocked() []*x509.Certificate {
	roots := make([]*x509.Certificate, len(s.authorities))
	for i, ca := range s.authorities {
		roots[i] = ca.root
	}
	return roots
}

// getWorkloadIdentityCertificate issues a leaf for id over the request's CSR.
// The members the model constrains are checked first, as STS validates a
// request before acting on it.
func (s *Server) getWorkloadIdentityCertificate(requestID string, request Request, csrErr error, id spiffeid.ID) (any, *APIError) {
	if request.Form.Get("CertificateSigningRequest") == "" {
		return nil, validationError("Value null at 'certificateSigningRequest' failed to satisfy constraint: Member must not be null")
	}
	lifetime := defaultLifetime
	if raw := request.Form.Get("MaxDurationSeconds"); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds < minDurationSeconds || seconds > maxDurationSeconds {
			return nil, validationError("Value '%s' at 'maxDurationSeconds' failed to satisfy constraint: Member must have value between %d and %d",
				raw, minDurationSeconds, maxDurationSeconds)
		}
		lifetime = time.Duration(seconds) * time.Second
	}
	if csrErr != nil {
		return nil, &APIError{Status: http.StatusBadRequest, Code: "MalformedCertificateSigningRequestException", Message: csrErr.Error()}
	}

	ca := func() *authority {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.currentLocked()
	}()
	leaf, err := issueLeaf(ca, id, request.CSR.PublicKey, s.now().UTC().Truncate(time.Second), min(lifetime, s.maxLifetime))
	if err != nil {
		return nil, &APIError{Status: http.StatusInternalServerError, Code: "InternalFailure", Message: "ststest: issuing the certificate: " + err.Error()}
	}
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.issued = append(s.issued, leaf)
	}()

	var response getWorkloadIdentityCertificateResponse
	response.Result.Certificate = encodeCertificate(leaf)
	response.Result.CertificateChain = encodeCertificate(ca.intermediate)
	response.Result.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	response.Result.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	response.Result.Subject = id.String()
	response.Metadata.RequestID = requestID
	return response, nil
}

// parseCSR parses a PEM certificate request and checks it as STS does: its
// signature proves possession of the key, and the key is one the agent can
// generate, at that strength or above. A CSR that parsed is returned with any
// error, so the request records it.
func parseCSR(text string) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("the certificate signing request is not a PEM CERTIFICATE REQUEST block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("the certificate signing request has data after its PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing the certificate signing request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return csr, fmt.Errorf("the certificate signing request's signature does not verify: %w", err)
	}
	switch key := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() && key.Curve != elliptic.P384() && key.Curve != elliptic.P521() {
			return csr, fmt.Errorf("the certificate signing request's key is on %s, not P-256, P-384 or P-521", key.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		if key.N.BitLen() < minRSABits {
			return csr, fmt.Errorf("the certificate signing request's RSA key has %d bits, fewer than %d", key.N.BitLen(), minRSABits)
		}
	default:
		return csr, fmt.Errorf("the certificate signing request's key is %T, not ECDSA or RSA", key)
	}
	return csr, nil
}

func encodeCertificate(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// mustGenerateKey makes a P-256 key, which the fake uses for every key it
// holds. crypto/rand doesn't fail on a supported platform.
func mustGenerateKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("ststest: generating a key: %v", err))
	}
	return key
}

// mustCreateCertificate signs template, whose fields the fake chooses, so a
// failure is a bug in the fake.
func mustCreateCertificate(template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		panic(fmt.Sprintf("ststest: creating %q: %v", template.Subject.CommonName, err))
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(fmt.Sprintf("ststest: parsing %q: %v", template.Subject.CommonName, err))
	}
	return cert
}

// newSerial is a random 128-bit serial number.
func newSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(fmt.Sprintf("ststest: generating a serial number: %v", err))
	}
	return serial
}

type getWorkloadIdentityCertificateResponse struct {
	XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ GetWorkloadIdentityCertificateResponse"`
	Result  struct {
		Certificate      string `xml:"Certificate"`
		CertificateChain string `xml:"CertificateChain"`
		NotBefore        string `xml:"NotBefore"`
		NotAfter         string `xml:"NotAfter"`
		Subject          string `xml:"Subject"`
	} `xml:"GetWorkloadIdentityCertificateResult"`
	Metadata responseMetadata `xml:"ResponseMetadata"`
}
