// Package ststest is a fake STS endpoint for the workload identity operations
// internal/cloud/sts calls: an httptest server that speaks awsQuery
// GetWorkloadIdentityCertificate and GetTrustBundles well enough for the real
// client, and the tiers built on it, to call it unmodified. It checks each
// request's SigV4 signature against credentials a test registered, issues real
// X.509-SVIDs from a CA a test can rotate, and publishes that CA in a SPIFFE
// bundle document.
//
// Every request is recorded, and every method is safe for concurrent use,
// including while requests are in flight.
package ststest

import (
	"crypto"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	// Region is the region Config sets, and the one every request must be
	// signed for.
	Region = "us-west-2"
	// DefaultProviderArn is the provider GetTrustBundles knows when Opts names
	// none.
	DefaultProviderArn = "arn:aws:iam::111122223333:workload-identity-provider/example"

	// ActionGetWorkloadIdentityCertificate and ActionGetTrustBundles are the
	// awsQuery actions the fake serves, as Request.Action and SetError name
	// them. They're spelled here, not taken from internal/cloud/sts, so a wrong
	// name in the client fails against the fake instead of being copied into it.
	ActionGetWorkloadIdentityCertificate = "GetWorkloadIdentityCertificate"
	ActionGetTrustBundles                = "GetTrustBundles"

	// apiVersion is the STS API version every request must name.
	apiVersion = "2011-06-15"
	// xmlNamespace is the namespace of every STS response document.
	xmlNamespace = "https://sts.amazonaws.com/doc/2011-06-15/"
	// defaultTrustDomain is the trust domain when Opts leaves it zero.
	defaultTrustDomain = "example.org"
	// defaultLifetime is what STS issues for a request with no
	// MaxDurationSeconds, and the default MaxLifetime.
	defaultLifetime = 12 * time.Hour
	// maxRequestBytes bounds how much of a request body is read. A CSR is at
	// most 32 KiB.
	maxRequestBytes = 1 << 20
)

// Opts configures the fake. The zero value is DefaultProviderArn in example.org
// on the wall clock.
type Opts struct {
	// TrustDomain is the provider's own trust domain. Zero means example.org.
	TrustDomain spiffeid.TrustDomain
	// ProviderArn is the one provider GetTrustBundles knows. Empty means
	// DefaultProviderArn.
	ProviderArn string
	// Now is the fake's clock. Issued certificates start at it, truncated to the
	// second, and a new CA is valid from an hour before it. Nil means time.Now.
	Now func() time.Time
	// MaxLifetime caps an issued certificate's lifetime, which is otherwise
	// MaxDurationSeconds or 12 hours. Lifetimes are truncated to whole seconds,
	// as a certificate encodes its validity, so it must be zero, meaning 12
	// hours, or at least a second.
	MaxLifetime time.Duration
	// RefreshHint is the spiffe_refresh_hint of every bundle document, rounded
	// up to the second. Zero leaves it out.
	RefreshHint time.Duration
}

// Server is a fake STS endpoint for one workload identity provider. Build it
// with New. It starts with one CA, no JWT authority and no registered
// credentials, so every request is refused with InvalidClientTokenId until a
// test calls Register.
type Server struct {
	server      *httptest.Server
	trustDomain spiffeid.TrustDomain
	providerArn string
	now         func() time.Time
	maxLifetime time.Duration
	refreshHint time.Duration

	mu sync.Mutex
	// principals holds what Register was given, by access key ID.
	principals map[string]principal
	// authorities holds the published CAs, oldest first, and issuing indexes the
	// one that signs, which a published CA becomes only once promoted.
	authorities []*authority
	issuing     int
	// generation counts the CAs ever made, to name each one.
	generation     int
	jwtAuthorities map[string]crypto.PublicKey
	// apiErrors holds what SetError was given, by action.
	apiErrors map[string]*APIError
	requests  []Request
	issued    []*x509.Certificate
}

// principal is one Register call: the credentials a request must be signed
// with, and the identity STS takes from them.
type principal struct {
	creds aws.Credentials
	id    spiffeid.ID
}

// Request is one request the fake received.
type Request struct {
	// Action is the body's Action member.
	Action string
	// AccessKeyID is the access key in the Authorization header's credential
	// scope, or empty when there is none. It's recorded whether or not the
	// signature verified.
	AccessKeyID string
	// Form is the decoded request body.
	Form url.Values
	// CSR is the parsed CertificateSigningRequest of a
	// GetWorkloadIdentityCertificate request, including one whose signature
	// failed to verify. It's nil for any other request or a CSR that didn't parse.
	CSR *x509.CertificateRequest
}

func (r Request) clone() Request {
	form := make(url.Values, len(r.Form))
	for name, values := range r.Form {
		form[name] = slices.Clone(values)
	}
	r.Form = form
	return r
}

// APIError is an error response in the awsQuery shape STS uses, which the
// client decodes into a smithy.APIError carrying Code and Message.
type APIError struct {
	// Status is the HTTP status. Zero is sent as 400.
	Status int
	// Code is the error code, such as "Throttling". The client reports an empty
	// one as the status text.
	Code    string
	Message string
}

// New starts a fake STS endpoint and closes it when the test ends. It fails t
// on a negative MaxLifetime or RefreshHint, or a MaxLifetime under a second.
func New(t testing.TB, opts Opts) *Server {
	t.Helper()
	if opts.MaxLifetime < 0 || opts.RefreshHint < 0 {
		t.Fatalf("ststest: MaxLifetime %v and RefreshHint %v must not be negative", opts.MaxLifetime, opts.RefreshHint)
	}
	if opts.MaxLifetime > 0 && opts.MaxLifetime < time.Second {
		t.Fatalf("ststest: MaxLifetime %v is under a second, the least a certificate's lifetime can be", opts.MaxLifetime)
	}
	if opts.TrustDomain.IsZero() {
		opts.TrustDomain = spiffeid.RequireTrustDomainFromString(defaultTrustDomain)
	}
	if opts.ProviderArn == "" {
		opts.ProviderArn = DefaultProviderArn
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.MaxLifetime == 0 {
		opts.MaxLifetime = defaultLifetime
	}
	s := &Server{
		trustDomain:    opts.TrustDomain,
		providerArn:    opts.ProviderArn,
		now:            opts.Now,
		maxLifetime:    opts.MaxLifetime.Truncate(time.Second),
		refreshHint:    opts.RefreshHint,
		principals:     map[string]principal{},
		jwtAuthorities: map[string]crypto.PublicKey{},
		apiErrors:      map[string]*APIError{},
	}
	s.RotateCA()
	s.server = httptest.NewServer(http.HandlerFunc(s.serveHTTP))
	t.Cleanup(s.server.Close)
	return s
}

// Config is an AWS configuration pointed at the fake: Region, and BaseEndpoint
// set to URL. It carries no credentials, since the client signs each call with
// the credentials it is given.
func (s *Server) Config() aws.Config {
	return aws.Config{Region: Region, BaseEndpoint: aws.String(s.server.URL)}
}

// URL is the endpoint's base URL.
func (s *Server) URL() string {
	return s.server.URL
}

// TrustDomain is the provider's own trust domain.
func (s *Server) TrustDomain() spiffeid.TrustDomain {
	return s.trustDomain
}

// ProviderArn is the one provider GetTrustBundles knows.
func (s *Server) ProviderArn() string {
	return s.providerArn
}

// Register accepts requests signed with creds, session token included, and
// issues certificates for id to them. Once Now reaches creds.Expires, when
// creds.CanExpire, a correctly signed request gets 400 ExpiredToken.
// Registering an access key again replaces it. It panics on an empty access
// key ID or an id outside the trust domain.
func (s *Server) Register(creds aws.Credentials, id spiffeid.ID) {
	if creds.AccessKeyID == "" {
		panic("ststest: Register needs an access key ID")
	}
	s.mustBeMember(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principals[creds.AccessKeyID] = principal{creds: creds, id: id}
}

// SetError fails every request for action with apiErr, before its signature is
// checked, until it's called again with nil. The value is copied. It panics on
// an action the fake doesn't serve.
func (s *Server) SetError(action string, apiErr *APIError) {
	if action != ActionGetWorkloadIdentityCertificate && action != ActionGetTrustBundles {
		panic(fmt.Sprintf("ststest: SetError for %q, which the fake doesn't serve", action))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if apiErr == nil {
		delete(s.apiErrors, action)
		return
	}
	copied := *apiErr
	s.apiErrors[action] = &copied
}

// Requests returns a copy of every request received so far, in arrival order,
// including refused ones.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	requests := make([]Request, len(s.requests))
	for i, r := range s.requests {
		requests[i] = r.clone()
	}
	return requests
}

// Calls reports how many requests for action have been received, counted as
// Requests counts them.
func (s *Server) Calls(action string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	calls := 0
	for _, r := range s.requests {
		if r.Action == action {
			calls++
		}
	}
	return calls
}

// Issued returns every leaf GetWorkloadIdentityCertificate issued, in order.
// NewPeer's leaves aren't among them.
func (s *Server) Issued() []*x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.issued)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
	form, _ := url.ParseQuery(string(body))
	request := Request{
		Action:      form.Get("Action"),
		AccessKeyID: credentialAccessKeyID(r.Header.Get("Authorization")),
		Form:        form,
	}
	var csrErr error
	if request.Action == ActionGetWorkloadIdentityCertificate {
		request.CSR, csrErr = parseCSR(form.Get("CertificateSigningRequest"))
	}
	requestID, injected := s.record(request)
	w.Header().Set("X-Amzn-RequestId", requestID)

	if (request.Action != ActionGetWorkloadIdentityCertificate && request.Action != ActionGetTrustBundles) ||
		form.Get("Version") != apiVersion {
		writeError(w, requestID, &APIError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidAction",
			Message: fmt.Sprintf("Could not find operation %s for version %s", request.Action, form.Get("Version")),
		})
		return
	}
	if injected != nil {
		writeError(w, requestID, injected)
		return
	}
	id, apiErr := s.authenticate(r, body, request.AccessKeyID)
	if apiErr != nil {
		writeError(w, requestID, apiErr)
		return
	}

	var response any
	if request.Action == ActionGetWorkloadIdentityCertificate {
		response, apiErr = s.getWorkloadIdentityCertificate(requestID, request, csrErr, id)
	} else {
		response, apiErr = s.getTrustBundles(requestID, request)
	}
	if apiErr != nil {
		writeError(w, requestID, apiErr)
		return
	}
	writeXML(w, http.StatusOK, response)
}

// record records request and returns a request ID for its response and the
// error SetError set for its action, if any.
func (s *Server) record(request Request) (string, *APIError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, request)
	return "ststest-" + strconv.Itoa(len(s.requests)), s.apiErrors[request.Action]
}

// authenticate checks the request's signature against the credentials
// registered for its access key, then their expiry against Now, and returns the
// identity registered with them. The signing time isn't compared with Now,
// since the real client signs with the wall clock whatever clock a test uses.
func (s *Server) authenticate(r *http.Request, body []byte, accessKeyID string) (spiffeid.ID, *APIError) {
	if accessKeyID == "" {
		return spiffeid.ID{}, &APIError{Status: http.StatusForbidden, Code: "MissingAuthenticationToken", Message: "Request is missing Authentication Token"}
	}
	registered, ok := func() (principal, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		registered, ok := s.principals[accessKeyID]
		return registered, ok
	}()
	if !ok || r.Header.Get("X-Amz-Security-Token") != registered.creds.SessionToken {
		return spiffeid.ID{}, &APIError{Status: http.StatusForbidden, Code: "InvalidClientTokenId", Message: "The security token included in the request is invalid."}
	}
	if err := verifySignature(r, body, registered.creds); err != nil {
		return spiffeid.ID{}, &APIError{Status: http.StatusForbidden, Code: "SignatureDoesNotMatch", Message: err.Error()}
	}
	if registered.creds.CanExpire && !s.now().Before(registered.creds.Expires) {
		return spiffeid.ID{}, &APIError{Status: http.StatusBadRequest, Code: "ExpiredToken", Message: "The security token included in the request is expired"}
	}
	return registered.id, nil
}

// mustBeMember panics unless id is in the fake's trust domain, which is the only
// one it issues in.
func (s *Server) mustBeMember(id spiffeid.ID) {
	if !id.MemberOf(s.trustDomain) {
		panic(fmt.Sprintf("ststest: %q is not in trust domain %q", id, s.trustDomain))
	}
}

// validationError is the awsQuery answer to a member the model constrains.
func validationError(format string, args ...any) *APIError {
	return &APIError{Status: http.StatusBadRequest, Code: "ValidationError", Message: "1 validation error detected: " + fmt.Sprintf(format, args...)}
}

// The documents below are the awsQuery shapes the client decodes. Each sits in
// the STS namespace, and a success carries its request ID under
// ResponseMetadata.

type responseMetadata struct {
	RequestID string `xml:"RequestId"`
}

type errorResponse struct {
	XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ ErrorResponse"`
	Error   struct {
		Type    string `xml:"Type"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
	RequestID string `xml:"RequestId"`
}

// writeError sends apiErr as an ErrorResponse, a Sender fault below 500 and a
// Receiver fault from it.
func writeError(w http.ResponseWriter, requestID string, apiErr *APIError) {
	status := apiErr.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	var document errorResponse
	document.Error.Type = "Sender"
	if status >= http.StatusInternalServerError {
		document.Error.Type = "Receiver"
	}
	document.Error.Code = apiErr.Code
	document.Error.Message = apiErr.Message
	document.RequestID = requestID
	writeXML(w, status, document)
}

func writeXML(w http.ResponseWriter, status int, document any) {
	body, err := xml.Marshal(document)
	if err != nil {
		// Every document is structs of strings.
		panic(fmt.Sprintf("ststest: encoding a response: %v", err))
	}
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
