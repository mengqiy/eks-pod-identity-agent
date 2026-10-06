package ststest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
)

// AddJWTAuthority publishes key as a jwt-svid authority in the trust domain's
// bundle under keyID, replacing any key already there. It panics on an empty
// keyID or a key that isn't an ECDSA or RSA public key, the types
// internal/material/bundle accepts: a private key would be published with its
// private members, and any other key makes the agent refuse the whole document.
func (s *Server) AddJWTAuthority(keyID string, key crypto.PublicKey) {
	switch key.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
	default:
		panic(fmt.Sprintf("ststest: JWT authority %q is %T, not an ECDSA or RSA public key", keyID, key))
	}
	if keyID == "" {
		panic("ststest: AddJWTAuthority needs a key ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwtAuthorities[keyID] = key
}

// getTrustBundles answers for the fake's provider with one member, the trust
// domain's own document: every published root as an x509-svid key and every
// JWT authority as a jwt-svid key.
func (s *Server) getTrustBundles(requestID string, request Request) (any, *APIError) {
	providerArn := request.Form.Get("ProviderArn")
	if providerArn == "" {
		return nil, validationError("Value null at 'providerArn' failed to satisfy constraint: Member must not be null")
	}
	if providerArn != s.providerArn {
		return nil, &APIError{
			Status:  http.StatusNotFound,
			Code:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Workload identity provider %s does not exist", providerArn),
		}
	}

	document := func() *spiffebundle.Bundle {
		s.mu.Lock()
		defer s.mu.Unlock()
		document := spiffebundle.FromX509Authorities(s.trustDomain, s.rootsLocked())
		document.SetJWTAuthorities(s.jwtAuthorities)
		return document
	}()
	if s.refreshHint > 0 {
		document.SetRefreshHint(s.refreshHint)
	}
	encoded, err := document.Marshal()
	if err != nil {
		return nil, &APIError{Status: http.StatusInternalServerError, Code: "InternalFailure", Message: "ststest: encoding the bundle: " + err.Error()}
	}

	var response getTrustBundlesResponse
	response.Result.Members = []trustBundleMember{{TrustDomain: s.trustDomain.Name(), Bundle: string(encoded)}}
	response.Metadata.RequestID = requestID
	return response, nil
}

type getTrustBundlesResponse struct {
	XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ GetTrustBundlesResponse"`
	Result  struct {
		Members []trustBundleMember `xml:"TrustBundles>member"`
	} `xml:"GetTrustBundlesResult"`
	Metadata responseMetadata `xml:"ResponseMetadata"`
}

type trustBundleMember struct {
	TrustDomain string `xml:"TrustDomain"`
	Bundle      string `xml:"Bundle"`
}
