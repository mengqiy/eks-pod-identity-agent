package ststest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// signingName is the SigV4 service name every request must be signed for.
const signingName = "sts"

// credentialAccessKeyID reads the access key ID out of a SigV4 Authorization
// header's Credential scope, or returns empty when there is none.
func credentialAccessKeyID(authorization string) string {
	_, credential, found := strings.Cut(authorization, "Credential=")
	if !found {
		return ""
	}
	accessKeyID, _, _ := strings.Cut(credential, "/")
	return accessKeyID
}

// verifySignature recomputes the SigV4 signature the way STS does: it re-signs
// the headers the Authorization header lists with creds, for Region, at the
// request's own X-Amz-Date, and compares. That catches a wrong payload hash,
// scope, secret or session token, but not a skewed signing time.
func verifySignature(r *http.Request, body []byte, creds aws.Credentials) error {
	authorization := r.Header.Get("Authorization")
	_, signedPart, found := strings.Cut(authorization, "SignedHeaders=")
	if !found {
		return errors.New("no SignedHeaders in the Authorization header")
	}
	signedHeaderList, _, _ := strings.Cut(signedPart, ",")
	signedHeaders := strings.Split(signedHeaderList, ";")
	signingTime, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return fmt.Errorf("reading X-Amz-Date: %w", err)
	}

	rebuilt, err := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	rebuilt.Header = http.Header{}
	for _, name := range signedHeaders {
		switch name {
		case "host", "x-amz-date", "x-amz-security-token", "content-length":
			// The signer writes these from the URL, the time, creds and the body.
			continue
		}
		rebuilt.Header.Set(name, r.Header.Get(name))
	}
	if !slices.Contains(signedHeaders, "content-length") {
		rebuilt.ContentLength = 0
	}
	hash := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, rebuilt, hex.EncodeToString(hash[:]), signingName, Region, signingTime); err != nil {
		return err
	}
	if expected := rebuilt.Header.Get("Authorization"); expected != authorization {
		return fmt.Errorf("the request signature does not match the one calculated: got %q, want %q", authorization, expected)
	}
	return nil
}
