//go:build integration

// Isolated probe for the sts:GetWorkloadIdentityCertificate integration, the Go
// equivalent of the Java sample in Appendix C.5 of the workload identity
// onboarding guide.
//
// It lives in the package rather than as a separate command so it reuses the real
// pieces instead of reimplementing them: T6's hand-rolled awsQuery client, and
// this package's own unexported generateKey, buildCSR and parseChain. The bytes it
// puts on the wire are the bytes the agent puts on the wire, which is the whole
// point of probing it.
//
// Excluded from the normal suite by the integration build tag, so `go test ./...`
// never reaches for credentials or the network.
//
//	# Offline. Generates the request and prints the CLI command to replay it.
//	go test -tags=integration ./internal/material/x509/ \
//	  -run TestIntegrationPrintRequest -v
//
//	# Live. Needs credentials whose session already carries a workload identity.
//	go test -tags=integration ./internal/material/x509/ \
//	  -run TestIntegrationIssueCertificate -v
//
// Endpoint. The call is not in any released SDK and is unlikely to be live on the
// public endpoint, so point it somewhere with AWS_ENDPOINT_URL_STS. T6's client
// resolves endpoints through the SDK's own STS rules, so that variable, FIPS,
// dual-stack and partitions all behave as the SDK behaves.
//
//	AWS_ENDPOINT_URL_STS=https://prodpreview.sts.us-east-1.amazonaws.com
//
// What a failure means. The call is authorized on the caller's own role and matched
// on aws:OriginIdentity/Subject, so a session carrying no workload identity has no
// subject to mint for and is refused however broad its grant. That refusal is the
// expected first result from an ordinary role, and it still proves the useful part:
// endpoint resolution, SigV4 over the workload's credentials, and error decoding.

package x509

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
)

// integDuration is the lifetime the probe requests. The model accepts 3600 to
// 43200 seconds; override with X509_INTEG_DURATION.
func integDuration(t *testing.T) time.Duration {
	t.Helper()
	if raw := os.Getenv("X509_INTEG_DURATION"); raw != "" {
		d, err := time.ParseDuration(raw)
		require.NoError(t, err, "X509_INTEG_DURATION is not a duration")
		return d
	}
	return 6 * time.Hour
}

// TestIntegrationPrintRequest needs no credentials and no network. It produces the
// exact request the agent would send, writes the key and request to a temporary
// directory, and prints the CLI command to replay it by hand.
//
// Useful on its own: it is how you check what the agent asks for without having a
// decorated session, and the printed command is how you drive the API from a shell
// that does have one.
func TestIntegrationPrintRequest(t *testing.T) {
	key, err := generateKey()
	require.NoError(t, err)
	csr, err := buildCSR(key)
	require.NoError(t, err)

	// Confirm on the way past that the request really is bare, since that is the
	// property the service contract rests on.
	block, _ := pem.Decode([]byte(csr))
	require.NotNil(t, block)
	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, parsed.CheckSignature())
	require.Empty(t, parsed.Subject.String(), "the request carries no subject")
	require.Empty(t, parsed.Extensions, "the request carries no extensions")
	require.Empty(t, parsed.URIs, "the identity comes from the session, not the request")

	dir := t.TempDir()
	csrPath := filepath.Join(dir, "workload.csr")
	require.NoError(t, os.WriteFile(csrPath, []byte(csr), 0o600))

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "workload.key")
	require.NoError(t, os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))

	t.Logf("key algorithm:     %s (%s)", parsed.PublicKeyAlgorithm, keyCurve.Params().Name)
	t.Logf("signature:         %s", parsed.SignatureAlgorithm)
	t.Logf("request written:   %s", csrPath)
	t.Logf("test key written:  %s (throwaway; the temp dir is removed when the test ends)", keyPath)
	t.Logf("\nreplay it with:\n\n"+
		"  aws sts get-workload-identity-certificate \\\n"+
		"    --certificate-signing-request \"$(cat %s)\" \\\n"+
		"    --max-duration-seconds %d\n\n"+
		"adding --endpoint-url if the operation is not on the public endpoint.\n\n%s",
		csrPath, int(integDuration(t).Seconds()), csr)
}

// TestIntegrationIssueCertificate makes one live call and reports everything the
// response says, then checks the round trip the way the tier does.
func TestIntegrationIssueCertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	require.NoError(t, err, "no AWS configuration could be loaded")
	require.NotEmpty(t, cfg.Region, "no region is configured; set AWS_REGION")

	creds, err := cfg.Credentials.Retrieve(ctx)
	require.NoError(t, err, "no credentials could be retrieved")

	// Report who is calling. The identity to be issued for is read off this
	// session, so this is the single most useful thing to see next to a refusal.
	if who, err := awssts.NewFromConfig(cfg).GetCallerIdentity(ctx, &awssts.GetCallerIdentityInput{}); err != nil {
		t.Logf("GetCallerIdentity failed, continuing anyway: %v", err)
	} else {
		t.Logf("calling as:      %s (account %s)", *who.Arn, *who.Account)
	}
	t.Logf("region:          %s", cfg.Region)
	if endpoint := os.Getenv("AWS_ENDPOINT_URL_STS"); endpoint != "" {
		t.Logf("endpoint:        %s", endpoint)
	} else {
		t.Logf("endpoint:        the SDK default for %s (set AWS_ENDPOINT_URL_STS to override)", cfg.Region)
	}

	key, err := generateKey()
	require.NoError(t, err)
	csr, err := buildCSR(key)
	require.NoError(t, err)

	requested := integDuration(t)
	t.Logf("requesting:      %s", requested)

	issued, err := sts.NewService(cfg).GetWorkloadIdentityCertificate(ctx, creds, sts.CertificateRequest{
		CertificateSigningRequestPEM: csr,
		MaxDuration:                  requested,
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			t.Fatalf("the call was refused\n  code:    %s\n  message: %s\n  fault:   %s\n\n%s",
				apiErr.ErrorCode(), apiErr.ErrorMessage(), apiErr.ErrorFault(), interpret(apiErr.ErrorCode()))
		}
		t.Fatalf("the call failed before STS answered: %v", err)
	}

	t.Logf("\n--- response ---")
	t.Logf("Subject:         %q", issued.Subject)
	t.Logf("NotBefore:       %s", issued.NotBefore)
	t.Logf("NotAfter:        %s", issued.NotAfter)

	lifetime := issued.NotAfter.Sub(issued.NotBefore)
	t.Logf("issued lifetime: %s (requested %s)", lifetime, requested)
	if lifetime != requested {
		t.Logf("  note: the requested duration is a ceiling, not a grant, which is why the\n"+
			"        renewal schedule is derived from the window above rather than from %s", requested)
	}
	if backdate := issued.NotBefore.Sub(time.Now().UTC()); backdate < 0 {
		t.Logf("backdated by:    %s", -backdate)
	}

	// Parse it exactly as the tier does.
	chain, err := parseChain(issued.CertificatePEM, issued.CertificateChainPEM)
	require.NoError(t, err, "the issued certificate is not one the agent would serve")

	t.Logf("leaf SPIFFE ID:  %s", chain.spiffeID)
	t.Logf("chain length:    %d (leaf first, root excluded by contract)", len(chain.der))
	for i, der := range chain.der {
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		role := "leaf"
		if i > 0 {
			role = fmt.Sprintf("issuer %d", i)
		}
		t.Logf("  [%d] %-9s subject=%q issuer=%q isCA=%t", i, role, cert.Subject, cert.Issuer, cert.IsCA)
	}

	// The invariants the tier depends on.
	leaf, err := x509.ParseCertificate(chain.der[0])
	require.NoError(t, err)
	require.Equal(t, key.Public(), leaf.PublicKey,
		"the leaf has to certify the key generated here, not another one")
	require.Len(t, leaf.URIs, 1, "an X.509-SVID carries exactly one URI SAN")
	require.NoError(t, checkIdentity(chain.spiffeID, issued.Subject))
	require.True(t, chain.notAfter.After(chain.notBefore))

	// What the renewal schedule would be, so the probe reports the real behaviour
	// rather than only the happy path.
	renewAt := renewalPoint(chain.notBefore, chain.notAfter, 0.5, 0.1, func() float64 { return 0.5 })
	t.Logf("would renew at:  %s (in %s)", renewAt, renewAt.Sub(time.Now().UTC()).Truncate(time.Second))
}

// interpret explains the refusals worth recognising, so a first run does not read
// as a defect in the client.
func interpret(code string) string {
	switch code {
	case "AccessDenied", "AccessDeniedException":
		return "Most likely the session carries no workload identity, so there is no\n" +
			"aws:OriginIdentity/Subject for STS to mint against, and the call is refused\n" +
			"however broad the grant. A plain role cannot get past this; the caller needs a\n" +
			"session minted through IssueWorkloadIdentityContext and AssumeRole. Otherwise\n" +
			"check the role's identity policy allows sts:GetWorkloadIdentityCertificate."
	case "SignerNotConfiguredException":
		return "The session's Provider has no outbound signer for X.509. The identity resolved\n" +
			"and the request was well formed, so the client works; the Provider needs a\n" +
			"certificate signer attached."
	case "RegionalSignerUnavailableException":
		return "A signer exists but its signing material is absent in this Region. Try the\n" +
			"Region the signing certificate authority lives in."
	case "MalformedCertificateSigningRequestException":
		return "STS or the certificate authority rejected the request itself. This one is on\n" +
			"the agent: check the key type against what the authority accepts, which is the\n" +
			"open question keyCurve is a single variable for."
	case "InvalidAction", "InvalidClientTokenId":
		return "The operation is not available on this endpoint. Set AWS_ENDPOINT_URL_STS to\n" +
			"one where it is."
	case "ValidationError", "ValidationException":
		return "The request shape was rejected. MaxDurationSeconds has to be 3600 to 43200;\n" +
			"check X509_INTEG_DURATION."
	default:
		return "No specific interpretation for this code."
	}
}
