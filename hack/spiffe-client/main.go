// spiffe-client talks to the agent's Workload API with go-spiffe, as a workload
// would, for trying the agent by hand. It fetches and verifies an X.509-SVID,
// prints the trust bundles, and can validate a JWT-SVID or watch for updates.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func main() {
	socket := flag.String("socket", envOr("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/wi-local/agent.sock"), "Workload API socket address")
	timeout := flag.Duration("timeout", 10*time.Second, "deadline for each one-shot call")
	validate := flag.String("validate", "", "file holding a JWT-SVID to check with ValidateJWTSVID")
	audience := flag.String("audience", "spiffe://example.org/demo", "audience for -validate and -jwt")
	fetchJWT := flag.Bool("jwt", false, "fetch a JWT-SVID for -audience")
	watch := flag.Bool("watch", false, "keep the X.509 stream open and print every update")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(*socket))
	if err != nil {
		fail("connecting to %s: %v", *socket, err)
	}
	defer client.Close()

	call := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, *timeout) }

	callCtx, cancel := call()
	x509Ctx, err := client.FetchX509Context(callCtx)
	cancel()
	if err != nil {
		fail("FetchX509Context: %v", err)
	}
	printX509Context(x509Ctx)

	callCtx, cancel = call()
	jwtBundles, err := client.FetchJWTBundles(callCtx)
	cancel()
	if err != nil {
		fmt.Printf("FetchJWTBundles: %v\n", err)
	} else {
		printJWTBundles(jwtBundles)
	}

	if *validate != "" {
		token, err := os.ReadFile(*validate)
		if err != nil {
			fail("reading %s: %v", *validate, err)
		}
		callCtx, cancel = call()
		svid, err := client.ValidateJWTSVID(callCtx, strings.TrimSpace(string(token)), *audience)
		cancel()
		if err != nil {
			fmt.Printf("ValidateJWTSVID: %v\n", err)
		} else {
			fmt.Printf("ValidateJWTSVID: valid, subject %s, audience %v, expires %s\n",
				svid.ID, svid.Audience, svid.Expiry.Format(time.RFC3339))
		}
	}

	if *fetchJWT {
		callCtx, cancel = call()
		svid, err := client.FetchJWTSVID(callCtx, jwtsvid.Params{Audience: *audience})
		cancel()
		if err != nil {
			fmt.Printf("FetchJWTSVID: %v\n", err)
		} else {
			fmt.Printf("FetchJWTSVID: %s for %v, expires %s\n", svid.ID, svid.Audience, svid.Expiry.Format(time.RFC3339))
		}
	}

	if *watch {
		fmt.Println("\nWatching the X.509 stream; Ctrl-C to stop.")
		err := client.WatchX509Context(ctx, watcher{})
		if err != nil && !cancelled(err) {
			fail("WatchX509Context: %v", err)
		}
	}
}

// printX509Context prints each SVID, checks its chain against the bundle served
// in the same response, and lists the bundles.
func printX509Context(x509Ctx *workloadapi.X509Context) {
	for _, svid := range x509Ctx.SVIDs {
		leaf := svid.Certificates[0]
		fmt.Printf("X.509-SVID %s\n  serial %s, valid %s to %s, chain of %d, key %T\n",
			svid.ID, leaf.SerialNumber, leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339),
			len(svid.Certificates), svid.PrivateKey.Public())
		if _, _, err := x509svid.Verify(svid.Certificates, x509Ctx.Bundles); err != nil {
			fmt.Printf("  does NOT verify against the served bundle: %v\n", err)
		} else {
			fmt.Println("  verifies against the bundle served with it")
		}
	}
	printX509Bundles(x509Ctx.Bundles)
}

func printX509Bundles(set *x509bundle.Set) {
	for _, bundle := range set.Bundles() {
		fmt.Printf("X.509 bundle %s: %d authorities\n", bundle.TrustDomain().IDString(), len(bundle.X509Authorities()))
		for _, ca := range bundle.X509Authorities() {
			fmt.Printf("  %s (serial %s)\n", ca.Subject.CommonName, ca.SerialNumber)
		}
	}
}

func printJWTBundles(set *jwtbundle.Set) {
	for _, bundle := range set.Bundles() {
		var keyIDs []string
		for keyID := range bundle.JWTAuthorities() {
			keyIDs = append(keyIDs, keyID)
		}
		sort.Strings(keyIDs)
		fmt.Printf("JWT bundle %s: key IDs %v\n", bundle.TrustDomain().IDString(), keyIDs)
	}
}

// watcher prints every update the open X.509 stream delivers.
type watcher struct{}

func (watcher) OnX509ContextUpdate(x509Ctx *workloadapi.X509Context) {
	fmt.Printf("\n[%s] update\n", time.Now().Format(time.TimeOnly))
	printX509Context(x509Ctx)
}

func (watcher) OnX509ContextWatchError(err error) {
	if !cancelled(err) {
		fmt.Printf("[%s] watch error: %v\n", time.Now().Format(time.TimeOnly), err)
	}
}

// cancelled reports whether err is this client stopping, as a context error or the
// Canceled status gRPC turns it into.
func cancelled(err error) bool {
	return errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
