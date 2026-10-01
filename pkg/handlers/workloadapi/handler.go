// Package workloadapi serves the SPIFFE Workload API on the workload identity
// socket. It is the launch interface for applications that use a SPIFFE library:
// the library finds the socket through the SPIFFE_ENDPOINT_SOCKET environment
// variable the Pod Identity webhook injects, opens a stream, and expects the
// agent to keep it current.
//
// This package composes the tiers and does not fetch. It attests the caller,
// reads the tiers it was given, translates their domain types onto the wire
// types, and keeps each stream current by re-reading on every notification.
// Conformance to the specification is what makes this work with libraries nobody
// at AWS wrote, so the specified behaviour wins over anything more convenient.
//
// The wire types come from pkg/wireproto rather than from go-spiffe directly.
// That boundary exists so the later replacement of the upstream generated code
// with a pruned proto subset is an edit of one file, and
// TestRestrictedModules_AreImportedOnlyFromWireproto in the repository root
// enforces it. grpc itself is outside the boundary, so the stream types below are
// named directly.
//
// Skeleton. Every method has its final signature. The three streaming RPCs carry
// their real subscription lifecycle and their real send-then-wait loop, because
// that is the part the notification tier's contract is expressed in: what each
// stream subscribes to, that it re-reads its source on every signal rather than
// trusting the signal, and that it releases on any way the stream can end.
// Assembling the responses, mapping errors onto gRPC codes, and the two unary
// RPCs are placeholders that T10 fills in.
package workloadapi

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/wireproto"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Opts are the tiers the handler composes. Every field is required, and each one
// is an interface so the handler's own tests drive it with the fakes in
// pkg/workloadidentity/fake rather than with a cluster.
//
// There is no socket path and no AWS configuration here. This package serves what
// it is given and builds no client.
type Opts struct {
	// Attestor resolves the process behind a connection to a Workload. The
	// handler attests on every RPC rather than trusting anything in the request,
	// since a Workload API request carries no identity.
	Attestor workloadidentity.Attestor
	// Sessions exchanges an attested workload for an AWS session. The session is
	// what names the identity provider for every bundle read, and no node-level
	// provider is available to fall back on.
	Sessions workloadidentity.SessionProvider
	// Certs yields the workload's X.509-SVIDs, minting or renewing as needed.
	Certs workloadidentity.CertSource
	// Tokens yields JWT-SVIDs for the audiences a caller asks for.
	Tokens workloadidentity.TokenSource
	// Bundles yields trust material, which is node-scoped rather than per
	// workload.
	Bundles workloadidentity.BundleSource
	// Subs is how a stream learns its material changed. Each streaming RPC
	// subscribes on open, with the provider ARN from the caller's session, and
	// releases on end.
	//
	// It is one Subscriber for the whole handler, so the subscription metrics of
	// all three Workload API streams share one RPC label. Splitting it into a
	// field per RPC is a wiring change here and nothing more, since the
	// notification tier hands out a per-RPC view; whether the label is worth
	// three fields is a T10 decision.
	Subs workloadidentity.Subscriber
}

// Handler implements the SPIFFE Workload API.
//
// UnimplementedSpiffeWorkloadAPIServer is embedded by value, which the generated
// code requires: the service interface has an unexported method only that struct
// provides, and registration panics on a nil pointer embed. It also supplies the
// two WIT methods, FetchWITSVID and FetchWITBundles, which the agent does not
// serve. They are deliberately not declared below, so that the Unimplemented
// answer comes from the generated code rather than from a hand-written method
// that would have to be kept in step with it.
type Handler struct {
	wireproto.UnimplementedSpiffeWorkloadAPIServer

	opts Opts
}

// New returns a Handler over the given tiers.
func New(opts Opts) *Handler {
	return &Handler{opts: opts}
}

// Register attaches the handler to a gRPC server. It is what the wiring site
// passes as grpcserver.Opts.Register, in place of the stub this replaces.
func (h *Handler) Register(registrar grpc.ServiceRegistrar) {
	wireproto.RegisterWorkloadAPIServer(registrar, h)
}

// FetchX509SVID streams the caller's X.509-SVIDs with the trust bundle of its
// provider, and sends a fresh response whenever either changes.
//
// The response embeds the bundle alongside the SVID. That is not redundant: a
// workload gets its identity and the means to verify peers in one message, so it
// never has to correlate two streams.
//
// One subscription carries both reasons to wake: the pod's own renewals and the
// X.509 rotations of its provider. The stream is deliberately not deduplicated,
// which matches SPIRE and is recorded as an open question in T10: a rotation in
// the provider's authorities re-sends the SVID response even though the
// certificate did not change.
func (h *Handler) FetchX509SVID(_ *wireproto.X509SVIDRequest, stream grpc.ServerStreamingServer[wireproto.X509SVIDResponse]) error {
	ctx := stream.Context()

	caller, session, err := h.caller(ctx)
	if err != nil {
		return err
	}

	signals, release := h.opts.Subs.SubscribeToWorkloadMaterial(ctx, caller, session.ProviderArn)
	defer release()

	// PLACEHOLDER(T10): take BundleSource.Lease(ctx, session.ProviderArn) and
	// defer its release beside this one, so the bundle tier does not evict a
	// provider whose only reader waits on a signal. Lease arrives with T6.

	return serveStream(ctx, signals, func() error {
		response, err := h.buildX509SVIDResponse(ctx, caller, session)
		if err != nil {
			return err
		}
		return stream.Send(response)
	})
}

// FetchX509Bundles streams trust material only, with no SVID, for a caller that
// verifies peers without holding an identity of its own.
//
// Its request carries no fields, so it cannot name a provider: the provider comes
// from the caller's session, which is why this RPC needs a session even though it
// never touches an SVID.
//
// It subscribes through SubscribeToCertBundles, so a renewed SVID, which this
// stream could not act on, never wakes it. Unlike the SVID stream it
// deduplicates, which is also what SPIRE does: a bundle stream that re-sends
// identical authorities tells its client nothing.
func (h *Handler) FetchX509Bundles(_ *wireproto.X509BundlesRequest, stream grpc.ServerStreamingServer[wireproto.X509BundlesResponse]) error {
	ctx := stream.Context()

	caller, session, err := h.caller(ctx)
	if err != nil {
		return err
	}

	signals, release := h.opts.Subs.SubscribeToCertBundles(ctx, session.ProviderArn)
	defer release()

	// PLACEHOLDER(T10): take the bundle lease, as in FetchX509SVID.

	var last *wireproto.X509BundlesResponse
	return serveStream(ctx, signals, func() error {
		response, err := h.buildX509BundlesResponse(ctx, caller, session)
		if err != nil {
			return err
		}
		if proto.Equal(response, last) {
			return nil
		}
		if err := stream.Send(response); err != nil {
			return err
		}
		last = response
		return nil
	})
}

// FetchJWTSVID returns one JWT-SVID per requested audience. It is unary, takes no
// bundle lease, and subscribes to nothing.
//
// PLACEHOLDER(T10): attest, then read TokenSource for the requested audiences.
func (h *Handler) FetchJWTSVID(_ context.Context, _ *wireproto.JWTSVIDRequest) (*wireproto.JWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "FetchJWTSVID is not implemented yet")
}

// FetchJWTBundles streams the JWT authorities as JWK Set documents keyed by trust
// domain. Like FetchX509Bundles its request carries no fields.
//
// It is the only stream subscribing through SubscribeToJWTBundles, and the only
// one a JWT key roll reaches. That separation is why a signing key rotating does
// not wake every SVID stream on the node for a change none of them can observe.
// It deduplicates as FetchX509Bundles does.
func (h *Handler) FetchJWTBundles(_ *wireproto.JWTBundlesRequest, stream grpc.ServerStreamingServer[wireproto.JWTBundlesResponse]) error {
	ctx := stream.Context()

	caller, session, err := h.caller(ctx)
	if err != nil {
		return err
	}

	signals, release := h.opts.Subs.SubscribeToJWTBundles(ctx, session.ProviderArn)
	defer release()

	// PLACEHOLDER(T10): take the bundle lease, as in FetchX509SVID.

	var last *wireproto.JWTBundlesResponse
	return serveStream(ctx, signals, func() error {
		response, err := h.buildJWTBundlesResponse(ctx, caller, session)
		if err != nil {
			return err
		}
		if proto.Equal(response, last) {
			return nil
		}
		if err := stream.Send(response); err != nil {
			return err
		}
		last = response
		return nil
	})
}

// ValidateJWTSVID verifies a token the caller presents and returns its SPIFFE ID
// and claims. It validates someone else's token, so it needs the bundle and not
// the caller's own credential, and it does not require the caller to hold an
// SVID.
//
// PLACEHOLDER(T10): read the JWT bundles first, then validate with go-spiffe's
// jwtsvid.ParseAndValidate. Reading first is what keeps a bundle outage reported
// as Unavailable rather than as a rejected token.
func (h *Handler) ValidateJWTSVID(_ context.Context, _ *wireproto.ValidateJWTSVIDRequest) (*wireproto.ValidateJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ValidateJWTSVID is not implemented yet")
}

// serveStream is the wait-then-send loop every streaming RPC runs. It is one
// function rather than three copies because the delivery contract is the same on
// all of them and only sendCurrent differs.
//
// There is no special case for the initial response. The notification tier hands
// back a channel with one signal already pending, so the first pass through the
// loop is the initial send and every pass after it is a change. A library opening
// the stream therefore gets its material at once rather than waiting for the first
// rotation.
//
// Each pass sends the state it reads now. It never acts on anything the signal
// carried, because the signal carries nothing: that is what stops a slow stream
// from being handed a credential a newer one has already superseded. A subscriber
// that misses several signals finds one pending and reads the newest state
// through it.
//
// sendCurrent owns the decision to send at all, which is where deduplication
// belongs: only the handler knows what it last put on this stream.
//
// The loop ends when the client goes away or the server is shutting down, both of
// which arrive as a done stream context. Returning the context's own status code
// rather than a bare error is what keeps a client disconnect reported as
// Canceled instead of Unknown.
func serveStream(ctx context.Context, signals <-chan struct{}, sendCurrent func() error) error {
	for {
		select {
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case <-signals:
		}

		if err := sendCurrent(); err != nil {
			return err
		}
	}
}

// caller attests the process on the other end of the stream and reads its AWS
// session, which is what names the identity provider for every bundle read.
//
// The connection comes from the transport credentials the server is built with,
// and it is the only route to it. A caller that cannot be identified is refused
// rather than served anything.
func (h *Handler) caller(ctx context.Context) (*workloadidentity.Workload, *workloadidentity.WorkloadSession, error) {
	conn, ok := grpcserver.ConnFromContext(ctx)
	if !ok {
		// The server was built without the conn-carrying credentials, so no
		// caller on this socket can be attested. It is a wiring bug rather than
		// anything this caller did, and refusing is still the only safe answer.
		return nil, nil, status.Error(codes.PermissionDenied, "the caller's connection is not available, so it cannot be attested")
	}

	caller, err := h.opts.Attestor.Attest(ctx, conn)
	if err != nil {
		return nil, nil, statusError(err)
	}

	session, err := h.opts.Sessions.Session(ctx, caller)
	if err != nil {
		return nil, nil, statusError(err)
	}

	return caller, session, nil
}

// statusError maps a tier error onto a gRPC status.
//
// PLACEHOLDER(T10): the real mapping is total over the pkg/errors taxonomy.
// Everything is Internal for now, which is wrong for most of it.
func statusError(err error) error {
	return status.Error(codes.Internal, err.Error())
}

// buildX509SVIDResponse assembles the current X.509-SVID response for the caller.
//
// PLACEHOLDER(T10): read CertSource and BundleSource, translate onto the wire
// types.
func (h *Handler) buildX509SVIDResponse(_ context.Context, _ *workloadidentity.Workload, _ *workloadidentity.WorkloadSession) (*wireproto.X509SVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "building an X509SVIDResponse is not implemented yet")
}

// buildX509BundlesResponse assembles the current X.509 trust bundle response.
//
// PLACEHOLDER(T10): read BundleSource.X509Bundles for the session's provider.
func (h *Handler) buildX509BundlesResponse(_ context.Context, _ *workloadidentity.Workload, _ *workloadidentity.WorkloadSession) (*wireproto.X509BundlesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "building an X509BundlesResponse is not implemented yet")
}

// buildJWTBundlesResponse assembles the current JWT trust bundle response.
//
// PLACEHOLDER(T10): read BundleSource.JWTBundles for the session's provider.
func (h *Handler) buildJWTBundlesResponse(_ context.Context, _ *workloadidentity.Workload, _ *workloadidentity.WorkloadSession) (*wireproto.JWTBundlesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "building a JWTBundlesResponse is not implemented yet")
}

var _ wireproto.SpiffeWorkloadAPIServer = (*Handler)(nil)
