package grpcserver

import (
	"context"
	"errors"
	"net"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// authType is the label AuthInfo.AuthType reports. Nothing negotiates it and
// nothing matches on it; gRPC only prints it, in peer.Peer and in channelz.
const authType = "eks-workload-identity-uds"

// errClientHandshake is what ClientHandshake returns. These credentials are
// server-side only, so a client reaching them is a wiring bug rather than a
// fallback.
var errClientHandshake = errors.New("grpcserver: connection credentials are server-side only")

// AuthInfo carries the accepted connection from the transport handshake to the
// handler. It is the seam between this package and attestation: this package puts
// the conn in, attestation takes it out and asks the kernel who is on the other
// end.
//
// Conn is typed net.Conn rather than *net.UnixConn to match
// workloadidentity.Attestor, which takes a net.Conn so a fake can ignore it and does
// the assertion itself. Attestation is what reads the kernel's answer off this
// connection; this package only carries it.
type AuthInfo struct {
	credentials.CommonAuthInfo
	// Conn is the connection the RPC arrived on.
	Conn net.Conn
}

// AuthType implements credentials.AuthInfo.
//
// The value receiver matters to callers. ServerHandshake returns an AuthInfo
// value, so a consumer asserts peer.AuthInfo.(AuthInfo); the pointer form
// compiles and fails at runtime on every RPC, with nothing to catch it at build
// time. Do not change what ServerHandshake returns without changing every
// assertion.
func (AuthInfo) AuthType() string { return authType }

// connCredentials is a credentials.TransportCredentials that performs no
// cryptography whatsoever. It exists only to carry the caller's net.Conn across a
// seam that otherwise drops it, and it must not be read as a promise of transport
// security.
//
// The problem it solves: attestation needs the connection, because SO_PEERCRED on
// the accepted socket is the only statement of who is calling that the caller
// cannot forge. gRPC hands a handler a context, not a connection. gRPC does put
// the raw conn into that context, but under a key in
// google.golang.org/grpc/internal/transport, which Go's internal-package rule
// makes unreachable from here. The one supported route is a TransportCredentials
// whose ServerHandshake returns an AuthInfo holding the conn: gRPC copies that
// AuthInfo onto the peer, and a handler reads it back with peer.FromContext.
//
// So ServerHandshake exchanges no bytes, verifies nothing, and returns the conn it
// was given unchanged. What protects the socket is its file mode and, above all,
// attestation. Do not delete this type as dead code: without it a handler has no
// caller.
//
// Where this sits next to SPIRE is worth being exact about, because the two shapes
// upstream ships look alike and mean opposite things. pkg/common/auth/untracked_uds.go
// is a credential that carries nothing, documented as not for use where caller
// information feeds an authorization decision, and SPIRE mounts it only on its admin
// socket where file permissions are the whole control. Everything that attests a
// caller goes through pkg/common/peertracker instead, whose listener reads peer
// credentials at accept time and whose ServerHandshake refuses any connection that
// did not come through that listener.
//
// This type is the middle of those two: it carries the connection so the caller can
// be attested, and it does not itself resolve or refuse anything. The refusal lives
// in the handler, which has to call Attest and act on its error. If attestation later
// wants SPIRE's stricter shape, where a connection that did not come through a
// credential-reading listener is refused at the transport instead, this is the file
// that changes.
type connCredentials struct{}

var _ credentials.TransportCredentials = connCredentials{}

// NewConnCredentials returns transport credentials that record each accepted
// connection in an AuthInfo, reachable from a handler through ConnFromContext.
// Pass the result to grpc.Creds.
func NewConnCredentials() credentials.TransportCredentials { return connCredentials{} }

// ServerHandshake records conn in an AuthInfo and returns conn unchanged.
func (connCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, AuthInfo{
		// A Unix socket never leaves the kernel, so it has both privacy and
		// integrity without any cryptography, and gRPC's own local credentials
		// report the same level for a Unix connection for that reason. Nothing on
		// the server path reads this field; it is documentation, and claiming
		// NoSecurity would contradict upstream.
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		Conn:           conn,
	}, nil
}

// ClientHandshake always fails. These credentials capture an accepted connection
// on the server; there is no client half.
func (connCredentials) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	_ = conn.Close()
	return nil, nil, errClientHandshake
}

// Info reports the protocol label gRPC surfaces through channelz. The remaining
// ProtocolInfo fields are TLS-specific or deprecated and stay empty.
func (connCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: authType}
}

// Clone returns the receiver. The type is an empty struct with no configuration
// to copy.
func (c connCredentials) Clone() credentials.TransportCredentials { return c }

// OverrideServerName is a no-op. gRPC documents the method as deprecated, and a
// Unix socket has no server name to override.
func (connCredentials) OverrideServerName(string) error { return nil }

// AuthInfoFromContext returns the AuthInfo gRPC recorded for the connection this
// RPC arrived on.
//
// It reports false when the server was built without NewConnCredentials, which is
// the only way the AuthInfo can be missing: gRPC attaches a peer to every
// server-side RPC context, and it permits a nil AuthInfo, which a type assertion
// reports false for without a separate nil check.
//
// This is the accessor attestation extends. A handler wants ConnFromContext.
func AuthInfoFromContext(ctx context.Context) (AuthInfo, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return AuthInfo{}, false
	}
	info, ok := p.AuthInfo.(AuthInfo)
	return info, ok
}

// ConnFromContext returns the connection this RPC arrived on.
//
// It works the same in a unary handler, in a stream handler through
// grpc.ServerStream.Context, and in either interceptor kind, because gRPC derives
// every stream context from the one connection context that holds the peer.
//
// A caller that gets false cannot identify who is calling and has to refuse.
func ConnFromContext(ctx context.Context) (net.Conn, bool) {
	info, ok := AuthInfoFromContext(ctx)
	if !ok || info.Conn == nil {
		return nil, false
	}
	return info.Conn, true
}
