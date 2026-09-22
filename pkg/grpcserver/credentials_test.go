package grpcserver

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// TestConnFromContext_ReachesTheHandler is the seam attestation is built on:
// without the caller's connection there is nothing to attest, because SO_PEERCRED
// on that connection is the only statement of who is calling that the caller cannot
// forge.
//
// It covers a unary and a streaming method, because a stream reaches the same
// accessor through grpc.ServerStream.Context rather than through a handler argument
// and nothing but a test proves the two agree.
func TestConnFromContext_ReachesTheHandler(t *testing.T) {
	g := NewWithT(t)

	conns := make(chan net.Conn, 2)
	report := func(ctx context.Context) error {
		conn, ok := ConnFromContext(ctx)
		if !ok {
			return status.Error(codes.Internal, "handler could not reach the caller's connection")
		}
		conns <- conn
		return nil
	}
	stub := &stubService{
		unary:  report,
		stream: func(ss grpc.ServerStream) error { return report(ss.Context()) },
	}

	path := tempSocketPath(t)
	srv := newStubServer(t, stub, Opts{SocketPath: path})
	serve(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dial(t, path)
	g.Eventually(func() error { return callUnary(withHeader(ctx), conn) }).WithContext(ctx).Should(Succeed())
	_, err := openStream(withHeader(ctx), conn)
	g.Expect(err).ToNot(HaveOccurred())

	for _, kind := range []string{"unary", "stream"} {
		var handlerConn net.Conn
		g.Eventually(conns, 10*time.Second).Should(Receive(&handlerConn), "no connection reported by the %s method", kind)

		// The agent's own end is the socket it bound. The caller's end is the
		// autobind address "@" for an unnamed client socket, which is also what the
		// client's own LocalAddr reports, so a comparison of the two strings would
		// pass for any pair of unrelated connections and proves nothing.
		g.Expect(handlerConn.LocalAddr().String()).To(Equal(path))
		g.Expect(handlerConn.RemoteAddr().Network()).To(Equal("unix"))

		// What does prove it is asking the kernel, which is the same read
		// attestation performs. The client is this process.
		unixConn, ok := handlerConn.(*net.UnixConn)
		g.Expect(ok).To(BeTrue(), "the connection has to be a *net.UnixConn, got %T", handlerConn)
		raw, err := unixConn.SyscallConn()
		g.Expect(err).ToNot(HaveOccurred())
		var ucred *unix.Ucred
		var credErr error
		g.Expect(raw.Control(func(fd uintptr) {
			ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		})).To(Succeed())
		g.Expect(credErr).ToNot(HaveOccurred())
		g.Expect(ucred.Pid).To(Equal(int32(os.Getpid())))
	}
}

// TestConnFromContext_WithoutTheCredentials pins the other half of the seam. gRPC
// permits a nil AuthInfo and serves the RPC anyway, so a server built without these
// credentials has no caller information and nothing else would notice: the
// accessors report false rather than panicking, and it is the handler's job to
// refuse.
func TestConnFromContext_WithoutTheCredentials(t *testing.T) {
	g := NewWithT(t)

	_, present := ConnFromContext(context.Background())
	g.Expect(present).To(BeFalse())

	_, present = AuthInfoFromContext(context.Background())
	g.Expect(present).To(BeFalse())
}

// TestAuthInfo_IsAssertedByValue guards the shape of the assertion every consumer
// makes. ServerHandshake returns an AuthInfo value, so asserting the pointer type
// compiles and fails on every RPC with nothing to catch it at build time.
func TestAuthInfo_IsAssertedByValue(t *testing.T) {
	g := NewWithT(t)

	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()

	returned, info, err := NewConnCredentials().ServerHandshake(left)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(returned).To(BeIdenticalTo(left), "the connection has to be handed back untouched")

	byValue, ok := info.(AuthInfo)
	g.Expect(ok).To(BeTrue())
	g.Expect(byValue.Conn).To(BeIdenticalTo(left))
	g.Expect(byValue.AuthType()).To(Equal(authType))

	_, ok = info.(*AuthInfo)
	g.Expect(ok).To(BeFalse(), "a pointer assertion has to fail, which is why the value form is documented")
}

// TestClientHandshake_Fails records that these credentials are server-side only: a
// client reaching them is a wiring bug, and quietly succeeding would hand a dialer
// an unauthenticated connection it believed was protected.
func TestClientHandshake_Fails(t *testing.T) {
	g := NewWithT(t)

	left, right := net.Pipe()
	defer func() { _ = right.Close() }()

	_, _, err := NewConnCredentials().ClientHandshake(context.Background(), "agent", left)
	g.Expect(err).To(MatchError(errClientHandshake))
	// the connection is closed rather than leaked
	_, err = left.Write([]byte("anything"))
	g.Expect(err).To(HaveOccurred())
}
