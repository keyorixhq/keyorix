package wirefuzz

// grpc_world_test.go stands the REAL gRPC server (grpc.NewServer with the full
// production interceptor chain: Recovery→RequestID→Metrics→Logging→Timeout→
// WriteContention→Auth→RateLimit→ShareAudit) up on a loopback listener, seeded
// identically to the HTTP world, and provides the raw HTTP/2 connection plumbing
// shared by FuzzWireHTTP2 and FuzzWireGRPCFraming.
//
// The gRPC listener speaks HTTP/2 with PRIOR KNOWLEDGE and no TLS (the empty test
// config leaves grpc.Server.TLS disabled), exactly matching a production deployment
// that terminates TLS at a sidecar and forwards cleartext h2. So a raw TCP socket
// plus the HTTP/2 client preface reaches the real framing stack.

import (
	"bytes"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/keyorixhq/keyorix/internal/config"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
)

// Real gRPC method paths (unauthenticated callers must be rejected before any
// secret is read). GetSecretValue is the highest-value target: its success response
// carries a secret's plaintext, so a framing-confusion auth bypass would surface as
// a plaintext leak.
const (
	methodGetSecretValue = "/keyorix.v1.SecretService/GetSecretValue"
	methodGetSecret      = "/keyorix.v1.SecretService/GetSecret"
	methodListSecrets    = "/keyorix.v1.SecretService/ListSecrets"
)

type grpcWorld struct {
	addr string
	s    *seededStack
}

func buildGRPCWorld(tb testing.TB) *grpcWorld {
	tb.Helper()
	s := seedCore(tb)
	gsrv, err := keyorixgrpc.NewServer(&config.Config{}, s.c)
	if err != nil {
		tb.Fatalf("grpc NewServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	go func() { _ = gsrv.Serve(ln) }()
	tb.Cleanup(gsrv.Stop)
	return &grpcWorld{addr: ln.Addr().String(), s: s}
}

// h2Handshake dials the listener, sends the HTTP/2 client preface and an empty
// SETTINGS frame, and returns a Framer ready to emit fuzz-controlled frames. It does
// NOT wait for the server SETTINGS (the fuzzer may want to misbehave before the ack);
// callers that need a clean stream read frames themselves.
func h2Handshake(addr string) (net.Conn, *http2.Framer, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, nil, err
	}
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, fr, nil
}

// drainConn half-closes the write side (a FIN makes the server flush its GOAWAY and
// close, giving a prompt EOF instead of blocking on the full watchdog) and reads
// whatever the server returned under a short, fixed deadline. The outer per-exec
// watchdog in the drive functions still bounds the whole exchange for a true hang;
// this deadline only keeps throughput sane on the common case where the server holds
// the HTTP/2 connection open after our frames.
func drainConn(conn net.Conn) []byte {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(conn)
	return buf.Bytes()
}

// encodeHeaders HPACK-encodes a header list into a single HEADERS block.
func encodeHeaders(hdrs []hpack.HeaderField) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, h := range hdrs {
		_ = enc.WriteField(h)
	}
	return buf.Bytes()
}

// grpcRequestHeaders is the pseudo-header + content-type set for a well-formed gRPC
// request to method, optionally carrying an authorization metadata header.
func grpcRequestHeaders(method, authority, authHdr string) []hpack.HeaderField {
	h := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: method},
		{Name: ":authority", Value: authority},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
	}
	if authHdr != "" {
		h = append(h, hpack.HeaderField{Name: "authorization", Value: authHdr})
	}
	return h
}
