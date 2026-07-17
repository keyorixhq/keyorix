// interceptors_s18_test.go — coverage uplift for PeerIP (auth.go:339).
package interceptors

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc/peer"
)

// fakeAddr is a minimal net.Addr implementation for injecting peer addresses.
type fakeAddr struct{ addr string }

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return f.addr }

// peerCtx returns a context that carries a peer with the given address string.
func peerCtx(addr string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: fakeAddr{addr: addr},
	})
}

// TestPeerIP_NoPeer returns "" when the context carries no peer.
func TestPeerIP_NoPeer(t *testing.T) {
	got := PeerIP(context.Background())
	if got != "" {
		t.Errorf("PeerIP(no peer) = %q, want empty", got)
	}
}

// TestPeerIP_NilAddr returns "" when the peer's Addr is nil.
func TestPeerIP_NilAddr(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: nil})
	got := PeerIP(ctx)
	if got != "" {
		t.Errorf("PeerIP(nil addr) = %q, want empty", got)
	}
}

// TestPeerIP_IPv4WithPort returns just the host for a standard host:port address.
func TestPeerIP_IPv4WithPort(t *testing.T) {
	ctx := peerCtx("192.168.1.42:50051")
	got := PeerIP(ctx)
	if got != "192.168.1.42" {
		t.Errorf("PeerIP(IPv4:port) = %q, want %q", got, "192.168.1.42")
	}
}

// TestPeerIP_IPv6WithPort returns just the host for a bracketed IPv6 address.
func TestPeerIP_IPv6WithPort(t *testing.T) {
	ctx := peerCtx("[::1]:50051")
	got := PeerIP(ctx)
	if got != "::1" {
		t.Errorf("PeerIP(IPv6 bracketed) = %q, want %q", got, "::1")
	}
}

// TestPeerIP_BareIPFallback returns the raw string when SplitHostPort fails
// (i.e. when there is no port component).
func TestPeerIP_BareIPFallback(t *testing.T) {
	// SplitHostPort requires a port; without one it errors, so PeerIP falls back
	// to returning p.Addr.String() unchanged.
	ctx := peerCtx("10.0.0.1")
	got := PeerIP(ctx)
	if got != "10.0.0.1" {
		t.Errorf("PeerIP(bare IP) = %q, want %q", got, "10.0.0.1")
	}
}

// TestPeerIP_LoopbackIPv4 returns "127.0.0.1" for a localhost address.
func TestPeerIP_LoopbackIPv4(t *testing.T) {
	ctx := peerCtx("127.0.0.1:12345")
	got := PeerIP(ctx)
	if got != "127.0.0.1" {
		t.Errorf("PeerIP(loopback) = %q, want %q", got, "127.0.0.1")
	}
}

// TestPeerIP_UnixSocketFallback verifies PeerIP does not panic for a unix-socket
// style address where SplitHostPort will fail and the raw string is returned.
func TestPeerIP_UnixSocketFallback(t *testing.T) {
	ctx := peerCtx("/var/run/keyorix.sock")
	got := PeerIP(ctx)
	// SplitHostPort will fail; fallback returns the raw address string.
	if got != "/var/run/keyorix.sock" {
		t.Errorf("PeerIP(unix socket) = %q, want raw path", got)
	}
}

// TestPeerIP_RealTCPAddr uses a real net.TCPAddr (the type gRPC uses in
// production) to exercise the same branch.
func TestPeerIP_RealTCPAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 9090}
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: addr})
	got := PeerIP(ctx)
	if got != "203.0.113.5" {
		t.Errorf("PeerIP(TCPAddr) = %q, want %q", got, "203.0.113.5")
	}
}
