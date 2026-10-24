package grpc

import (
	"context"
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/testhelper"
)

// TestNewServer_TLS_NegotiatesX25519MLKEM768 (RD-PQTLS-1): a real gRPC client
// (grpc-go's credentials.NewTLS, no CurvePreferences) against the server NewServer
// builds. The group is read from the client's peer.AuthInfo, i.e. what the wire
// negotiated, and the call itself (an unknown method) only has to reach the server.
func TestNewServer_TLS_NegotiatesX25519MLKEM768(t *testing.T) {
	for _, mode := range []string{"", config.TLSModeStrict} {
		t.Run("mode="+mode, func(t *testing.T) {
			dir := t.TempDir()
			certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
			writeECDSAPairGRPC(t, certFile, keyFile, 1)

			h := testhelper.NewRBACTestHelper(t)
			t.Cleanup(h.Cleanup)
			cfg := &config.Config{}
			cfg.Server.GRPC.TLS = config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile}
			cfg.Server.GRPC.TLSMode = mode
			srv, err := NewServer(cfg, h.CoreService)
			if err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = srv.Serve(ln) }()
			t.Cleanup(srv.Stop)

			conn, err := grpc.NewClient(ln.Addr().String(),
				grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}))) // #nosec G402 -- throwaway self-signed test cert; the test is about the key-exchange group
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var p peer.Peer
			// The method does not exist: the server answers Unimplemented/Unauthenticated, which
			// is fine, the handshake and its negotiated group are what this test reads.
			_ = conn.Invoke(ctx, "/keyorix.pqtls.Probe/Ping", &emptypb.Empty{}, &emptypb.Empty{}, grpc.Peer(&p))
			ti, ok := p.AuthInfo.(credentials.TLSInfo)
			if !ok {
				t.Fatalf("peer AuthInfo is %T, want credentials.TLSInfo (the call never completed a TLS handshake)", p.AuthInfo)
			}
			if ti.State.CurveID != tls.X25519MLKEM768 {
				t.Fatalf("negotiated group = %v (%#x), want X25519MLKEM768", ti.State.CurveID, uint16(ti.State.CurveID))
			}
			if ti.State.Version != tls.VersionTLS13 {
				t.Errorf("version %#x, want TLS 1.3", ti.State.Version)
			}
		})
	}
}

// createGRPCTLSConfig must not narrow the groups (see the HTTP twin in server/pq_transport_test.go).
func TestCreateGRPCTLSConfig_DoesNotSetCurvePreferences(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeECDSAPairGRPC(t, certFile, keyFile, 1)
	for _, mode := range []string{"", config.TLSModeStrict} {
		cfg := &config.Config{}
		cfg.Server.GRPC.TLS = config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile}
		cfg.Server.GRPC.TLSMode = mode
		tc, err := createGRPCTLSConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if tc.CurvePreferences != nil {
			t.Errorf("mode %q: CurvePreferences = %v, want nil", mode, tc.CurvePreferences)
		}
	}
}
