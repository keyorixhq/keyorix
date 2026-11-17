package grpc

// TestGRPCMetadataAbuse drives abusive gRPC metadata patterns at the REAL Keyorix
// gRPC server and asserts:
//
//   - The server never panics and stays responsive (HealthCheck still works after each
//     abuse pattern).
//
//   - Metadata abuse cannot bypass auth: sending `authorization-bin` with valid
//     base64-encoded token bytes does NOT satisfy the auth interceptor, which reads
//     only the plain `authorization` key.
//
//   - Invalid base64 in a -bin metadata value is rejected or dropped by the transport;
//     it does not crash the server.
//
//   - Duplicate `grpc-timeout` headers do not cause a hang.
//
// These are deterministic robustness tests (not fuzz targets) — the full Keyorix
// server stack required here (serveNewServer + testhelper.NewRBACTestHelper) is not
// available inside a *testing.F.
//
// What these tests do NOT verify:
//   - NOT tested: streaming interceptor auth (only unary gRPC calls are exercised).
//   - NOT tested: metadata key case-folding by the application-layer auth interceptor
//     — gRPC-go normalises keys to lowercase before passing them to handlers, so
//     `AUTHORIZATION` and `authorization` already behave identically at the interceptor.
//   - NOT tested: server-sent metadata / trailer encoding.

import (
	"context"
	"encoding/base64"
	"runtime"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TestGRPCMetadataAbuse_ServerStaysResponsive verifies the server keeps handling
// legitimate RPCs after each metadata-abuse pattern.
func TestGRPCMetadataAbuse_ServerStaysResponsive(t *testing.T) {
	addr := serveNewServer(t, &config.Config{})

	if err := grpcHealthCheck(addr); err != nil {
		t.Fatalf("baseline HealthCheck failed: %v", err)
	}
	base := runtime.NumGoroutine()

	abuses := []struct {
		name string
		fn   func(fr *http2.Framer, next func() uint32) error
	}{
		{"invalid-bin-metadata-base64", func(fr *http2.Framer, next func() uint32) error {
			return writeGRPCHeaders(fr, next(), grpcHeaderBlockWithMeta([]hpack.HeaderField{
				{Name: "x-custom-bin", Value: "!!!not-valid-base64!!!"},
			}), true)
		}},
		{"bin-metadata-with-nulls", func(fr *http2.Framer, next func() uint32) error {
			return writeGRPCHeaders(fr, next(), grpcHeaderBlockWithMeta([]hpack.HeaderField{
				{Name: "x-custom-bin", Value: base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0, 1, 2, 3})},
			}), true)
		}},
		{"duplicate-grpc-timeout", func(fr *http2.Framer, next func() uint32) error {
			return writeGRPCHeaders(fr, next(), grpcHeaderBlockWithMeta([]hpack.HeaderField{
				{Name: "grpc-timeout", Value: "1H"},
				{Name: "grpc-timeout", Value: "1H"},
			}), true)
		}},
		{"grpc-timeout-invalid", func(fr *http2.Framer, next func() uint32) error {
			return writeGRPCHeaders(fr, next(), grpcHeaderBlockWithMeta([]hpack.HeaderField{
				{Name: "grpc-timeout", Value: "not-a-timeout"},
			}), true)
		}},
		{"many-metadata-keys", func(fr *http2.Framer, next func() uint32) error {
			fields := make([]hpack.HeaderField, 128)
			for i := range fields {
				fields[i] = hpack.HeaderField{Name: "x-abuse-meta", Value: "v"}
			}
			return writeGRPCHeaders(fr, next(), grpcHeaderBlockWithMeta(fields), true)
		}},
		{"authorization-bin-bypass-attempt", func(fr *http2.Framer, next func() uint32) error {
			encoded := base64.StdEncoding.EncodeToString([]byte("Bearer fake-auth-token-abuse"))
			return writeGRPCHeaders(fr, next(), grpcHeaderBlockWithMeta([]hpack.HeaderField{
				{Name: "authorization-bin", Value: encoded},
			}), true)
		}},
	}

	for _, a := range abuses {
		t.Run(a.name, func(t *testing.T) {
			runAbuse(t, addr, a.fn)
			if err := grpcHealthCheck(addr); err != nil {
				t.Fatalf("server unresponsive after %q: %v", a.name, err)
			}
		})
	}

	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > base+96 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > base+96 {
		t.Fatalf("goroutine leak after metadata abuse: %d now vs %d baseline", g, base)
	}
}

// TestGRPCMetadataAbuse_AuthorizationBinDoesNotBypassAuth verifies that sending
// `authorization-bin` with valid base64-encoded token bytes DOES NOT satisfy the
// gRPC auth interceptor.
//
// Red proof: a request with ONLY `authorization-bin` (and no plain `authorization`)
// must fail with Unauthenticated/PermissionDenied — it must not succeed.
func TestGRPCMetadataAbuse_AuthorizationBinDoesNotBypassAuth(t *testing.T) {
	addr := serveNewServer(t, &config.Config{})

	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = cc.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	md := metadata.New(map[string]string{
		"authorization-bin": base64.StdEncoding.EncodeToString([]byte("Bearer fake-bypass-attempt")),
	})
	authCtx := metadata.NewOutgoingContext(ctx, md)

	_, callErr := pb.NewSecretServiceClient(cc).ListSecrets(authCtx, &pb.ListSecretsRequest{})
	if callErr == nil {
		t.Fatal("BYPASS: ListSecrets returned success with only authorization-bin and no authorization header")
	}
	code := status.Code(callErr)
	if code == codes.OK {
		t.Fatalf("BYPASS: got OK status from an unauthenticated request; expected Unauthenticated/PermissionDenied")
	}
	t.Logf("authorization-bin bypass attempt correctly rejected (code=%s)", code)
}

// grpcHeaderBlockWithMeta builds an HPACK block for a minimal gRPC call (HealthCheck
// path) with extra metadata fields appended.
func grpcHeaderBlockWithMeta(extra []hpack.HeaderField) []byte {
	var buf grpcHdrBuf
	enc := hpack.NewEncoder(&buf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "http"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/keyorix.v1.SystemService/HealthCheck"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "localhost"})
	_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})
	for _, f := range extra {
		_ = enc.WriteField(f)
	}
	return []byte(buf)
}
