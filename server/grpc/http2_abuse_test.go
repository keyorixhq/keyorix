package grpc

// TestHTTP2Abuse_ServerStaysResponsive throws abusive HTTP/2 frames at the REAL
// gRPC server (NewServer, with Keyorix's h2 limits: MaxConcurrentStreams 128,
// MaxHeaderListSize 64 KiB, the keepalive enforcement policy) and asserts a
// normal RPC still works afterwards and the goroutine count does not explode.
//
// This is a deterministic robustness test rather than a Go fuzz target: standing
// up the real gRPC server requires testhelper.NewRBACTestHelper, which takes a
// *testing.T (unavailable in a fuzz setup that only holds *testing.F). The
// abusive-frame set below is the same catalogue the HTTP/2 FUZZ target
// (server.FuzzHTTP2AbusiveFrames) explores against the REST listener; here it is
// driven by fixed patterns against the gRPC listener so the Keyorix-set h2 limits
// are the ones under test.
//
// Oracles: the server never panics; after each abusive connection a real
// SystemService.HealthCheck RPC on an independent grpc.ClientConn succeeds within
// a deadline (server-wide responsiveness); goroutines return under a ceiling.
//
// What this does NOT verify: it does not measure heap bytes directly; it does not
// fuzz-explore frame orderings (the HTTP target does that); it uses HealthCheck
// (unauthenticated) as the liveness probe, so it exercises the transport layer,
// not authenticated handlers.

import (
	"context"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestHTTP2Abuse_ServerStaysResponsive(t *testing.T) {
	addr := serveNewServer(t, &config.Config{})

	// Baseline: the server answers before any abuse.
	if err := grpcHealthCheck(addr); err != nil {
		t.Fatalf("baseline HealthCheck failed before abuse: %v", err)
	}

	base := runtime.NumGoroutine()

	abuses := []struct {
		name string
		fn   func(fr *http2.Framer, next func() uint32) error
	}{
		{"settings-flood", func(fr *http2.Framer, _ func() uint32) error {
			for i := range 256 {
				if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(i * 1024)}); err != nil {
					return err
				}
			}
			return nil
		}},
		{"rapid-reset", func(fr *http2.Framer, next func() uint32) error {
			for range 256 {
				id := next()
				if err := writeGRPCHeaders(fr, id, grpcSmallHeaderBlock(), false); err != nil {
					return err
				}
				if err := fr.WriteRSTStream(id, http2.ErrCodeCancel); err != nil {
					return err
				}
			}
			return nil
		}},
		{"oversized-headers", func(fr *http2.Framer, next func() uint32) error {
			return writeGRPCHeaders(fr, next(), grpcBigHeaderBlock(), true)
		}},
		{"ping-flood", func(fr *http2.Framer, _ func() uint32) error {
			for i := range 256 {
				var p [8]byte
				p[0] = byte(i)
				if err := fr.WritePing(false, p); err != nil {
					return err
				}
			}
			return nil
		}},
		{"continuation-flood", func(fr *http2.Framer, next func() uint32) error {
			id := next()
			if err := writeGRPCHeaders(fr, id, grpcSmallHeaderBlock(), false); err != nil {
				return err
			}
			for range 32 {
				if err := fr.WriteContinuation(id, false, grpcSmallHeaderBlock()); err != nil {
					return err
				}
			}
			return nil
		}},
		{"exceed-max-concurrent-streams", func(fr *http2.Framer, next func() uint32) error {
			// Open well past MaxConcurrentStreams (128) without closing them.
			for range 400 {
				if err := writeGRPCHeaders(fr, next(), grpcSmallHeaderBlock(), true); err != nil {
					return err
				}
			}
			return nil
		}},
	}

	for _, a := range abuses {
		t.Run(a.name, func(t *testing.T) {
			runAbuse(t, addr, a.fn)
			if err := grpcHealthCheck(addr); err != nil {
				t.Fatalf("gRPC server unresponsive after %q abuse: %v", a.name, err)
			}
		})
	}

	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > base+96 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > base+96 {
		t.Fatalf("goroutine leak after abuse: %d now vs %d baseline (ceiling +96)", g, base)
	}
}

// runAbuse opens one raw h2c connection to the gRPC server and runs fn. All
// errors are tolerated: the server rejecting abuse by resetting/closing is the
// intended outcome; the HealthCheck afterwards is the judge.
func runAbuse(t *testing.T, addr string, fn func(fr *http2.Framer, next func() uint32) error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := fr.ReadFrame(); err != nil {
				return
			}
		}
	}()
	defer func() { _ = conn.Close(); <-done }()

	id := uint32(1)
	next := func() uint32 {
		v := id
		id += 2
		return v
	}
	_ = fn(fr, next)
}

func grpcHealthCheck(addr string) error {
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer func() { _ = cc.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err = pb.NewSystemServiceClient(cc).HealthCheck(ctx, &emptypb.Empty{})
	return err
}

func writeGRPCHeaders(fr *http2.Framer, id uint32, block []byte, endHeaders bool) error {
	return fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      id,
		BlockFragment: block,
		EndStream:     false,
		EndHeaders:    endHeaders,
	})
}

func grpcSmallHeaderBlock() []byte {
	var buf grpcHdrBuf
	enc := hpack.NewEncoder(&buf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "http"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/grpc.health.v1.Health/Check"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "localhost"})
	_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})
	return []byte(buf)
}

func grpcBigHeaderBlock() []byte {
	var buf grpcHdrBuf
	enc := hpack.NewEncoder(&buf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "http"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/grpc.health.v1.Health/Check"})
	val := make([]byte, 2048)
	for i := range val {
		val[i] = 'a'
	}
	for range 64 {
		_ = enc.WriteField(hpack.HeaderField{Name: "x-abuse", Value: string(val)})
	}
	return []byte(buf)
}

type grpcHdrBuf []byte

func (b *grpcHdrBuf) Write(p []byte) (int, error) {
	*b = append(*b, p...)
	return len(p), nil
}
