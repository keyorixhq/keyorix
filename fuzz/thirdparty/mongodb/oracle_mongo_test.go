package mongofuzz

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// TestCanaryOracle_RedGreen validates oracle (b)'s detector: fires on the secret,
// silent on clean server text.
func TestCanaryOracle_RedGreen(t *testing.T) {
	if !containsCanary("scram proof failed for " + canaryPassword) {
		t.Fatal("canary oracle failed to detect a leaked password")
	}
	if containsCanary("auth error: mechanism SCRAM-SHA-256 failed") {
		t.Fatal("canary oracle false-positived on clean server text")
	}
}

// seqServer is a deterministic fake that replies to the i-th client message with
// handler(i, reqID); when handler signals stop, it half-closes the write side
// (EOF) while keeping the read side open so the driver's in-flight writes do not
// reset. Used by the truncation / length oracles.
type seqServer struct {
	ln      net.Listener
	handler func(msgIdx int, reqID int32) (reply []byte, cont bool)
	wg      sync.WaitGroup
}

func newSeqServer(t *testing.T, h func(int, int32) ([]byte, bool)) *seqServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &seqServer{ln: ln, handler: h}
	s.wg.Add(1)
	go s.serve()
	return s
}

func (s *seqServer) addr() string { return s.ln.Addr().String() }

func (s *seqServer) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer func() { _ = c.Close() }()
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			_ = c.SetDeadline(time.Now().Add(callWallBound))
			idx := 0
			for {
				reqID, err := readClientMessage(c)
				if err != nil {
					return
				}
				reply, cont := s.handler(idx, reqID)
				if _, err := c.Write(reply); err != nil {
					return
				}
				if !cont {
					if tcp, ok := c.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
					_, _ = io.Copy(io.Discard, c)
					return
				}
				idx++
			}
		}(c)
	}
}

func (s *seqServer) close() { _ = s.ln.Close(); s.wg.Wait() }

func helloReplyBytes(reqID int32) []byte { return opMsgReply(reqID, cannedHelloDoc()) }
func okReplyBytes(reqID int32) []byte {
	return opMsgReply(reqID, bson.D{{Key: "ok", Value: int32(1)}})
}

// newHostileClientNoAuth builds a credential-free client so a well-formed handshake
// actually lets Ping SUCCEED — needed to give oracle (d) a real success/failure
// distinction (with SCRAM, Ping can never succeed against a fake that cannot forge
// the proof). This isolates the wire reader, which is auth-independent.
func newHostileClientNoAuth(addr string) (*mongo.Client, error) {
	opts := options.Client().
		SetHosts([]string{addr}).
		SetDirect(true).
		SetDialer(lingerDialer{}).
		SetConnectTimeout(500 * time.Millisecond).
		SetServerSelectionTimeout(700 * time.Millisecond).
		SetTimeout(time.Second)
	return mongo.Connect(opts)
}

// TestTruncatedWireMessage validates oracle (d): a reply whose messageLength header
// overstates the bytes actually sent, followed by EOF, must surface as an error —
// never a truncated success. Green control: an honest, full handshake lets Ping
// succeed, proving the path discriminates.
func TestTruncatedWireMessage(t *testing.T) {
	// Red: hello reply header claims 500 more bytes than sent, then EOF.
	redSrv := newSeqServer(t, func(i int, reqID int32) ([]byte, bool) {
		full := helloReplyBytes(reqID)
		binary.LittleEndian.PutUint32(full[0:], uint32(len(full)+500)) // overstate
		return full, false                                             // half-close after
	})
	defer redSrv.close()
	rc, err := newHostileClientNoAuth(redSrv.addr())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer disconnect(rc)
	ctx, cancel := context.WithTimeout(context.Background(), callWallBound)
	defer cancel()
	if err := rc.Ping(ctx, nil); err == nil {
		t.Fatal("truncated wire message produced a successful Ping — reader ignored the short read")
	}

	// Green: honest hello + ok reply to ping -> Ping succeeds.
	greenSrv := newSeqServer(t, func(i int, reqID int32) ([]byte, bool) {
		if i == 0 {
			return helloReplyBytes(reqID), true
		}
		return okReplyBytes(reqID), true
	})
	defer greenSrv.close()
	gc, err := newHostileClientNoAuth(greenSrv.addr())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer disconnect(gc)
	ctx2, cancel2 := context.WithTimeout(context.Background(), callWallBound)
	defer cancel2()
	if err := gc.Ping(ctx2, nil); err != nil {
		t.Fatalf("well-formed handshake failed Ping: %v", err)
	}
}

// TestWireLengthBound characterises whether the driver pre-allocates the full
// attacker-declared messageLength before reading the body. Safe one-shot: declares
// 8 MiB, sends a tiny body, then EOF. Asserts only that Ping errors (no truncated
// success) and records the realised allocation for the report. Does NOT push to the
// 48 MB maxMessageSize boundary (host safety); that cap was not exercised.
func TestWireLengthBound(t *testing.T) {
	const declared = 8 << 20 // 8 MiB
	srv := newSeqServer(t, func(i int, reqID int32) ([]byte, bool) {
		// A header declaring 8 MiB, with only a few body bytes, then EOF.
		full := helloReplyBytes(reqID)
		if len(full) > 24 {
			full = full[:24] // header + a few bytes
		}
		binary.LittleEndian.PutUint32(full[0:], uint32(declared))
		return full, false
	})
	defer srv.close()
	c, err := newHostileClientNoAuth(srv.addr())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer disconnect(c)
	ctx, cancel := context.WithTimeout(context.Background(), callWallBound)
	defer cancel()

	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	err = c.Ping(ctx, nil)
	runtime.ReadMemStats(&b)
	delta := b.TotalAlloc - a.TotalAlloc
	if err == nil {
		t.Fatal("8 MiB-declared short message produced a successful Ping — truncated-success bug")
	}
	t.Logf("wire-length probe: declared %d bytes, sent ~24, Ping TotalAlloc delta ~%d bytes", declared, delta)
	if delta >= declared/2 {
		t.Logf("NOTE: driver pre-allocated ~the full declared messageLength before detecting the short read")
	} else {
		t.Logf("NOTE: driver did NOT pre-allocate the full declared length (bounded reader)")
	}
}

func disconnect(c *mongo.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = c.Disconnect(ctx)
}
