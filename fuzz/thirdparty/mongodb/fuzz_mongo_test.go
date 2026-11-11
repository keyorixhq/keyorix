// Package mongofuzz drives the real go.mongodb.org/mongo-driver/v2 client against a
// hostile loopback server whose MongoDB wire-protocol replies (message framing,
// opCode, messageLength, OP_MSG sections and the BSON documents inside them) come
// from the fuzz input. The goal is to find defects in the driver's own response
// parser — wire-message reader + BSON decoder — reachable from the client's PUBLIC
// API only (Connect + Ping + RunCommand), with no Keyorix wrapper in the path.
//
// Keyorix pins go.mongodb.org/mongo-driver/v2 v2.9.2 (see go.mod). The client is
// used in internal/dynamic/mongodb.go to connect to an operator-configured target
// MongoDB and run createUser / dropUser; a compromised or malicious target can
// return arbitrary wire bytes, which is the surface fuzzed here.
//
// The fuzzer controls the reply to the connection handshake. Two modes:
//   - mode 0: the very first reply (to the driver's `hello`) is fuzzer bytes, so
//     the wire-header + OP_MSG + hello-reply BSON decode path is fuzzed directly.
//   - mode 1: the first reply is a canned VALID hello (built with the real
//     bson.Marshal), so the driver proceeds to SCRAM saslStart; every subsequent
//     reply is fuzzer bytes, fuzzing the sasl/command reply BSON path.
//
// ORACLES (and what each does NOT verify):
//
//	(a) no-panic / no-hang / bounded-memory. A panic fails the run. A hang is
//	    bounded by the context deadline + the driver's connect/selection/socket
//	    timeouts. Bounded memory is STRUCTURAL: the fuzzer-declared messageLength is
//	    clamped to maxWireLen before the bytes reach the driver (the driver reads
//	    the whole wire message into one buffer sized by messageLength, and parses
//	    all BSON within that buffer, so clamping the outer length bounds every
//	    allocation). It therefore does NOT prove the driver self-bounds the outer
//	    length — that uncapped behaviour is probed once by TestWireLengthBound.
//
//	(b) canary. The client is given a secret canaryPassword via SCRAM credentials.
//	    SCRAM never puts the password on the wire, so any appearance of it in a
//	    returned error or in fmt of returned values is a real leak. Does NOT capture
//	    driver logs (the v2 driver's logger is off by default; no global sink).
//
//	(c) echo. Server-controlled text the server places into an error-document
//	    `errmsg` legitimately surfaces in the driver error — reported as the echo
//	    class, never a failure. Canary bytes are never sent as reply content, so an
//	    echo can never be a canary hit.
//
//	(d) ignored-read-error. Handled deterministically by TestTruncatedWireMessage:
//	    a reply whose messageLength exceeds the bytes sent, then EOF, must surface
//	    as an error, never a truncated success.
package mongofuzz

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func init() { runtime.GOMAXPROCS(2) }

const (
	canaryUsername = "kx-mongo-canary-user-7e1a9c"
	canaryPassword = "kxPASS-mongo-canary-9f3a1c7e5b2d4086-SECRET-do-not-leak"

	opMsg   = 2013
	opReply = 1

	// maxWireLen bounds every fuzzer-declared messageLength so a hostile length
	// cannot drive a giant allocation on this shared host. 64 KiB: large enough to
	// exercise the reader, small enough that a per-iteration worst case is cheap.
	maxWireLen = 1 << 16

	callWallBound = 2 * time.Second
)

// ---- wire-message construction ---------------------------------------------

// wireHeader builds a 16-byte MongoDB message header + body. The caller may then
// overwrite the leading messageLength to fuzz length handling.
func wireHeader(responseTo, opcode int32, body []byte) []byte {
	total := 16 + len(body)
	out := make([]byte, 16, total)
	binary.LittleEndian.PutUint32(out[0:], uint32(total))
	binary.LittleEndian.PutUint32(out[4:], 1) // our requestID
	binary.LittleEndian.PutUint32(out[8:], uint32(responseTo))
	binary.LittleEndian.PutUint32(out[12:], uint32(opcode))
	return append(out, body...)
}

// opMsgReply wraps a single BSON document as an OP_MSG kind-0 section reply.
func opMsgReply(responseTo int32, doc bson.D) []byte {
	raw, err := bson.Marshal(doc)
	if err != nil {
		panic(err)
	}
	body := make([]byte, 0, 5+len(raw))
	body = append(body, 0, 0, 0, 0) // flagBits
	body = append(body, 0)          // section kind 0 (body)
	body = append(body, raw...)
	return wireHeader(responseTo, opMsg, body)
}

// cannedHelloDoc is a minimal VALID hello reply so the driver accepts the server
// and proceeds to authentication (mode 1). Built with the real bson.Marshal.
func cannedHelloDoc() bson.D {
	return bson.D{
		{Key: "ok", Value: int32(1)},
		{Key: "isWritablePrimary", Value: true},
		{Key: "helloOk", Value: true},
		{Key: "minWireVersion", Value: int32(0)},
		{Key: "maxWireVersion", Value: int32(21)},
		{Key: "maxBsonObjectSize", Value: int32(16 * 1024 * 1024)},
		{Key: "maxMessageSizeBytes", Value: int32(48000000)},
		{Key: "maxWriteBatchSize", Value: int32(100000)},
		{Key: "logicalSessionTimeoutMinutes", Value: int32(30)},
		{Key: "connectionId", Value: int32(1)},
		{Key: "readOnly", Value: false},
	}
}

func clampWireLen(n int64) uint32 {
	if n < 0 || n > maxWireLen {
		return uint32(maxWireLen)
	}
	return uint32(n)
}

// buildFuzzReply assembles a wire-message reply from fuzzer-controlled opcode,
// length mode, and body bytes. The declared messageLength is clamped for host
// safety; lenMode lets the fuzzer declare more (amplification/truncation) or less
// than it sends.
func buildFuzzReply(opSel, lenMode byte, body []byte, responseTo int32) []byte {
	var opcode int32
	switch opSel % 3 {
	case 0:
		opcode = opMsg
	case 1:
		opcode = opReply
	default:
		opcode = int32(opSel) // garbage opcode
	}
	full := wireHeader(responseTo, opcode, body)
	switch lenMode % 4 {
	case 0:
		// honest length — leave as computed
	case 1:
		binary.LittleEndian.PutUint32(full[0:], clampWireLen(1<<30)) // declare >> sent (clamped)
	case 2:
		binary.LittleEndian.PutUint32(full[0:], 16) // declare header-only
	case 3:
		binary.LittleEndian.PutUint32(full[0:], 0) // nonsense tiny length
	}
	return full
}

// ---- hostile loopback server -----------------------------------------------

type hostileServer struct {
	ln      net.Listener
	mode    byte
	opSel   byte
	lenMode byte
	body    []byte
	wg      sync.WaitGroup
}

func newHostileServer(t testingTB, mode, opSel, lenMode byte, body []byte) *hostileServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &hostileServer{ln: ln, mode: mode, opSel: opSel, lenMode: lenMode, body: body}
	s.wg.Add(1)
	go s.serve()
	return s
}

// testingTB is the minimal subset used so both *testing.T and *testing.F work.
type testingTB interface {
	Fatalf(string, ...any)
}

func (s *hostileServer) addr() string { return s.ln.Addr().String() }

func (s *hostileServer) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0) // avoid TIME_WAIT buildup on this shared host
			}
			_ = c.SetDeadline(time.Now().Add(callWallBound))
			msgIdx := 0
			for {
				reqID, err := readClientMessage(c)
				if err != nil {
					return
				}
				var reply []byte
				if s.mode%2 == 1 && msgIdx == 0 {
					reply = opMsgReply(reqID, cannedHelloDoc())
				} else {
					reply = buildFuzzReply(s.opSel, s.lenMode, s.body, reqID)
				}
				if _, err := c.Write(reply); err != nil {
					return
				}
				msgIdx++
				if msgIdx > 8 { // bound handshake round-trips
					return
				}
			}
		}(c)
	}
}

func (s *hostileServer) close() { _ = s.ln.Close(); s.wg.Wait() }

// readClientMessage reads one full MongoDB wire message and returns its requestID.
// The real driver sends well-formed small messages, but the read is bounded anyway.
func readClientMessage(c net.Conn) (int32, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return 0, err
	}
	total := int(int32(binary.LittleEndian.Uint32(hdr[0:])))
	reqID := int32(binary.LittleEndian.Uint32(hdr[4:]))
	rem := total - 16
	if rem < 0 || rem > maxWireLen {
		// protocol-nonsense from the driver should not happen; bound and move on.
		return reqID, nil
	}
	if rem > 0 {
		if _, err := io.ReadFull(c, make([]byte, rem)); err != nil {
			return reqID, err
		}
	}
	return reqID, nil
}

// ---- client ----------------------------------------------------------------

type lingerDialer struct{}

func (lingerDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	return c, nil
}

func newHostileClient(addr string) (*mongo.Client, error) {
	opts := options.Client().
		SetHosts([]string{addr}).
		SetDirect(true).
		SetDialer(lingerDialer{}).
		SetConnectTimeout(500 * time.Millisecond).
		SetServerSelectionTimeout(700 * time.Millisecond).
		SetTimeout(time.Second).
		SetAuth(options.Credential{
			AuthMechanism: "SCRAM-SHA-256",
			AuthSource:    "admin",
			Username:      canaryUsername,
			Password:      canaryPassword,
			PasswordSet:   true,
		})
	return mongo.Connect(opts)
}

func containsCanary(s string) bool {
	return strings.Contains(s, canaryPassword)
}

// drive runs one public-API interaction and returns the error plus a formatted view
// of any returned value. mode byte selects Ping vs a RunCommand.
func drive(ctx context.Context, c *mongo.Client, mode byte) (error, string) {
	switch mode % 2 {
	case 0:
		return c.Ping(ctx, nil), "ping"
	default:
		var res bson.M
		err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "createUser", Value: "x"}, {Key: "pwd", Value: canaryPassword}, {Key: "roles", Value: bson.A{}}}).Decode(&res)
		return err, fmt.Sprintf("%+v", res)
	}
}

// runInteraction performs one hostile exchange and runs oracles (a)+(b).
func runInteraction(t *testing.T, mode, opSel, lenMode, driveMode byte, body []byte) {
	t.Helper()
	srv := newHostileServer(t, mode, opSel, lenMode, body)
	defer srv.close()

	client, err := newHostileClient(srv.addr())
	if err != nil {
		// Connect only fails on invalid options, which are fixed here.
		t.Fatalf("connect: %v", err)
	}
	defer func() {
		dctx, dcancel := context.WithTimeout(context.Background(), time.Second)
		defer dcancel()
		_ = client.Disconnect(dctx)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), callWallBound)
	defer cancel()

	var ms0, ms1 runtime.MemStats
	runtime.ReadMemStats(&ms0)

	type res struct {
		err  error
		fmtd string
	}
	ch := make(chan res, 1)
	go func() {
		e, f := drive(ctx, client, driveMode)
		ch <- res{e, f}
	}()

	select {
	case r := <-ch:
		runtime.ReadMemStats(&ms1)
		// oracle (b): the SCRAM password must never surface.
		if r.err != nil && containsCanary(r.err.Error()) {
			t.Fatalf("CANARY LEAK in error: %v", r.err)
		}
		if containsCanary(r.fmtd) {
			t.Fatalf("CANARY LEAK in value: %s", r.fmtd)
		}
		// oracle (a) bounded-memory sanity backstop (clamp is the real guarantee).
		if d := ms1.TotalAlloc - ms0.TotalAlloc; d > 32<<20 {
			t.Fatalf("alloc delta %d exceeds bound for %d body bytes", d, len(body))
		}
	case <-time.After(callWallBound + 2*time.Second):
		t.Fatalf("driver interaction did not return within bound (mode=%d opSel=%d lenMode=%d)", mode, opSel, lenMode)
	}
}

func FuzzMongoReply(f *testing.F) {
	// valid-ish exchanges
	validHello, _ := bson.Marshal(cannedHelloDoc())
	helloBody := append([]byte{0, 0, 0, 0, 0}, validHello...) // flagBits + kind0 + doc
	f.Add(uint8(0), uint8(0), uint8(0), uint8(0), helloBody)  // fuzz hello = valid hello
	f.Add(uint8(1), uint8(0), uint8(0), uint8(0), []byte{})   // canned hello then empty
	f.Add(uint8(1), uint8(0), uint8(0), uint8(1), helloBody)  // canned hello then a doc

	// error-document echo (class c)
	errDoc, _ := bson.Marshal(bson.D{{Key: "ok", Value: int32(0)}, {Key: "errmsg", Value: "auth failed: bad things"}, {Key: "code", Value: int32(18)}})
	f.Add(uint8(1), uint8(0), uint8(0), uint8(0), append([]byte{0, 0, 0, 0, 0}, errDoc...))

	// known-bad shapes
	f.Add(uint8(0), uint8(0), uint8(1), uint8(0), []byte{0, 0, 0, 0, 0})              // declared len >> sent
	f.Add(uint8(0), uint8(0), uint8(2), uint8(0), []byte{0, 0, 0, 0, 0})              // declared header-only
	f.Add(uint8(0), uint8(1), uint8(0), uint8(0), []byte{1, 2, 3, 4})                 // OP_REPLY opcode, garbage
	f.Add(uint8(0), uint8(9), uint8(0), uint8(0), []byte{1, 2, 3, 4})                 // garbage opcode
	f.Add(uint8(0), uint8(0), uint8(0), uint8(0), []byte{})                           // empty body
	f.Add(uint8(0), uint8(0), uint8(0), uint8(0), []byte{5, 0, 0, 0, 0})              // minimal empty BSON doc fragment
	f.Add(uint8(0), uint8(0), uint8(0), uint8(0), []byte{0, 0, 0, 0, 0, 0xff, 0, 0, 0}) // bad BSON length

	f.Fuzz(func(t *testing.T, mode, opSel, lenMode, driveMode uint8, body []byte) {
		if len(body) > maxWireLen {
			body = body[:maxWireLen]
		}
		runInteraction(t, mode, opSel, lenMode, driveMode, body)
	})
}
