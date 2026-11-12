// Package mongofuzz drives the real go.mongodb.org/mongo-driver/v2 client against
// a hostile MongoDB server whose command-reply wire bytes come from the fuzz
// input, through the client's public API only (mongo.Connect + RunCommand). No
// Keyorix wrapper is in the path, so any crash is a driver bug.
//
// This is the h1 follow-up: h1 flagged OP_MSG section-length / checksum-flag
// handling, the OP_COMPRESSED wrapper, and cursor batches as the open leads. The
// fake server completes a fixed valid handshake (OP_QUERY isMaster -> OP_REPLY
// hello; OP_MSG hello -> OP_MSG hello) so the connection is usable, then streams
// a fuzz-controlled wire reply as the answer to a marker RunCommand, driving the
// driver's wiremessage/OP_MSG/OP_COMPRESSED parser.
//
// KEYORIX REACHABILITY. internal/dynamic/mongodb.go connects this driver to an
// operator-configured target MongoDB (mongo.Connect + client.Ping at
// mongodb.go:233/237, and Database.RunCommand for createUser/dropUser) to
// mint/drop short-lived accounts. A hostile/compromised target controls every
// reply byte the wire parser sees. CANDIDATE (hostile-target precondition).
//
// ORACLES (and what each does NOT verify)
//
//	(a) no panic / no hang / bounded memory. A panic fails the iteration; a
//	    watchdog bounds hangs. The whole reply is capped at maxMongoReply (64 KiB)
//	    and the OP_COMPRESSED uncompressedSize is clamped, so the loop does NOT
//	    exercise the driver's true wire ceiling (maxMessageSizeBytes, ~48 MB) nor
//	    a decompression bomb; those are bounded here for host safety. Does NOT
//	    catch a slow-but-finishing parse.
//	(b) canary: a sentinel must never appear in a returned error or the fmt of a
//	    decoded value. The credential-free client holds no admin secret (the SCRAM
//	    auth path is NOT fuzzed — it cannot be faked without the password), so this
//	    oracle proves the DETECTOR works (red/green) and guards server-echoed
//	    content, rather than a real client-held secret.
//	(c) echo: a server errmsg surfaced in an error is EXPECTED echo, not a bug.
//	(d) truncated success: a reply whose declared messageLength exceeds the bytes
//	    sent, then EOF, must make the driver error, not return a truncated result.
package mongofuzz

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	mongoCanary    = "mongo-canary-secret-7h3x2b"
	mongoMarkerCmd = "fuzzcmd"
	// maxMongoReply caps the whole fuzz-built wire reply so the driver's initial
	// bounded read cannot be driven to OOM on this shared host; section/document
	// length lies then operate within that bounded buffer (where an unguarded
	// slice is a finding, not an allocation).
	maxMongoReply = 64 << 10
	mongoAllocBudget = 96 << 20
	mongoHangBudget  = 6 * time.Second
	opMSG            = 2013
	opCOMPRESSED     = 2012
	opQUERY          = 2004
)

// clampMongoReply truncates the fuzz reply and, when it is an OP_COMPRESSED
// wrapper, lowers the declared uncompressedSize so a decompression bomb cannot
// allocate gigabytes. fuzzBody is everything from the opcode field onward.
func clampMongoReply(fuzzBody []byte) []byte {
	out := append([]byte(nil), fuzzBody...)
	if len(out) > maxMongoReply {
		out = out[:maxMongoReply]
	}
	// OP_COMPRESSED layout from the opcode: [opcode:4][originalOpcode:4]
	// [uncompressedSize:4][compressorId:1][data...]. Clamp uncompressedSize.
	if len(out) >= 12 && binary.LittleEndian.Uint32(out[0:4]) == opCOMPRESSED {
		if binary.LittleEndian.Uint32(out[8:12]) > maxMongoReply {
			binary.LittleEndian.PutUint32(out[8:12], maxMongoReply)
		}
	}
	return out
}

// frameFuzzReply prepends a wire header to the fuzz body (opcode-onward). The
// outer messageLength is set honestly to the actual byte count so the driver
// reads exactly these bytes into its bounded buffer; a hostile input exercises
// the parsing of the sections WITHIN that buffer. When wantTruncate is set the
// declared messageLength is inflated past the bytes actually sent (truncation
// oracle).
func frameFuzzReply(responseTo int32, fuzzBody []byte, wantTruncate bool) []byte {
	// Wire header is [messageLength:4][requestID:4][responseTo:4][opcode:4…]; the
	// fuzz body supplies the opcode onward, so the header prefix is 12 bytes.
	hdr := make([]byte, 12)
	binary.LittleEndian.PutUint32(hdr[4:8], 0)                  // requestID
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(responseTo)) // responseTo
	msg := append(hdr, fuzzBody...)
	total := len(msg)
	if wantTruncate {
		total += 4096 // declare more than we send
	}
	binary.LittleEndian.PutUint32(msg[0:4], uint32(total))
	return msg
}

// serveMongo runs the handshake and streams the fuzz reply to the marker command.
func serveMongo(ln net.Listener, fuzzReply []byte) {
	hello := helloDoc()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			for {
				reqID, opcode, body, ok := readWireMessage(c)
				if !ok {
					return
				}
				_ = c.SetWriteDeadline(time.Now().Add(time.Second))
				if strings.Contains(string(body), mongoMarkerCmd) {
					if _, err := c.Write(frameFuzzReply(reqID, fuzzReply, false)); err != nil {
						return
					}
					time.Sleep(20 * time.Millisecond)
					return
				}
				if _, err := c.Write(replyFor(opcode, reqID, hello)); err != nil {
					return
				}
			}
		}(c)
	}
}

type mongoOutcome struct {
	err      error
	rendered string
}

func runHostileMongo(t *testing.T, in []byte) (*mongoOutcome, uint64) {
	t.Helper()
	reply := clampMongoReply(in)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer ln.Close()
	go serveMongo(ln, reply)

	opts := options.Client().ApplyURI("mongodb://" + ln.Addr().String() +
		"/?directConnection=true&serverSelectionTimeoutMS=2000&connectTimeoutMS=2000&socketTimeoutMS=2000")
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("harness: connect: %v", err)
	}
	defer client.Disconnect(context.Background())

	out := &mongoOutcome{}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	before := ms.TotalAlloc

	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(mongoHangBudget):
			panic("mongo reply parse did not return within hang budget (possible infinite loop)")
		}
	}()
	defer close(done)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var res bson.M
	out.err = client.Database("admin").RunCommand(ctx, bson.D{{Key: mongoMarkerCmd, Value: 1}}).Decode(&res)
	out.rendered = fmt.Sprintf("%#v", res)

	runtime.ReadMemStats(&ms)
	return out, ms.TotalAlloc - before
}

func checkMongoCanary(in []byte, o *mongoOutcome) string {
	if strings.Contains(string(in), mongoCanary) {
		return "" // echo
	}
	if o.err != nil && strings.Contains(o.err.Error(), mongoCanary) {
		return "error: " + o.err.Error()
	}
	if strings.Contains(o.rendered, mongoCanary) {
		return "decoded value contains the canary"
	}
	return ""
}

func recoverStack(fn func()) (val any, stack string) {
	defer func() {
		if r := recover(); r != nil {
			val, stack = r, string(debug.Stack())
		}
	}()
	fn()
	return nil, ""
}

func FuzzMongoReply(f *testing.F) {
	for _, seed := range mongoSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var o *mongoOutcome
		var alloc uint64
		val, stack := recoverStack(func() { o, alloc = runHostileMongo(t, in) })
		if val != nil {
			t.Fatalf("PANIC in mongo reply parse: %v\n%s", val, stack)
		}
		if leak := checkMongoCanary(in, o); leak != "" {
			t.Fatalf("CANARY LEAK: %s", leak)
		}
		if alloc > mongoAllocBudget {
			t.Fatalf("AMPLIFICATION: one reply iteration allocated %d bytes from a %d-byte input (budget %d)", alloc, len(in), mongoAllocBudget)
		}
	})
}
