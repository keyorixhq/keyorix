package mongofuzz

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// docWithCanary builds an OK reply whose "value" field carries the canary.
func docWithCanary() []byte {
	b, _ := bson.Marshal(bson.D{{Key: "ok", Value: 1.0}, {Key: "value", Value: mongoCanary}})
	return opMsgBody(0, b)
}

// TestMongo_SeedsAreGreen: every seed parses with no panic, no canary leak, no
// over-budget alloc; the valid OK seed decodes its "value".
func TestMongo_SeedsAreGreen(t *testing.T) {
	for i, s := range mongoSeeds() {
		o, alloc := runHostileMongo(t, s)
		if leak := checkMongoCanary(s, o); leak != "" {
			t.Fatalf("seed %d: canary oracle fired on a valid exchange: %s", i, leak)
		}
		if alloc > mongoAllocBudget {
			t.Fatalf("seed %d: alloc oracle fired: %d", i, alloc)
		}
		t.Logf("seed %d: err=%v rendered=%.80q", i, o.err, o.rendered)
	}
	o, _ := runHostileMongo(t, mongoSeeds()[0])
	if o.err != nil || !strings.Contains(o.rendered, "fine") {
		t.Fatalf("valid OK seed did not decode: err=%v rendered=%q", o.err, o.rendered)
	}
}

// TestMongo_CanaryOracle_RedGreen.
func TestMongo_CanaryOracle_RedGreen(t *testing.T) {
	in := docWithCanary()
	o, _ := runHostileMongo(t, in)
	if leak := checkMongoCanary(nil, o); leak == "" {
		t.Fatalf("RED expected: canary in a decoded value must be detected; rendered=%q", o.rendered)
	}
	if leak := checkMongoCanary(in, o); leak != "" {
		t.Fatalf("GREEN expected: server-supplied canary bytes are echo, got %s", leak)
	}
}

// TestMongo_EchoIsNotCanary: a server errmsg surfaces in the error (echo), not a
// canary leak.
func TestMongo_EchoIsNotCanary(t *testing.T) {
	const marker = "ECHO-MARKER-MONGO-55"
	in := opMsgBody(0, errDoc(59, marker))
	o, _ := runHostileMongo(t, in)
	if o.err == nil || !strings.Contains(o.err.Error(), marker) {
		t.Fatalf("expected server errmsg echoed in the error, got %v", o.err)
	}
	if leak := checkMongoCanary(in, o); leak != "" {
		t.Fatalf("echo misclassified as leak: %s", leak)
	}
}

// TestMongo_ClampMongo: an OP_COMPRESSED wrapper declaring a huge uncompressedSize
// is lowered to the cap; a normal body is unchanged.
func TestMongo_ClampMongo(t *testing.T) {
	huge := opCompressedBody(opMSG, 0x7fffffff, 0, []byte{1, 2, 3, 4})
	got := clampMongoReply(huge)
	if binary.LittleEndian.Uint32(got[8:12]) > maxMongoReply {
		t.Fatalf("clamp did not lower uncompressedSize: %d", binary.LittleEndian.Uint32(got[8:12]))
	}
	normal := opMsgBody(0, okDoc())
	if string(clampMongoReply(normal)) != string(normal) {
		t.Fatalf("clamp altered a normal reply")
	}
}

// TestMongo_TruncatedReply_Oracle: a reply whose declared messageLength exceeds
// the bytes sent, then EOF, must make the driver error, not return a truncated
// result. Green control: the same reply honestly framed decodes.
func TestMongo_TruncatedReply_Oracle(t *testing.T) {
	for range 3 {
		if err := runMongoTruncation(t, opMsgBody(0, okDoc()), true); err == nil {
			t.Fatalf("truncated wire message produced success")
		}
		if err := runMongoTruncation(t, opMsgBody(0, okDoc()), false); err != nil {
			t.Fatalf("green control: honest reply should decode, got %v", err)
		}
	}
}

// runMongoTruncation drives one RunCommand; the server frames the fuzz body with
// the given truncation flag.
func runMongoTruncation(t *testing.T, fuzzBody []byte, truncate bool) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = ln.Close() }()
	hello := helloDoc()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				for {
					reqID, opcode, body, ok := readWireMessage(c)
					if !ok {
						return
					}
					_ = c.SetWriteDeadline(time.Now().Add(time.Second))
					if strings.Contains(string(body), mongoMarkerCmd) {
						_, _ = c.Write(frameFuzzReply(reqID, fuzzBody, truncate))
						time.Sleep(20 * time.Millisecond)
						return
					}
					if _, err := c.Write(replyFor(opcode, reqID, hello)); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	opts := options.Client().ApplyURI("mongodb://" + ln.Addr().String() +
		"/?directConnection=true&serverSelectionTimeoutMS=2000&connectTimeoutMS=2000&socketTimeoutMS=1500")
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	var res bson.M
	return client.Database("admin").RunCommand(ctx, bson.D{{Key: mongoMarkerCmd, Value: 1}}).Decode(&res)
}
