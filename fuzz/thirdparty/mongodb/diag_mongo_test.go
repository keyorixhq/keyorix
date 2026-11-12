package mongofuzz

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// helloDoc builds a minimal valid MongoDB handshake reply body. maxWireVersion
// must be high enough for the v2 driver to accept the server.
func helloDoc() []byte {
	b, _ := bson.Marshal(bson.D{
		{Key: "ok", Value: 1.0},
		{Key: "isWritablePrimary", Value: true},
		{Key: "ismaster", Value: true},
		{Key: "maxWireVersion", Value: int32(21)},
		{Key: "minWireVersion", Value: int32(0)},
		{Key: "maxBsonObjectSize", Value: int32(16 * 1024 * 1024)},
		{Key: "maxMessageSizeBytes", Value: int32(48000000)},
		{Key: "maxWriteBatchSize", Value: int32(100000)},
		{Key: "logicalSessionTimeoutMinutes", Value: int32(30)},
		{Key: "connectionId", Value: int32(1)},
		{Key: "localTime", Value: bson.NewDateTimeFromTime(time.Unix(0, 0))},
	})
	return b
}

// opMsgReply frames a body document as an OP_MSG (opcode 2013) reply to the
// given responseTo request id. Section kind 0 (body), flags 0.
func opMsgReply(responseTo int32, body []byte) []byte {
	const opMsg = 2013
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[4:8], 0)                 // requestID
	binary.LittleEndian.PutUint32(out[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(out[12:16], opMsg)
	out = binary.LittleEndian.AppendUint32(out, 0) // flagBits
	out = append(out, 0x00)                         // section kind 0: body
	out = append(out, body...)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(out))) // messageLength
	return out
}

// opReplyReply frames a body document as an OP_REPLY (opcode 1) to responseTo —
// the legacy reply shape the driver expects for its initial OP_QUERY isMaster.
func opReplyReply(responseTo int32, body []byte) []byte {
	const opReply = 1
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(out[12:16], opReply)
	out = binary.LittleEndian.AppendUint32(out, 0)  // responseFlags
	out = binary.LittleEndian.AppendUint64(out, 0)  // cursorID
	out = binary.LittleEndian.AppendUint32(out, 0)  // startingFrom
	out = binary.LittleEndian.AppendUint32(out, 1)  // numberReturned
	out = append(out, body...)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(out)))
	return out
}

// replyFor builds the correct reply shape for the client's opcode.
func replyFor(opcode, responseTo int32, body []byte) []byte {
	if opcode == 2004 { // OP_QUERY -> OP_REPLY
		return opReplyReply(responseTo, body)
	}
	return opMsgReply(responseTo, body) // OP_MSG -> OP_MSG
}

// readWireMessage reads one wire message and returns the client's requestID,
// opcode and body (everything after the 16-byte header).
func readWireMessage(c net.Conn) (reqID, opcode int32, body []byte, ok bool) {
	var hdr [16]byte
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := readFull(c, hdr[:]); err != nil {
		return 0, 0, nil, false
	}
	msgLen := int(binary.LittleEndian.Uint32(hdr[0:4]))
	reqID = int32(binary.LittleEndian.Uint32(hdr[4:8]))
	opcode = int32(binary.LittleEndian.Uint32(hdr[12:16]))
	if msgLen > 16 && msgLen < 1<<24 {
		body = make([]byte, msgLen-16)
		if _, err := readFull(c, body); err != nil {
			return reqID, opcode, body, true
		}
	}
	return reqID, opcode, body, true
}

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// TestMongo_HandshakeSpike confirms a canned valid hello reply satisfies the
// driver's handshake so client.Ping succeeds — the precondition for streaming
// fuzz-controlled replies afterwards.
func TestMongo_HandshakeSpike(t *testing.T) {
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
					t.Logf("client msg: reqID=%d opcode=%d bodylen=%d", reqID, opcode, len(body))
					_ = c.SetWriteDeadline(time.Now().Add(time.Second))
					if _, err := c.Write(replyFor(opcode, reqID, hello)); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	opts := options.Client().ApplyURI("mongodb://" + ln.Addr().String() + "/?directConnection=true&serverSelectionTimeoutMS=2000&connectTimeoutMS=2000")
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = client.Ping(ctx, nil)
	t.Logf("Ping -> %v", err)
	if err != nil {
		t.Fatalf("handshake spike: Ping should succeed against a canned hello, got %v", err)
	}
}
