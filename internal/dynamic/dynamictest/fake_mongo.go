package dynamictest

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// FakeMongo is a minimal MongoDB server for driving the real driver in tests. It
// answers the handshake and every command with ok:1, and records the users named
// by dropUser and createUser commands. It speaks no authentication, so test URIs
// carry no credentials. Plain TCP only.
type FakeMongo struct {
	Addr string

	mu      sync.Mutex
	dropped []string
	created []string
}

// StartFakeMongo starts a FakeMongo on a loopback port until the test ends.
func StartFakeMongo(t *testing.T) *FakeMongo {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake mongo listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f := &FakeMongo{Addr: l.Addr().String()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

// Dropped returns the users dropped so far.
func (f *FakeMongo) Dropped() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dropped...)
}

// Created returns the users created so far.
func (f *FakeMongo) Created() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.created...)
}

const (
	mongoOpReply = 1
	mongoOpQuery = 2004
	mongoOpMsg   = 2013
)

func (f *FakeMongo) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	for {
		header := make([]byte, 16)
		if _, err := io.ReadFull(c, header); err != nil {
			return
		}
		size := int(binary.LittleEndian.Uint32(header))
		if size < 16 || size > 1<<24 {
			return
		}
		body := make([]byte, size-16)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		requestID := binary.LittleEndian.Uint32(header[4:])
		switch binary.LittleEndian.Uint32(header[12:]) {
		case mongoOpQuery:
			// flags, then a NUL-terminated collection name, skip and limit, then the document.
			rest := body[4:]
			for len(rest) > 0 && rest[0] != 0 {
				rest = rest[1:]
			}
			if len(rest) < 9 {
				return
			}
			if !writeMongoReply(c, requestID, f.answer(bson.Raw(rest[9:]))) {
				return
			}
		case mongoOpMsg:
			// flags, then a kind-0 section holding the command document.
			if len(body) < 5 || body[4] != 0 {
				return
			}
			if !writeMongoMsg(c, requestID, f.answer(bson.Raw(body[5:]))) {
				return
			}
		default:
			return
		}
	}
}

func (f *FakeMongo) answer(cmd bson.Raw) []byte {
	elems, _ := cmd.Elements()
	var name string
	if len(elems) > 0 {
		name = elems[0].Key()
	}
	f.mu.Lock()
	switch name {
	case "dropUser":
		f.dropped = append(f.dropped, cmd.Lookup("dropUser").StringValue())
	case "createUser":
		f.created = append(f.created, cmd.Lookup("createUser").StringValue())
	}
	f.mu.Unlock()
	doc := bson.D{{Key: "ok", Value: 1.0}}
	switch name {
	case "hello", "isMaster", "ismaster":
		doc = append(doc,
			bson.E{Key: "isWritablePrimary", Value: true},
			bson.E{Key: "ismaster", Value: true},
			bson.E{Key: "minWireVersion", Value: int32(0)},
			bson.E{Key: "maxWireVersion", Value: int32(25)},
			bson.E{Key: "maxBsonObjectSize", Value: int32(16 * 1024 * 1024)},
			bson.E{Key: "maxMessageSizeBytes", Value: int32(48000000)},
			bson.E{Key: "maxWriteBatchSize", Value: int32(100000)},
		)
	}
	out, err := bson.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return out
}

func mongoHeader(size int, responseTo uint32, op uint32) []byte {
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h, uint32(size))
	binary.LittleEndian.PutUint32(h[8:], responseTo)
	binary.LittleEndian.PutUint32(h[12:], op)
	return h
}

func writeMongoReply(c net.Conn, responseTo uint32, doc []byte) bool {
	// responseFlags, cursorID, startingFrom, numberReturned.
	prefix := make([]byte, 20)
	binary.LittleEndian.PutUint32(prefix[16:], 1)
	msg := append(mongoHeader(16+len(prefix)+len(doc), responseTo, mongoOpReply), prefix...)
	_, err := c.Write(append(msg, doc...))
	return err == nil
}

func writeMongoMsg(c net.Conn, responseTo uint32, doc []byte) bool {
	// flagBits, then a kind-0 section.
	prefix := []byte{0, 0, 0, 0, 0}
	msg := append(mongoHeader(16+len(prefix)+len(doc), responseTo, mongoOpMsg), prefix...)
	_, err := c.Write(append(msg, doc...))
	return err == nil
}
