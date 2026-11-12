package wirefuzz

// FuzzWireGRPCFraming attacks the gRPC MESSAGE framing on top of a valid HTTP/2
// stream to the real gRPC server: the 5-byte length-prefix (1 compression flag + 4
// big-endian length) that delimits each gRPC message inside DATA frames. It fuzzes
// bad declared lengths (longer than the payload, or a 4 GiB claim), the compressed
// flag set without a grpc-encoding header, truncated messages, multiple messages in
// one DATA frame, trailing junk, oversized payloads, and a mismatched content-type.
//
// ORACLES (and what each does NOT verify):
//
//	(1) LIVENESS/BOUNDED — the exchange must not panic the server process, must
//	    finish within a 10s watchdog, and must not blow a fixed heap-allocation cap.
//	    In particular a 4 GiB length prefix must NOT cause the server to pre-allocate
//	    a 4 GiB buffer (the MaxRecvMsgSize guard must bound it). DOES NOT verify: CPU,
//	    goroutine/fd leaks, or subsequent-connection health.
//
//	(2) AUTHZ/LEAK INVARIANCE — a seeded secret's plaintext must never appear in the
//	    returned bytes unless an authorizing credential rode a HEADERS frame. DOES
//	    NOT verify: positive reachability or protobuf-field correctness.
//
// NOT AN ORACLE HERE: handler-invocation smuggling count (see FuzzWireHTTP2's note).
//
// RED-PROOFS: scripts/fuzzing/wire-redproof (scratch, never committed).

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func FuzzWireGRPCFraming(f *testing.F) {
	w := buildGRPCWorld(f)

	f.Add([]byte{0, 0, 0, 0}) // one empty message, no cred
	f.Add([]byte{1, 0, 0, 0}) // compressed flag set, no encoding header
	f.Add([]byte{2, 0, 0, 0}) // huge declared length (DoS pre-alloc probe)
	f.Add([]byte{3, 0, 0, 0}) // truncated message
	f.Add([]byte{4, 0, 0, 0}) // multiple messages + trailing junk
	f.Add([]byte{0, 2, 0, 0}) // with admin credential
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		http1Mu.Lock()
		defer http1Mu.Unlock()

		runtime.GC()
		var m0 runtime.MemStats
		runtime.ReadMemStats(&m0)

		resp, sent, timedOut := grpcFramingDrive(w, data, 10*time.Second)

		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)

		if timedOut {
			t.Fatalf("HANG: gRPC framing exchange exceeded watchdog for %d-byte input", len(data))
		}
		const allocCap = 512 << 20
		if d := heapDelta(m0, m1); d > allocCap {
			t.Fatalf("UNBOUNDED ALLOC: heap grew %d bytes for %d-byte gRPC input (cap %d) — a length-prefix DoS?", d, len(data), allocCap)
		}
		if bytes.Contains(resp, []byte(w.s.valB)) && !sent.admin {
			t.Fatalf("LEAK: secret B plaintext in gRPC response without admin credential\nresp=%q", truncate(resp, 800))
		}
		if bytes.Contains(resp, []byte(w.s.valA)) && !sent.admin && !sent.reader {
			t.Fatalf("LEAK: secret A plaintext in gRPC response without an authorizing credential\nresp=%q", truncate(resp, 800))
		}
		// POST-ABUSE HEALTH — a fresh HTTP/2 connection must still be served after the
		// malformed gRPC message framing (closes the single-connection gap).
		if err := grpcHealthProbe(w.addr); err != nil {
			t.Fatalf("POST-ABUSE HEALTH: gRPC listener did not serve a fresh HTTP/2 connection after %d-byte input: %v", len(data), err)
		}
	})
}

// grpcMessage builds a (possibly malformed) gRPC length-prefixed message. declaredLen
// may disagree with len(payload) to exercise the framing guard.
func grpcMessage(flag byte, declaredLen uint32, payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	b[0] = flag
	binary.BigEndian.PutUint32(b[1:5], declaredLen)
	copy(b[5:], payload)
	return b
}

func grpcFramingDrive(w *grpcWorld, data []byte, watchdog time.Duration) (resp []byte, sent credsSent, timedOut bool) {
	type result struct {
		b    []byte
		sent credsSent
	}
	ch := make(chan result, 1)
	go func() {
		var sent credsSent
		conn, fr, err := h2Handshake(w.addr)
		if err != nil {
			ch <- result{nil, sent}
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(watchdog))

		rd := &byteReader{data: data}
		shape := rd.u8() % 5
		authHdr, s := h2PickCred(w, rd)
		sent = s

		// A valid HTTP/2 HEADERS for GetSecretValue; some shapes corrupt content-type.
		ct := "application/grpc"
		if shape == 4 {
			ct = "application/grpc+proto; charset=evil"
		}
		hdrs := grpcRequestHeaders(methodGetSecretValue, "127.0.0.1", authHdr)
		for i := range hdrs {
			if hdrs[i].Name == "content-type" {
				hdrs[i].Value = ct
			}
		}
		_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: encodeHeaders(hdrs), EndHeaders: true})

		var msg []byte
		payload := bytes.Repeat([]byte{rd.u8()}, int(rd.u8()))
		switch shape {
		case 0: // declared length larger than payload (truncated)
			msg = grpcMessage(rd.u8()%2, uint32(len(payload))+uint32(rd.u32()%4096), payload)
		case 1: // compressed flag set, but no grpc-encoding header was sent
			msg = grpcMessage(1, uint32(len(payload)), payload)
		case 2: // 4 GiB-ish declared length with a tiny payload (pre-alloc DoS probe)
			msg = grpcMessage(0, 0xFFFFFFFF, payload)
		case 3: // several messages concatenated + trailing junk
			msg = append(msg, grpcMessage(0, uint32(len(payload)), payload)...)
			msg = append(msg, grpcMessage(0, uint32(len(payload)), payload)...)
			msg = append(msg, bytes.Repeat([]byte{0xAB}, int(rd.u8()))...) // < 5 trailing bytes = partial prefix
		default: // valid framing but corrupt content-type (handled above)
			msg = grpcMessage(0, uint32(len(payload)), payload)
		}
		_ = fr.WriteData(1, true, msg)
		_ = fr.WriteSettingsAck()
		ch <- result{drainConn(conn), sent}
	}()
	select {
	case r := <-ch:
		return r.b, r.sent, false
	case <-time.After(watchdog + 2*time.Second):
		return nil, credsSent{}, true
	}
}
