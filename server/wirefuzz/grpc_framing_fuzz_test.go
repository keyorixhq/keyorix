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
//	    finish within a 10s watchdog, and must not blow a fixed heap-allocation cap
//	    (evalAlloc). In particular a 4 GiB length prefix must NOT cause the server to
//	    pre-allocate a 4 GiB buffer (the MaxRecvMsgSize guard must bound it); the
//	    measurement path is watched failing in TestRedProof_Alloc_GRPCPreAlloc. DOES
//	    NOT verify: CPU, goroutine/fd leaks.
//
//	(2) AUTHZ/LEAK INVARIANCE, PER STREAM — a seeded secret's plaintext must never
//	    appear unless the credential on the stream's HEADERS is authorized to read it
//	    (evalH2Leak). Shape 5 sends a properly framed GetSecretRequest for secret A or
//	    B (the junk payloads of the other shapes can never decode to a real secret id),
//	    so an authorized and a cross-tenant read are both reachable
//	    (TestAntiVacuity_GRPCFraming). DOES NOT verify: protobuf-field correctness.
//
//	(3) POST-ABUSE HEALTH — a fresh connection must still be served a real
//	    (unauthenticated) RPC afterwards.
//
// NOT AN ORACLE HERE: handler-invocation smuggling count (see FuzzWireHTTP2's note).
//
// RED-PROOFS: oracle_redproof_test.go and anti_vacuity_test.go.

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func FuzzWireGRPCFraming(f *testing.F) {
	w := buildGRPCWorld(f)

	f.Add([]byte{0, 0, 0, 0})    // one empty message, no cred
	f.Add([]byte{1, 0, 0, 0})    // compressed flag set, no encoding header
	f.Add([]byte{2, 0, 0, 0})    // huge declared length (DoS pre-alloc probe)
	f.Add([]byte{3, 0, 0, 0})    // truncated message
	f.Add([]byte{4, 0, 0, 0})    // multiple messages + trailing junk
	f.Add([]byte{0, 2, 0, 0})    // with admin credential
	f.Add([]byte{5, 2, 0, 0, 0}) // valid GetSecretRequest for A, admin
	f.Add([]byte{5, 2, 0, 0, 1}) // valid GetSecretRequest for B, admin
	f.Add([]byte{5, 3, 0, 0, 1}) // valid GetSecretRequest for B, reader (must be denied)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		http1Mu.Lock()
		defer http1Mu.Unlock()

		var res *h2Result
		var timedOut bool
		delta := measureAlloc(func() { res, timedOut = grpcFramingDrive(w, data, 10*time.Second) })

		if timedOut {
			t.Fatalf("HANG: gRPC framing exchange exceeded watchdog for %d-byte input", len(data))
		}
		if v := evalAlloc(delta); v != "" {
			t.Fatalf("%s for %d-byte gRPC input — a length-prefix DoS?", v, len(data))
		}
		if v := evalH2Leak(res, w.s.valA, w.s.valB); v != "" {
			t.Fatalf("%s\nresp=%q", v, truncate(res.all(), 800))
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

func grpcFramingDrive(w *grpcWorld, data []byte, watchdog time.Duration) (res *h2Result, timedOut bool) {
	ch := make(chan *h2Result, 1)
	go func() {
		res := newH2Result()
		conn, fr, err := h2Handshake(w.addr)
		if err != nil {
			ch <- res
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(watchdog))

		rd := &byteReader{data: data}
		shape := rd.u8() % 6
		authHdr, s := h2PickCred(w, rd)
		res.creds[1] = s

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
		case 5: // a VALID GetSecretRequest for secret A or B (the authz-reachable shape)
			msg = validGRPCMessage([]uint32{w.s.idA, w.s.idB}[rd.u8()%2])
		default: // valid framing but corrupt content-type (handled above)
			msg = grpcMessage(0, uint32(len(payload)), payload)
		}
		_ = fr.WriteData(1, true, msg)
		_ = fr.WriteSettingsAck()
		readH2(conn, fr, map[uint32]bool{1: true}, res)
		ch <- res
	}()
	select {
	case r := <-ch:
		return r, false
	case <-time.After(watchdog + 2*time.Second):
		return newH2Result(), true
	}
}
