package wirefuzz

// FuzzWireHTTP2 drives the REAL gRPC server's HTTP/2 framing layer (golang.org/x/
// net/http2, as embedded in google.golang.org/grpc) with a fuzz-controlled sequence
// of raw frames after a valid client preface + SETTINGS: HEADERS with pseudo-header
// abuse (missing/duplicate/out-of-order/injected :method/:path/:authority),
// CONTINUATION chains, DATA frames with lengths that disagree with content-length,
// RST_STREAM floods, SETTINGS abuse, PRIORITY cycles, and WINDOW_UPDATE storms.
//
// ORACLES (and what each does NOT verify):
//
//	(1) LIVENESS/BOUNDED — the whole exchange must not panic the server process
//	    (an unrecovered panic in the framing goroutine crashes `go test`, failing
//	    the fuzz), must finish within a 10s watchdog, and must not blow a fixed heap-
//	    allocation cap (evalAlloc). DOES NOT verify: CPU, goroutine/fd leaks; nor does
//	    it distinguish a graceful GOAWAY from a silent drop.
//
//	(2) AUTHZ/LEAK INVARIANCE, PER STREAM — a seeded secret's plaintext must never
//	    appear on a stream unless the credential sent on THAT stream's HEADERS is
//	    authorized to read it (evalH2Leak). The driver keeps the connection open until
//	    the response is complete (no half-close: see oracles_test.go), and it can send
//	    a properly length-prefixed GetSecretRequest for either secret on the last
//	    opened stream, so an authorized read and a cross-tenant read are both
//	    reachable; TestAntiVacuity_HTTP2 proves it. DOES NOT verify: protobuf-field
//	    correctness, or leaks that are not the literal seeded plaintext (e.g. an
//	    encrypted blob).
//
//	(3) POST-ABUSE HEALTH — a fresh HTTP/2 connection must still be served a real
//	    (unauthenticated) RPC after the abusive frame sequence.
//
// NOT AN ORACLE HERE: the HTTP/1 "N requests ⇒ at most N handler invocations"
// smuggling count. HTTP/2 stream multiplexing is managed by the grpc transport, not
// a recording middleware we can wrap, so this target is a robustness + leak fuzzer,
// not a request-count smuggling detector. That gap is stated in the report.
//
// RED-PROOFS: oracle_redproof_test.go (predicates, planted-leak twin) and
// anti_vacuity_test.go (TestAntiVacuity_HTTP2: the driver reaches an authorized read).

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func FuzzWireHTTP2(f *testing.F) {
	w := buildGRPCWorld(f)

	// Seeds: a valid gRPC-shaped request, pseudo-header abuse, CONTINUATION, flood.
	f.Add([]byte{0, 0, 0})       // minimal: one HEADERS, no creds
	f.Add([]byte{1, 0, 0})       // HEADERS + DATA
	f.Add([]byte{2, 0, 0, 2, 0}) // HEADERS + RST flood
	f.Add([]byte{3, 0, 0})       // CONTINUATION chain
	f.Add([]byte{4, 0, 0})       // SETTINGS abuse
	f.Add([]byte{5, 0, 0})       // PRIORITY cycle
	f.Add([]byte{6, 0, 0})       // WINDOW_UPDATE storm
	// Authorized-path seeds: HEADERS(admin|reader, GetSecretValue, stream left open) then a
	// valid GetSecretRequest for secret A / B on that stream.
	f.Add([]byte{1, 0, 2, 0, 1, 1, 1, 0}) // admin reads A
	f.Add([]byte{1, 0, 2, 0, 1, 1, 1, 1}) // admin reads B
	f.Add([]byte{1, 0, 3, 0, 1, 1, 1, 1}) // reader reads B (must be denied)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		http1Mu.Lock() // serialize: shared seeded world
		defer http1Mu.Unlock()

		var res *h2Result
		var timedOut bool
		delta := measureAlloc(func() { res, timedOut = h2Drive(w, data, 10*time.Second) })

		if timedOut {
			t.Fatalf("HANG: HTTP/2 exchange exceeded watchdog for %d-byte input", len(data))
		}
		if v := evalAlloc(delta); v != "" {
			t.Fatalf("%s for %d-byte HTTP/2 input", v, len(data))
		}
		if v := evalH2Leak(res, w.s.valA, w.s.valB); v != "" {
			t.Fatalf("%s\nresp=%q", v, truncate(res.all(), 800))
		}
		// POST-ABUSE HEALTH — a fresh HTTP/2 connection must still be served after the
		// abusive frame sequence (closes the single-connection gap).
		if err := grpcHealthProbe(w.addr); err != nil {
			t.Fatalf("POST-ABUSE HEALTH: gRPC listener did not serve a fresh HTTP/2 connection after %d-byte input: %v", len(data), err)
		}
	})
}

// h2Drive performs the preface+SETTINGS handshake and then emits a fuzz-controlled
// frame sequence, reading whatever the server returns (per stream) under the watchdog.
// It returns the per-stream response, the credential sent on each stream, and whether
// the watchdog fired. It never half-closes before reading (see oracles_test.go).
func h2Drive(w *grpcWorld, data []byte, watchdog time.Duration) (res *h2Result, timedOut bool) {
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
		streamID := uint32(1)
		var lastOpen uint32 // the most recently OPENED stream (DATA must target it, not the next idle id)
		open := map[uint32]bool{}
		nFrames := int(rd.u8()%8) + 1
		for range nFrames {
			switch rd.u8() % 8 {
			case 0: // well-formed-ish HEADERS to a secret method, maybe with a credential
				authHdr, s := h2PickCred(w, rd)
				res.creds[streamID] = s
				method := []string{methodGetSecretValue, methodGetSecret, methodListSecrets}[rd.u8()%3]
				hb := encodeHeaders(grpcRequestHeaders(method, "127.0.0.1", authHdr))
				_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: hb, EndHeaders: true, EndStream: rd.u8()%2 == 0})
				open[streamID], lastOpen = true, streamID
				streamID += 2
			case 1: // DATA frame: junk (wrong length semantics) or a valid GetSecretRequest for A/B
				target := lastOpen
				if target == 0 {
					target = streamID // nothing opened yet: DATA on an idle stream is itself an abuse shape
				}
				if rd.u8()%2 == 1 {
					id := []uint32{w.s.idA, w.s.idB}[rd.u8()%2]
					_ = fr.WriteData(target, true, validGRPCMessage(id))
				} else {
					_ = fr.WriteData(target, rd.u8()%2 == 0, bytes.Repeat([]byte{rd.u8()}, int(rd.u8())))
				}
			case 2: // RST_STREAM flood
				for range int(rd.u8()%32) + 1 {
					_ = fr.WriteRSTStream(streamID, http2.ErrCode(rd.u8()))
				}
			case 3: // pseudo-header abuse + CONTINUATION chain
				hb := encodeHeaders(h2AbusiveHeaders(rd))
				// Split into HEADERS (no END_HEADERS) + CONTINUATION frames.
				mid := len(hb) / 2
				_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: hb[:mid], EndHeaders: false})
				_ = fr.WriteContinuation(streamID, true, hb[mid:])
				open[streamID], lastOpen = true, streamID
				streamID += 2
			case 4: // SETTINGS abuse (extreme values)
				_ = fr.WriteSettings(
					http2.Setting{ID: http2.SettingHeaderTableSize, Val: rd.u32()},
					http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: rd.u32()},
					http2.Setting{ID: http2.SettingInitialWindowSize, Val: rd.u32()},
					http2.Setting{ID: http2.SettingMaxFrameSize, Val: rd.u32()},
				)
			case 5: // PRIORITY (self-dependency / cycles)
				_ = fr.WritePriority(streamID, http2.PriorityParam{StreamDep: streamID, Weight: rd.u8(), Exclusive: rd.u8()%2 == 0})
			case 6: // WINDOW_UPDATE storm (incl. 0 increments, which are protocol errors)
				_ = fr.WriteWindowUpdate(rd.u32()%8, rd.u32())
			default: // PING / GOAWAY noise
				var p [8]byte
				p[0] = rd.u8()
				_ = fr.WritePing(rd.u8()%2 == 0, p)
			}
		}
		_ = fr.WriteSettingsAck()
		readH2(conn, fr, open, res)
		ch <- res
	}()
	select {
	case r := <-ch:
		return r, false
	case <-time.After(watchdog + 2*time.Second):
		return newH2Result(), true
	}
}

func h2PickCred(w *grpcWorld, rd *byteReader) (authHdr string, sent credsSent) {
	switch rd.u8() % 4 {
	case 0:
		return "", sent // none
	case 1:
		return "Bearer garbage-not-a-real-token", sent
	case 2:
		sent.admin = true
		return "Bearer " + w.s.adminTok, sent
	default:
		sent.reader = true
		return "Bearer " + w.s.readTok, sent
	}
}

// h2AbusiveHeaders builds a pseudo-header set that violates HTTP/2 rules: missing
// required pseudo-headers, a pseudo-header AFTER a regular header, duplicated
// :method/:path, and an injected CRLF-bearing value. The framing layer must reject
// these, never dispatch a secret read off them.
func h2AbusiveHeaders(rd *byteReader) []hpack.HeaderField {
	switch rd.u8() % 5 {
	case 0: // pseudo-header after a regular header (illegal ordering)
		return []hpack.HeaderField{
			{Name: "content-type", Value: "application/grpc"},
			{Name: ":method", Value: "POST"},
			{Name: ":path", Value: methodGetSecretValue},
		}
	case 1: // duplicate :path
		return []hpack.HeaderField{
			{Name: ":method", Value: "POST"},
			{Name: ":scheme", Value: "http"},
			{Name: ":path", Value: methodGetSecretValue},
			{Name: ":path", Value: methodListSecrets},
			{Name: ":authority", Value: "127.0.0.1"},
		}
	case 2: // missing :method
		return []hpack.HeaderField{
			{Name: ":scheme", Value: "http"},
			{Name: ":path", Value: methodGetSecretValue},
			{Name: ":authority", Value: "127.0.0.1"},
		}
	case 3: // unknown pseudo-header
		return []hpack.HeaderField{
			{Name: ":method", Value: "POST"},
			{Name: ":bogus", Value: "x"},
			{Name: ":path", Value: methodGetSecretValue},
		}
	default: // CRLF-injection attempt in a header value
		return []hpack.HeaderField{
			{Name: ":method", Value: "POST"},
			{Name: ":scheme", Value: "http"},
			{Name: ":path", Value: methodGetSecretValue},
			{Name: ":authority", Value: "127.0.0.1"},
			{Name: "x-evil", Value: "a\r\nx-injected: 1"},
		}
	}
}
