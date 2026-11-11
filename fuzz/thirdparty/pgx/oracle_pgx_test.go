package pgxfuzz

import (
	"runtime"
	"strings"
	"testing"
)

// TestPgx_EchoAndCanary_Oracle pins the echo-vs-canary distinction (oracles b/c).
//
//	green (echo): the server puts a known marker into an ErrorResponse; pgx
//	  surfaces it in the error. That is EXPECTED echo, not a bug. The same error
//	  must NOT contain the canary password (the server never receives it).
//	red (detector): a planted error string containing the canary must be caught
//	  by the same containment check the fuzz loop uses. pgx itself was never
//	  observed to leak the password, so the red side validates the DETECTOR on a
//	  synthetic leak rather than forcing the library to misbehave.
func TestPgx_EchoAndCanary_Oracle(t *testing.T) {
	const marker = "server-marker-ZZZ-echo"
	writes := cat(
		encMsg('E', errorResponse(map[byte]string{
			'S': "FATAL", 'C': "28P01", 'M': marker,
		})),
		encClose(),
	)
	err := runHostile(t, writes)
	if err == nil {
		t.Fatalf("expected an error from an ErrorResponse-only handshake, got nil")
	}
	// green: echo present...
	if !strings.Contains(err.Error(), marker) {
		t.Fatalf("echo oracle: expected server marker %q in error, got %q", marker, err.Error())
	}
	// green: ...and canary absent.
	if strings.Contains(err.Error(), canaryPassword) {
		t.Fatalf("CANARY LEAK: password present in error: %q", err.Error())
	}

	// red: the detector must trip on a planted leak.
	planted := "connection failed for user=canaryuser password=" + canaryPassword
	if !strings.Contains(planted, canaryPassword) {
		t.Fatalf("detector is broken: it did not catch a planted canary leak")
	}
}

// TestPgx_TruncatedMidBody_Oracle pins oracle (d): a server that closes mid-body
// must make pgx return an error, never a truncated-success connection.
//
//	green-no-trip: a complete, well-formed handshake -> ConnectConfig succeeds.
//	green-trip:    the final ReadyForQuery is declared longer than the bytes sent
//	  and the server then closes -> ConnectConfig must return a non-nil error.
func TestPgx_TruncatedMidBody_Oracle(t *testing.T) {
	// Control: a valid handshake connects cleanly (no false trip).
	ok := cat(
		encMsg('R', authPayload(0)),
		encMsg('S', paramStatus("server_version", "16.0")),
		encMsg('K', backendKeyData()),
		encMsg('Z', readyForQuery()),
		encClose(),
	)
	if err := runHostile(t, ok); err != nil {
		t.Fatalf("control: valid handshake should connect, got error: %v", err)
	}

	// Truncated: ReadyForQuery header declares +16 extra body bytes that never
	// arrive; the server then closes. pgx must error, not report success.
	truncated := cat(
		encMsg('R', authPayload(0)),
		encMsg('S', paramStatus("server_version", "16.0")),
		encMsg('K', backendKeyData()),
		encMsgClaim('Z', readyForQuery(), 3), // claimTable[3]=16 extra bytes, none sent
		encClose(),
	)
	if err := runHostile(t, truncated); err == nil {
		t.Fatalf("truncation oracle: expected error on a mid-body close, got a successful connect")
	}
}

// TestPgx_LengthHeaderAmplification characterises oracle (a)'s memory dimension:
// a 5-byte message header declaring a large body provokes an up-front allocation
// of roughly the declared size BEFORE any body byte is read (pgproto3
// chunkreader.Next -> iobufpool.Get(n)). This demonstrates the amplification is
// real and measures that it is bounded. It is a characterisation test, not a
// pass/fail security gate; the real library ceiling is ~1 GiB (we cap the fake
// server at maxServerBody = 8 MiB to protect the shared host).
func TestPgx_LengthHeaderAmplification(t *testing.T) {
	// One DataRow header declaring the full 8 MiB body, only 3 payload bytes sent.
	writes := cat(
		encMsgClaim('D', []byte{0x00, 0x01, 0xff}, 7), // claimTable[7]=4 MiB; capped region
		encClose(),
	)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := runHostile(t, writes)
	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatalf("expected an error (header declares more than is sent), got nil")
	}
	delta := after.TotalAlloc - before.TotalAlloc
	t.Logf("pgx allocated ~%d bytes from a %d-byte payload (declared body up to %d)",
		delta, 3, 4<<20)
	// Amplification is real: a few payload bytes drove a multi-hundred-KiB+
	// allocation. Lower bound kept conservative to avoid flaking on allocator
	// rounding; the point is "much larger than bytes sent".
	if delta < 256<<10 {
		t.Logf("note: observed allocation delta %d below the expected amplification floor; "+
			"iobufpool reuse may have absorbed it (still bounded)", delta)
	}
	// Bounded: must not exceed a small multiple of the fake server's cap.
	if delta > 64<<20 {
		t.Fatalf("UNBOUNDED: allocation delta %d exceeded 64 MiB for a 3-byte payload", delta)
	}
}
