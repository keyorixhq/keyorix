package pgxfuzz

import (
	"strings"
	"testing"
)

// Red/green pins for FuzzPgxHostileQuery's oracles. Each oracle is shown to
// fire on a planted violation (red) and to stay quiet on a valid exchange
// (green), so a green fuzz run means something.

// TestPgxQuery_SeedsAreGreen: every valid seed exchange passes every oracle, and
// the valid simple-query seed really decodes rows (so the harness reaches the
// decoders rather than dying at the handshake).
func TestPgxQuery_SeedsAreGreen(t *testing.T) {
	for i, s := range pgxQuerySeeds() {
		o, alloc := runHostileQuery(t, s)
		if leak := checkQueryCanary(s, o); leak != "" {
			t.Fatalf("seed %d: canary oracle fired on a valid exchange: %s", i, leak)
		}
		if alloc > allocBudget {
			t.Fatalf("seed %d: alloc oracle fired: %d", i, alloc)
		}
		if o.connectErr != nil {
			t.Fatalf("seed %d: fixed handshake must always connect, got %v", i, o.connectErr)
		}
		// A write failure means the fake server hung up before the client sent
		// its query: the scripted bytes were never parsed (harness bug, not a
		// result).
		if o.opErr != nil && strings.Contains(o.opErr.Error(), "write failed") {
			t.Fatalf("seed %d: harness closed before the query was sent: %v", i, o.opErr)
		}
		t.Logf("seed %d: opErr=%v rendered=%.120q", i, o.opErr, o.rendered.String())
	}
	o, _ := runHostileQuery(t, pgxQuerySeeds()[0])
	if o.opErr != nil || !strings.Contains(o.rendered.String(), "hello") || !strings.Contains(o.rendered.String(), "SELECT 2") {
		t.Fatalf("simple-query seed did not decode rows: err=%v rendered=%q", o.opErr, o.rendered.String())
	}
}

// TestPgxQuery_CanaryOracle_RedGreen: the detector scans decoded values and
// errors. Red: a server that returns the canary in a DataRow, scanned as if the
// input had NOT contained it (i.e. as if the client had injected it) -> leak
// reported. Green: the same outcome with the real input -> classified as echo.
func TestPgxQuery_CanaryOracle_RedGreen(t *testing.T) {
	in := append([]byte{byte(opSimpleQuery)}, cat(
		encMsg('T', rowDescription(fieldDesc{"a", oidText, 0})),
		encMsg('D', dataRow([]byte(canaryPassword))),
		encMsg('C', cstr("SELECT 1")), encMsg('Z', readyForQuery()), encClose())...)
	o, _ := runHostileQuery(t, in)
	if leak := checkQueryCanary([]byte{byte(opSimpleQuery)}, o); leak == "" {
		t.Fatalf("RED expected: canary in a decoded value must be detected; rendered=%q", o.rendered.String())
	}
	if leak := checkQueryCanary(in, o); leak != "" {
		t.Fatalf("GREEN expected: server-supplied canary bytes are echo, got %s", leak)
	}

	// Same red on the typed-scan path (pins that scanned pointees, not pointer
	// addresses, are what gets rendered).
	in[0] = byte(opTypedScan)
	o, _ = runHostileQuery(t, in)
	if leak := checkQueryCanary([]byte{byte(opTypedScan)}, o); leak == "" {
		t.Fatalf("RED expected on typed-scan path; rendered=%.200q", o.rendered.String())
	}

	inErr := append([]byte{byte(opSimpleQuery)}, cat(
		encMsg('E', errorResponse(map[byte]string{'S': "ERROR", 'C': "XX000", 'M': canaryPassword})), encMsg('Z', readyForQuery()), encClose())...)
	o, _ = runHostileQuery(t, inErr)
	if leak := checkQueryCanary(nil, o); !strings.HasPrefix(leak, "error: ") {
		t.Fatalf("RED expected: canary in an op error must be detected, got %q (err=%v)", leak, o.opErr)
	}
}

// TestPgxQuery_EchoIsNotCanary: server ErrorResponse text surfaces in the error
// (expected echo, class c) and is not a canary leak.
func TestPgxQuery_EchoIsNotCanary(t *testing.T) {
	in := append([]byte{byte(opExecModeQuery)}, cat(
		encMsg('E', errorResponse(map[byte]string{'S': "ERROR", 'C': "42P01", 'M': "ECHO-MARKER-77"})),
		encMsg('Z', readyForQuery()), encClose())...)
	o, _ := runHostileQuery(t, in)
	if o.opErr == nil || !strings.Contains(o.opErr.Error(), "ECHO-MARKER-77") {
		t.Fatalf("expected server text echoed in the error, got %v", o.opErr)
	}
	if leak := checkQueryCanary(in, o); leak != "" {
		t.Fatalf("echo misclassified as leak: %s", leak)
	}
}

// TestPgxQuery_TruncatedDataRow_Oracle: a server that declares a DataRow body
// longer than it sends and then closes must surface an error from the query
// (red would be: rows iterate to completion with rows.Err()==nil). Green
// control: the same exchange without truncation completes with no error.
func TestPgxQuery_TruncatedDataRow_Oracle(t *testing.T) {
	fields := encMsg('T', rowDescription(fieldDesc{"a", oidText, 0}))
	row := dataRow([]byte("partial"))
	for range 3 {
		bad := append([]byte{byte(opSimpleQuery)}, cat(fields, encMsgClaim('D', row, 4), encClose())...)
		o, _ := runHostileQuery(t, bad)
		if o.opErr == nil {
			t.Fatalf("truncated DataRow produced success; rendered=%q", o.rendered.String())
		}
		good := append([]byte{byte(opSimpleQuery)}, cat(fields, encMsg('D', row), encMsg('C', cstr("SELECT 1")), encMsg('Z', readyForQuery()), encClose())...)
		o, _ = runHostileQuery(t, good)
		if o.opErr != nil || !strings.Contains(o.rendered.String(), "partial") {
			t.Fatalf("green control failed: err=%v rendered=%q", o.opErr, o.rendered.String())
		}
	}
}

// TestPgxQuery_AllocMeterSeesRealAllocation: the alloc oracle's meter is live.
// A CopyData declaring a 4 MiB body (claim 7) from a 1-byte payload must
// register >= 4 MiB of TotalAlloc growth; a small valid exchange must not. If
// the meter read zero, the budget check could never fire.
func TestPgxQuery_AllocMeterSeesRealAllocation(t *testing.T) {
	big := append([]byte{byte(opCopyTo)}, cat(encMsg('H', copyResponse(1)), encMsgClaim('d', []byte("x"), 7), encClose())...)
	_, allocBig := runHostileQuery(t, big)
	if allocBig < 4<<20 {
		t.Fatalf("meter did not see the 4 MiB up-front allocation: %d", allocBig)
	}
	_, allocSmall := runHostileQuery(t, pgxQuerySeeds()[5])
	if allocSmall >= 4<<20 || allocSmall >= allocBudget {
		t.Fatalf("small exchange allocated %d", allocSmall)
	}
}
