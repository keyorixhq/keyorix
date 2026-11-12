package mysqlfuzz

import (
	"errors"
	"strings"
	"testing"
)

// Red/green pins for FuzzMySQLHostileQuery's oracles. Each oracle fires on a
// planted violation (red) and stays quiet on a valid exchange (green), so a
// green fuzz run means something.

// TestMySQLQuery_SeedsAreGreen: every valid seed passes every oracle, and the
// two "valid" seeds really decode a row (so the harness reaches the row parsers
// rather than dying at the handshake). A panic on any seed is a bug in the seed
// layout, not a finding — the crashing shapes live only in the reproducer tests.
func TestMySQLQuery_SeedsAreGreen(t *testing.T) {
	for i, s := range mysqlQuerySeeds() {
		o, alloc := runHostileQuery(t, s)
		if pe, ok := errors.AsType[*panicErr](o.err); ok {
			t.Fatalf("seed %d: panicked (seed layout bug): %v\n%s", i, pe.val, pe.stack)
		}
		if errors.Is(o.err, errLibraryHang) {
			t.Fatalf("seed %d: hang", i)
		}
		if leak := checkQueryCanary(s, o); leak != "" {
			t.Fatalf("seed %d: canary oracle fired on a valid exchange: %s", i, leak)
		}
		if alloc > queryAllocBudget {
			t.Fatalf("seed %d: alloc oracle fired: %d", i, alloc)
		}
		t.Logf("seed %d: err=%v rendered=%.80q", i, o.err, o.rendered.String())
	}

	// The two valid seeds must decode their row value.
	o, _ := runHostileQuery(t, mysqlQuerySeeds()[0]) // valid binary
	if o.err != nil || !strings.Contains(o.rendered.String(), "ok-binary") {
		t.Fatalf("valid binary seed did not decode a row: err=%v rendered=%q", o.err, o.rendered.String())
	}
	o, _ = runHostileQuery(t, mysqlQuerySeeds()[1]) // valid text
	if o.err != nil || !strings.Contains(o.rendered.String(), "ok-text") {
		t.Fatalf("valid text seed did not decode a row: err=%v rendered=%q", o.err, o.rendered.String())
	}
}

// TestMySQLQuery_CanaryOracle_RedGreen: the detector scans decoded values and
// errors. Red: a server returns the canary in a row value, scanned as if the
// input had NOT carried it -> leak reported. Green: the same outcome with the
// real input -> echo.
func TestMySQLQuery_CanaryOracle_RedGreen(t *testing.T) {
	// A text query returning the canary as a row value.
	in := cat([]byte{byte(opTextQuery)}, textQueryGroup(canaryPassword))
	o, _ := runHostileQuery(t, in)
	if leak := checkQueryCanary([]byte{byte(opTextQuery)}, o); leak == "" {
		t.Fatalf("RED expected: canary in a decoded value must be detected; rendered=%q", o.rendered.String())
	}
	if leak := checkQueryCanary(in, o); leak != "" {
		t.Fatalf("GREEN expected: server-supplied canary bytes are echo, got %s", leak)
	}
}

// TestMySQLQuery_EchoIsNotCanary: server ERR text surfaces in the error
// (expected echo, class c) and is not a canary leak.
func TestMySQLQuery_EchoIsNotCanary(t *testing.T) {
	const marker = "ECHO-MARKER-QRY-31"
	in := cat([]byte{byte(opTextQuery)}, encQPkt(1, errPayload(1064, "42000", marker)))
	o, _ := runHostileQuery(t, in)
	if o.err == nil || !strings.Contains(o.err.Error(), marker) {
		t.Fatalf("expected server text echoed in the error, got %v", o.err)
	}
	if leak := checkQueryCanary(in, o); leak != "" {
		t.Fatalf("echo misclassified as leak: %s", leak)
	}
}

// TestMySQLQuery_TruncatedRow_Oracle: a server that declares a text row body
// longer than it sends and then closes must make the driver error, not report a
// truncated row as success. Green control: the same exchange, untruncated,
// decodes the row with no error.
func TestMySQLQuery_TruncatedRow_Oracle(t *testing.T) {
	for range 3 {
		// Truncated: header + col-def + EOF + a row packet that declares +16
		// body bytes that never arrive, then close.
		bad := cat([]byte{byte(opTextQuery)},
			encQPkt(1, resultHeaderBody(1)),
			encQPkt(2, columnDefBody("c", fieldTypeStringType)),
			encQPkt(3, eofBody()),
			encQPktClaim(4, textRowBody("partial"), 3))
		o, _ := runHostileQuery(t, bad)
		if o.err == nil {
			t.Fatalf("truncated row produced success; rendered=%q", o.rendered.String())
		}
		if pe, ok := errors.AsType[*panicErr](o.err); ok {
			t.Fatalf("truncated row panicked instead of erroring: %v\n%s", pe.val, pe.stack)
		}

		good := cat([]byte{byte(opTextQuery)}, textQueryGroup("partial"))
		o, _ = runHostileQuery(t, good)
		if o.err != nil || !strings.Contains(o.rendered.String(), "partial") {
			t.Fatalf("green control failed: err=%v rendered=%q", o.err, o.rendered.String())
		}
	}
}
