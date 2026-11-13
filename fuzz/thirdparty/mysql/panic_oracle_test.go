package mysqlhostile

import "testing"

// Red/green proof that the panic oracle's known-class classifier is NOT a blanket
// "ignore every driver panic": it tolerates ONLY a bounds-class runtime error whose
// stack is inside the driver, and flags everything else (a different panic class, or a
// bounds panic outside the driver) as a NOVEL violation the fuzz oracle must fail on.

// boundsPanic produces a genuine runtime.Error of the bounds class.
func boundsPanic() (r any) {
	defer func() { r = recover() }()
	s := make([]int, 1)
	_ = s[5] //nolint:staticcheck // intentional out-of-range to synthesize a runtime.Error
	return
}

// nilDerefPanic produces a genuine runtime.Error of the nil-dereference class.
func nilDerefPanic() (r any) {
	defer func() { r = recover() }()
	var p *int
	_ = *p //nolint:staticcheck // intentional nil deref to synthesize a runtime.Error
	return
}

const fakeDriverStack = "goroutine 1 [running]:\n" +
	"github.com/go-sql-driver/mysql.(*mysqlConn).readHandshakePacket(...)\n\t/mod/packets.go:206\n"
const fakeHarnessStack = "goroutine 1 [running]:\n" +
	"github.com/keyorixhq/keyorix/fuzz/thirdparty/mysql.frame(...)\n\thostile_mysql_test.go:1\n"

func TestPanicOracleRedProof(t *testing.T) {
	bp := boundsPanic()
	np := nilDerefPanic()
	if bp == nil || np == nil {
		t.Fatalf("failed to synthesize runtime panics: bounds=%v nil=%v", bp, np)
	}

	// GREEN (tolerated): bounds panic inside the driver → known short-packet class.
	if !isKnownShortPacketPanic(bp, fakeDriverStack) {
		t.Errorf("bounds panic with a driver stack must be classified KNOWN (tolerated)")
	}

	// RED path 1 (must be flagged): a bounds panic whose stack is NOT in the driver —
	// e.g. a bug in the harness — must NOT be swallowed as a known upstream crash.
	if isKnownShortPacketPanic(bp, fakeHarnessStack) {
		t.Errorf("bounds panic OUTSIDE the driver must be classified NOVEL (flagged)")
	}

	// RED path 2 (must be flagged): a non-bounds panic class (nil deref) inside the
	// driver is a DIFFERENT, potentially novel defect — must NOT be tolerated.
	if isKnownShortPacketPanic(np, fakeDriverStack) {
		t.Errorf("nil-deref panic in the driver must be classified NOVEL (flagged)")
	}
}
