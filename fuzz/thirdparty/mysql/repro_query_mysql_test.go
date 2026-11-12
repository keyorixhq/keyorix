package mysqlfuzz

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Minimal, deterministic reproducers for the go-sql-driver/mysql v1.10.1
// result-set defects found by FuzzMySQLHostileQuery. Each replays 3 times and
// asserts the panic, so it stays green while the library bug exists and goes red
// the day the driver adds the missing length guard (at which point the matching
// entry in knownQueryPanicSites must be removed too).

// reproQueryPanic runs one op against a hostile result-set stream and returns
// the recovered panic value + stack (nil if the driver did not panic). It reuses
// runHostileQuery, which already captures the panic from the client goroutine.
func reproQueryPanic(t *testing.T, in []byte) (any, string) {
	t.Helper()
	o, _ := runHostileQuery(t, in)
	var pe *panicErr
	if errors.As(o.err, &pe) {
		return pe.val, pe.stack
	}
	return nil, ""
}

// MYSQL-Q1: readPrepareResultPacket (packets.go:980-986) slices a
// server-controlled COM_STMT_PREPARE OK response — data[1:5] statement-id,
// data[5:7] column-count, data[7:9] param-count — with NO check that the packet
// is at least 9 bytes long. A hostile server replying to COM_STMT_PREPARE with a
// 1-byte OK body (just the 0x00 indicator) crashes the client with
// "slice bounds out of range". Reachable through database/sql on any `?`-param
// query (Keyorix: killUserConnections).
func TestMySQLQ1_ShortPrepareOK_Reproducer(t *testing.T) {
	// opBinaryQuery -> the first response group is the COM_STMT_PREPARE reply.
	// A single packet carrying only the iOK indicator (0x00) is a valid-looking
	// but too-short prepare-OK.
	in := cat([]byte{byte(opBinaryQuery)}, encQPkt(1, []byte{0x00}))
	for i := range 3 {
		val, stack := reproQueryPanic(t, in)
		if val == nil {
			t.Fatalf("replay %d: expected panic in readPrepareResultPacket; the driver may have added the length guard (remove MYSQL-Q1 from knownQueryPanicSites)", i)
		}
		if !strings.Contains(fmt.Sprint(val), "slice bounds out of range") ||
			!strings.Contains(stack, "readPrepareResultPacket") {
			t.Fatalf("replay %d: unexpected panic %v\n%s", i, val, stack)
		}
	}
}

// MYSQL-Q2: binaryRows.readRow (packets.go:1299-1300) computes the NULL-bitmap
// size from the DECLARED column count — pos := 1 + (len(dest)+7+2)>>3 — and
// slices data[1:pos] with NO check that the row packet is that long. A hostile
// server that completes a valid COM_STMT_PREPARE/COM_STMT_EXECUTE and then sends
// a binary result row consisting of only the 0x00 indicator (no bitmap bytes)
// crashes the client with "slice bounds out of range". This is the "NULL bitmap
// that does not match the column count" shape from the brief.
func TestMySQLQ2_ShortBinaryRowNullBitmap_Reproducer(t *testing.T) {
	// Valid prepare (1 result column, 1 param), valid execute header + col-def +
	// EOF, then a 1-byte binary row (iOK only): the bitmap read data[1:2] is out
	// of range on a len-1 packet.
	executeShortRow := cat(
		encQPkt(1, resultHeaderBody(1)),
		encQPkt(2, columnDefBody("c", fieldTypeStringType)),
		encQPkt(3, eofBody()),
		encQPkt(4, []byte{0x00}),
	)
	in := cat([]byte{byte(opBinaryQuery)}, prepareGroup(1, 1), encQSep(), executeShortRow)
	for i := range 3 {
		val, stack := reproQueryPanic(t, in)
		if val == nil {
			t.Fatalf("replay %d: expected panic in binaryRows.readRow (NULL bitmap); the driver may have added the length guard (remove MYSQL-Q2 from knownQueryPanicSites)", i)
		}
		if !strings.Contains(fmt.Sprint(val), "slice bounds out of range") ||
			!strings.Contains(stack, "readRow") {
			t.Fatalf("replay %d: unexpected panic %v\n%s", i, val, stack)
		}
	}
}

// TestMySQLQuery_AllowlistStillSurfacesNovelPanics: the allowlist swallows the
// real MYSQL-Q1/Q2 stacks (green) but NOT a panic from any other site (red), so
// a third, unknown result-set panic would still fail the fuzz run.
func TestMySQLQuery_AllowlistStillSurfacesNovelPanics(t *testing.T) {
	// Known Q1 stack is recognised (swallowed).
	in := cat([]byte{byte(opBinaryQuery)}, encQPkt(1, []byte{0x00}))
	val, stack := reproQueryPanic(t, in)
	if val == nil {
		t.Fatal("MYSQL-Q1 reproducer did not panic")
	}
	if msg := classifyQueryPanic(val, stack); msg != "" {
		t.Fatalf("known MYSQL-Q1 stack not recognised by the allowlist: %s", msg)
	}
	// A planted panic from an unlisted site is NOT swallowed.
	var idx []int
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("planted panic did not fire")
		}
		if classifyQueryPanic(r, "goroutine stack with no known site") == "" {
			t.Fatal("RED expected: a panic from an unlisted site was swallowed by the allowlist")
		}
	}()
	_ = idx[1]
}
