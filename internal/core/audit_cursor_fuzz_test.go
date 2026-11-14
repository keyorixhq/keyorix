package core

// Fuzz targets for the audit-list keyset cursor codec (audit_page.go):
// EncodeAuditCursor / DecodeAuditCursor. The cursor is the `cursor=` query
// parameter of GET /audit/logs and GET /audit/search and the gRPC
// AuditService.GetAuditLogs page token — directly attacker-controlled input on
// a request path. DecodeAuditCursor is explicitly unsigned ("it has no
// authority ... only strictly parsed"), so strict, crash-free parsing is the
// whole guarantee.
//
// FuzzDecodeAuditCursor — raw request bytes:
//   ORACLE: never panics; fails closed (a cursor it does not recognise →
//   ErrInvalidAuditCursor, never a usable value); and any cursor it ACCEPTS has
//   ID>=1 and re-encodes to a cursor that decodes back identically (idempotence
//   — it only accepts cursors it could itself have issued).
//
// FuzzAuditCursorRoundTrip — forward round-trip:
//   ORACLE: for an event with ID in [1, 2^32-1] and a nanosecond UTC time,
//   DecodeAuditCursor(EncodeAuditCursor(e)) recovers the same ID and EventTime.
//
// WHAT THESE DO NOT VERIFY:
//   - No signature/authority: the cursor is deliberately unsigned; a forged but
//     well-formed cursor is a correct parse. It only bounds where a page starts
//     in a result set the caller may already read.
//   - The round-trip is restricted to ID <= math.MaxUint32: DecodeAuditCursor
//     parses the id as a 32-bit unsigned, while EncodeAuditCursor emits
//     uint64(e.ID). An ID above 2^32-1 encodes to a value Decode rejects — a
//     bound noted in the report (audit IDs are a uint primary key; reaching
//     2^32 rows is the only way to observe it, and such a cursor simply fails
//     closed rather than mis-paging).
//   - EventTime is exercised only within int64-nanosecond range (time.Unix(0,
//     ns)); times outside ~[1678,2262] are not representable by UnixNano and are
//     out of scope.
//   - It does not drive ListAuditPage or any storage read; only the codec.
import (
	"math"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func FuzzDecodeAuditCursor(f *testing.F) {
	f.Add(EncodeAuditCursor(&models.AuditEvent{ID: 1, EventTime: time.Unix(0, 0).UTC()}))
	f.Add(EncodeAuditCursor(&models.AuditEvent{ID: 999999, EventTime: time.Unix(0, 1234567890123456789).UTC()}))
	f.Add("")
	f.Add("not-base64!!")
	f.Add("dg==") // valid base64, wrong structure
	// base64("v1.5.0") — zero id must be rejected.
	f.Add("djEuNS4w")
	// A >64-char string to hit the length guard.
	f.Add("djEuMTIzNDU2Nzg5MDEyMzQ1Njc4OS45OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5")

	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecodeAuditCursor panicked on %q: %v", s, r)
			}
		}()

		cur, err := DecodeAuditCursor(s)
		if err != nil {
			return // fail closed: an unrecognised cursor is rejected, the safe outcome
		}
		if cur.ID < 1 {
			t.Fatalf("DecodeAuditCursor accepted a cursor with ID=%d (<1) from %q", cur.ID, s)
		}
		// Idempotence: a cursor it accepts must be one it could have issued.
		re := EncodeAuditCursor(&models.AuditEvent{ID: cur.ID, EventTime: cur.EventTime})
		cur2, err2 := DecodeAuditCursor(re)
		if err2 != nil {
			t.Fatalf("re-encoded cursor %q (from accepted %q) failed to decode: %v", re, s, err2)
		}
		if cur2.ID != cur.ID || !cur2.EventTime.Equal(cur.EventTime) {
			t.Fatalf("cursor idempotence mismatch from %q: first ID=%d time=%v, second ID=%d time=%v",
				s, cur.ID, cur.EventTime, cur2.ID, cur2.EventTime)
		}
	})
}

func FuzzAuditCursorRoundTrip(f *testing.F) {
	f.Add(uint32(1), int64(0))
	f.Add(uint32(999999), int64(1234567890123456789))
	f.Add(uint32(math.MaxUint32), int64(-6795364578871345152))

	f.Fuzz(func(t *testing.T, id uint32, ns int64) {
		if id == 0 {
			return // id 0 is not a valid row id; DecodeAuditCursor rejects it by design
		}
		e := &models.AuditEvent{ID: uint(id), EventTime: time.Unix(0, ns).UTC()}
		enc := EncodeAuditCursor(e)
		cur, err := DecodeAuditCursor(enc)
		if err != nil {
			t.Fatalf("round-trip decode failed for id=%d ns=%d (encoded %q): %v", id, ns, enc, err)
		}
		if cur.ID != uint(id) {
			t.Fatalf("round-trip ID mismatch: encoded id=%d, decoded %d (%q)", id, cur.ID, enc)
		}
		if !cur.EventTime.Equal(e.EventTime) {
			t.Fatalf("round-trip EventTime mismatch for id=%d ns=%d: want %v, got %v (%q)", id, ns, e.EventTime, cur.EventTime, enc)
		}
	})
}
