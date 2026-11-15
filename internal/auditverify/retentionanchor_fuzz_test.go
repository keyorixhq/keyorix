package auditverify

// FuzzRetentionAnchorParse exercises ParseRetentionAnchorValue and
// ParseRetentionAnchor (retention.go) — the parsers of the system_metadata
// "audit_retention_anchor" value, the authenticated point from which the chain
// is re-anchored after a sanctioned purge. The value is read back from a text
// column an operator with database write access, or a corrupted store, can set
// to anything.
//
// Rather than fuzz raw bytes, this builds the canonical v1/v2 layouts from
// typed fields (a local re-encoder mirroring retention.go's own join format),
// then asserts:
//   - ROUND-TRIP: a well-formed value (RowID>=1, PurgedEvents>=0) parses back to
//     the exact fields it was built from, in the right layout.
//   - FAIL-CLOSED: RowID==0 is rejected (id 0 means "no anchor"); a negative
//     PurgedEvents in a v2 value is rejected.
//   - v1 DIFFERENTIAL: a v1 value accepted by ParseRetentionAnchorValue is also
//     accepted by ParseRetentionAnchor with identical fields (and vice versa) —
//     the two entry points must never disagree on the v1 layout.
//   - Never panics.
//
// WHAT THIS DOES NOT VERIFY:
//   - No HMAC check (SigMatches / SignRetentionAnchor*): an accepted anchor is
//     parsed, not authenticated; a forged-but-well-formed value is a correct
//     parse.
//   - It SKIPS fields containing the record separator \x1f (unescaped
//     single-separator format; real fields — a decimal row id, hex hashes, a
//     numeric key version, a hex signature — never contain it).
//   - It does not assert byte-identity with internal/core.parseAuditRetentionAnchor
//     (unexported).
//   - The v1 differential is partly structural: ParseRetentionAnchorValue's v1
//     branch delegates to ParseRetentionAnchor, so this guards against a
//     divergence introduced into either, not an independent reimplementation.
import (
	"strconv"
	"strings"
	"testing"
)

func FuzzRetentionAnchorParse(f *testing.F) {
	sep := auditRetentionAnchorSep
	// v1, v2, zero-id, negative-purged.
	f.Add(false, uint64(42), "prev", "entry", "keyv", "sig", int64(0))
	f.Add(true, uint64(7), "ph", "eh", "kv", "sg", int64(3))
	f.Add(false, uint64(0), "p", "e", "k", "s", int64(0))
	f.Add(true, uint64(9), "p", "e", "k", "s", int64(-1))

	f.Fuzz(func(t *testing.T, isV2 bool, rowID uint64, prevHash, entryHash, keyVersion, sig string, purged int64) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("retention-anchor parse panicked (isV2=%v id=%d): %v", isV2, rowID, r)
			}
		}()

		for _, s := range []string{prevHash, entryHash, keyVersion, sig} {
			if strings.Contains(s, sep) {
				return // cannot be represented by the unescaped format
			}
		}

		var val string
		if isV2 {
			val = strings.Join([]string{"v2", strconv.FormatUint(rowID, 10), prevHash, entryHash,
				strconv.FormatInt(purged, 10), keyVersion, sig}, sep)
		} else {
			val = strings.Join([]string{"v1", strconv.FormatUint(rowID, 10), prevHash, entryHash,
				keyVersion, sig}, sep)
		}

		got, ok := ParseRetentionAnchorValue(val)

		// Fail-closed cases.
		if rowID == 0 {
			if ok {
				t.Fatalf("ParseRetentionAnchorValue accepted RowID==0 from %q", val)
			}
			return
		}
		if isV2 && purged < 0 {
			if ok {
				t.Fatalf("ParseRetentionAnchorValue accepted negative PurgedEvents=%d from %q", purged, val)
			}
			return
		}

		// Well-formed: must round-trip.
		if !ok {
			t.Fatalf("ParseRetentionAnchorValue rejected a well-formed value %q", val)
		}
		wantLayout := "v1"
		wantPurged := int64(0)
		if isV2 {
			wantLayout, wantPurged = "v2", purged
		}
		if got.Layout != wantLayout || got.RowID != rowID || got.PrevHash != prevHash ||
			got.EntryHash != entryHash || got.KeyVersion != keyVersion || got.Signature != sig ||
			got.PurgedEvents != wantPurged {
			t.Fatalf("retention round-trip mismatch for %q:\n want layout=%s id=%d prev=%q entry=%q keyv=%q sig=%q purged=%d\n got  layout=%s id=%d prev=%q entry=%q keyv=%q sig=%q purged=%d",
				val, wantLayout, rowID, prevHash, entryHash, keyVersion, sig, wantPurged,
				got.Layout, got.RowID, got.PrevHash, got.EntryHash, got.KeyVersion, got.Signature, got.PurgedEvents)
		}

		// v1 differential: the two entry points must agree.
		if !isV2 {
			id2, prev2, entry2, keyv2, sig2, ok2 := ParseRetentionAnchor(val)
			if !ok2 {
				t.Fatalf("ParseRetentionAnchor rejected a v1 value ParseRetentionAnchorValue accepted: %q", val)
			}
			if id2 != rowID || prev2 != prevHash || entry2 != entryHash || keyv2 != keyVersion || sig2 != sig {
				t.Fatalf("v1 differential mismatch for %q: ParseRetentionAnchor got id=%d prev=%q entry=%q keyv=%q sig=%q",
					val, id2, prev2, entry2, keyv2, sig2)
			}
		}
	})
}
