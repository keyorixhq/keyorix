//go:build !windows

package auditverify_test

// witness_crash_replay_fuzz_test.go — FuzzWitnessCrashReplay (FS1).
//
// The audit high-water WITNESS file (witness.go) is the host-local rollback-
// protection reference: `admin restore` compares an archive's embedded mark
// against it (docs/design-b3-backup-v2.md §6.3). It is written atomically
// (temp → fsync → rename) and read back by ReadWitness; the mark it carries is
// authenticated by an HMAC signature under the KEK-derived checkpoint key.
//
// Existing coverage this does NOT duplicate:
//   - TestWriteWitnessIfHigher_NeverLowersTheMark (INV-AUDITVERIFY-10) is a
//     single hand-written monotonicity case, not a corpus-driven one.
//   - FuzzAuditChainRowDecode (INV-AUDITVERIFY-15) fuzzes audit-ROW decoding,
//     never the witness file.
// Neither drives the witness file through a CRASH-REPLAY shape: a post-crash
// on-disk witness that is truncated, bit-flipped, byte-appended, replaced with
// a forged (wrong-key-signed) higher value, or rewound to a lower value, then
// read back and advanced by the REAL reader/writer.
//
// This target manufactures the post-crash on-disk state directly (no production
// hook needed — the write path is atomic temp+rename, so the only states a
// crash leaves at the final path are "old bytes" or "new bytes"; a torn file at
// the final path can only come from a non-atomic writer or external tampering,
// which is exactly what this asserts the reader rejects) and drives the real
// ReadWitness / WriteWitnessIfHigher.
//
// Oracles (and, per the FS1 brief, what each does NOT verify):
//
//	(b) INTEGRITY — no torn/forged witness accepted as valid. A witness value
//	    whose bytes were not produced by EncodeHighWater over a checkpoint
//	    signed under `key` must FAIL HighWaterSigMatches. The HMAC is the
//	    witness's "checksum/manifest". DOES NOT verify: that the UNKEYED
//	    rollback-ordering in WriteWitnessIfHigher (which compares parsed,
//	    unauthenticated fields by design — the witness is explicitly not an
//	    authenticator at the WriteWitnessIfHigher layer) resists a forged mark;
//	    that is a documented non-goal (witness.go / manifest.go package docs).
//	(c) SURFACED — an EXISTING but unparseable witness file is an error from
//	    ReadWitness, never silently "no witness" (found=false,nil). DOES NOT
//	    verify the caller actually treats that error as fail-closed (that is the
//	    caller's contract, checked at the restore sites, not here).
//	(a) MONOTONIC under replay — WriteWitnessIfHigher over an existing coherent
//	    mark never yields a strictly lower readable mark, and over an
//	    unparseable file it surfaces the error rather than silently lowering.
//	    DOES NOT verify durability of the write itself (no fsync fault is
//	    injected — that needs a production seam; filed as a proposal).
//	(e) NO FD LEAK — repeating the read/write cycle does not grow the process's
//	    open file-descriptor count. DOES NOT verify goroutine leaks (these
//	    functions start none) nor leaks under concurrent callers.
//	ROBUSTNESS — ParseHighWater/ReadWitness never panic on arbitrary bytes.

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

// witnessFuzzKey is the fixed HMAC key standing in for the KEK-derived audit
// checkpoint signing key. 32 bytes; its exact value is irrelevant — the oracle
// only needs a key the harness controls so it can tell "signed by us" from
// "forged".
var witnessFuzzKey = []byte("fs1-witness-crash-replay-hmac-k0")

// witnessFuzzWrongKey is a DIFFERENT key the harness uses to forge a mark that
// is syntactically valid and orders higher but was never signed under the real
// key — the on-disk shape of an attacker/torn higher mark.
var witnessFuzzWrongKey = []byte("fs1-witness-crash-replay-WRONGke")

// countOpenFDs returns the number of entries in /proc/self/fd (Linux), or
// ok=false where it is missing (darwin), in which case only oracle (e) is
// skipped. The witness read/write helpers all close deterministically, so a
// per-call leak would show as monotonic growth across the oracle-(e) loop below.
func countOpenFDs() (n int, ok bool) {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	return len(ents), true
}

// sanitizeField strips the separator and NUL bytes a fuzzer might inject into a
// field that the encoder joins with \x1f — so EncodeHighWater produces a value
// ParseHighWater round-trips. This keeps the BASELINE mark well-formed; the
// torn/forged states are produced separately by mutate().
func sanitizeField(s string) string {
	s = strings.ReplaceAll(s, "\x1f", "")
	s = strings.ReplaceAll(s, "\x00", "")
	return s
}

func FuzzWitnessCrashReplay(f *testing.F) {
	f.Add(int64(5), uint64(10), "v1", "deadbeef", byte(0), uint16(3), int64(7))
	f.Add(int64(0), uint64(0), "", "", byte(1), uint16(0), int64(1))
	f.Add(int64(100), uint64(200), "key-2", "abc123", byte(2), uint16(1), int64(50))
	f.Add(int64(1<<40), uint64(1<<40), "v9", strings.Repeat("f", 64), byte(3), uint16(9999), int64(1))
	f.Add(int64(-3), uint64(1), "neg", "0", byte(4), uint16(2), int64(0))
	f.Add(int64(42), uint64(7), "v1", "cafe", byte(6), uint16(0), int64(3))

	f.Fuzz(func(t *testing.T, chained int64, headID uint64, keyVer, headHashIn string, mutSel byte, truncK uint16, advance int64) {
		dir := t.TempDir()
		path := auditverify.WitnessPath(filepath.Join(dir, "secrets.db"))

		headHash := sanitizeField(headHashIn)
		keyVersion := sanitizeField(keyVer)

		// ── baseline: commit a legitimate, signed witness V1 ──────────────
		cp1 := &auditverify.Checkpoint{
			ChainedEvents: chained,
			HeadID:        headID,
			HeadHash:      headHash,
			KeyVersion:    keyVersion,
		}
		v1 := auditverify.EncodeHighWater(cp1, auditverify.SignCheckpoint(cp1, witnessFuzzKey))

		wrote, err := auditverify.WriteWitnessIfHigher(path, v1)
		if err != nil {
			t.Fatalf("baseline WriteWitnessIfHigher(%q) errored: %v", v1, err)
		}
		if !wrote {
			t.Fatalf("baseline WriteWitnessIfHigher did not write to a fresh path")
		}
		// ReadWitness must return exactly what we signed, and it must verify.
		rcp, rsig, found, rerr := auditverify.ReadWitness(path)
		if rerr != nil || !found {
			t.Fatalf("baseline ReadWitness: found=%v err=%v (want found, no error)", found, rerr)
		}
		if !auditverify.HighWaterSigMatches(rcp, rsig, witnessFuzzKey) {
			t.Fatalf("baseline witness does not verify under its own key — EncodeHighWater/Sign mismatch")
		}

		// ── manufacture a post-crash / tampered on-disk witness ───────────
		orig, err := os.ReadFile(path) //nolint:gosec // harness temp path
		if err != nil {
			t.Fatalf("read baseline witness bytes: %v", err)
		}
		mutated, kind, rewound := mutateWitness(orig, int(mutSel), int(truncK), cp1, chained, advance)
		signedByUs := string(mutated) == string(orig) || (rewound != "" && string(mutated) == rewound)
		if err := os.WriteFile(path, mutated, 0o600); err != nil { //nolint:gosec // harness temp path
			t.Fatalf("write mutated witness: %v", err)
		}

		// ── oracle (b)+(c): read back the manufactured state ──────────────
		cp, sig, found, rerr := auditverify.ReadWitness(path)

		switch {
		case rerr != nil:
			// ReadWitness surfaced an error. For an EXISTING file this is only
			// legitimate when the bytes do not parse (oracle c): a parseable
			// file never errors. We planted bytes, so the file always exists.
			if _, _, ok := auditverify.ParseHighWater(string(mutated)); ok {
				t.Fatalf("SURFACED-WRONG: ReadWitness errored on a file whose bytes DO parse (%s): %v", kind, rerr)
			}
		case !found:
			// An existing, non-empty witness file must never read as "absent".
			t.Fatalf("SILENT-ABSENT (oracle c): an existing witness file (%s) read back as found=false,nil — a corrupted witness treated as 'no witness' is exactly the rollback-protection bypass this must reject; bytes=%q", kind, mutated)
		default:
			// Parsed OK. Oracle (b): it may verify under the real key ONLY if
			// the bytes are byte-identical to a value the harness itself signed
			// under witnessFuzzKey: v1 (orig), or the rewound value. "Signed by
			// us" comes from the harness's own record, never from
			// HighWaterSigMatches, the function under test. Any other byte
			// sequence that verifies is an HMAC integrity break.
			verifies := auditverify.HighWaterSigMatches(cp, sig, witnessFuzzKey)
			if verifies && !signedByUs {
				t.Fatalf("INTEGRITY (oracle b): a tampered/torn witness (%s) parsed AND verified under the real key though the harness never signed those bytes: %q", kind, mutated)
			}
			if !verifies && signedByUs {
				t.Fatalf("INTEGRITY (oracle b): a witness the harness signed under the real key (%s) does not verify", kind)
			}
		}

		// ── oracle (a): a legitimate higher advance over the replayed state ─
		// cp2 strictly higher than cp1 by ChainedEvents (advance >= 1).
		delta := max(advance, 1)
		var nextChained int64
		if chained > 0 && chained > (1<<62)-delta {
			nextChained = chained // avoid overflow; keep well-formed
		} else {
			nextChained = chained + delta
		}
		cp2 := &auditverify.Checkpoint{
			ChainedEvents: nextChained,
			HeadID:        headID + 1,
			HeadHash:      headHash,
			KeyVersion:    keyVersion,
		}
		v2 := auditverify.EncodeHighWater(cp2, auditverify.SignCheckpoint(cp2, witnessFuzzKey))

		_, preParseOK := parseOK(mutated)
		w2, e2 := auditverify.WriteWitnessIfHigher(path, v2)
		switch {
		case !preParseOK:
			// The on-disk witness was unparseable: WriteWitnessIfHigher reads it
			// first, so it must surface that error and NOT silently overwrite.
			if e2 == nil {
				t.Fatalf("FAIL-OPEN (oracle a): WriteWitnessIfHigher advanced over an UNPARSEABLE witness (%s) without surfacing an error (wrote=%v) — a torn witness must block advancement, not be silently clobbered", kind, w2)
			}
		case e2 != nil:
			t.Fatalf("WriteWitnessIfHigher over a parseable witness (%s) errored unexpectedly: %v", kind, e2)
		default:
			// It wrote (or no-op'd). The readable mark must now be >= cp1 by
			// HighWaterOrder: an acknowledged mark is never lost/lowered.
			after, _, found2, rerr2 := auditverify.ReadWitness(path)
			if rerr2 != nil || !found2 {
				t.Fatalf("post-advance ReadWitness failed: found=%v err=%v", found2, rerr2)
			}
			if auditverify.HighWaterOrder(after, cp1) < 0 {
				t.Fatalf("MONOTONIC (oracle a): after advance the readable mark is LOWER than the acknowledged baseline cp1 (%s)", kind)
			}
		}

		// ── oracle (e): no fd leak across repeated read/write cycles ──────
		before, fdOK := countOpenFDs()
		for range 16 {
			_, _, _, _ = auditverify.ReadWitness(path)
			_, _ = auditverify.WriteWitnessIfHigher(path, v2)
		}
		if !fdOK {
			t.Log("no /proc/self/fd: oracle (e) skipped")
			return
		}
		after, _ := countOpenFDs()
		if after > before+2 {
			t.Fatalf("FD LEAK (oracle e): open fd count grew %d→%d across 16 read/write cycles (%s)", before, after, kind)
		}
	})
}

// parseOK reports whether b parses as a high-water value (used to classify the
// manufactured state for the oracle branches).
func parseOK(b []byte) (string, bool) {
	_, sig, ok := auditverify.ParseHighWater(string(b))
	return sig, ok
}

// mutateWitness turns the baseline witness bytes into a post-crash / tampered
// shape chosen by sel. It returns the new bytes, a human-readable kind for
// failure messages and, for the rewound kind only, the value the harness
// signed under the real key (empty otherwise).
func mutateWitness(orig []byte, sel, truncK int, cp1 *auditverify.Checkpoint, chained, advance int64) ([]byte, string, string) {
	switch sel % 7 {
	case 0:
		// unchanged — the "clean replay, rename landed" state.
		return append([]byte(nil), orig...), "unchanged", ""
	case 1:
		// truncated at K (a short/torn write that a NON-atomic writer could
		// leave; the real writer is atomic, so this models external corruption).
		k := min(truncK, len(orig))
		return append([]byte(nil), orig[:k]...), "truncated", ""
	case 2:
		// a single bit flipped (bit rot / partial sector).
		b := append([]byte(nil), orig...)
		if len(b) > 0 {
			b[truncK%len(b)] ^= 0x40
		}
		return b, "bitflip", ""
	case 3:
		// garbage appended after a valid value (a splice).
		b := append([]byte(nil), orig...)
		b = append(b, []byte("\x1fTRAILING-GARBAGE")...)
		return b, "appended", ""
	case 4:
		// a forged HIGHER mark signed under the WRONG key — parses, orders
		// higher, but must not verify under the real key.
		forged := &auditverify.Checkpoint{
			ChainedEvents: chained + advance + 1000,
			HeadID:        cp1.HeadID + 1000,
			HeadHash:      cp1.HeadHash,
			KeyVersion:    cp1.KeyVersion,
		}
		v := auditverify.EncodeHighWater(forged, auditverify.SignCheckpoint(forged, witnessFuzzWrongKey))
		return []byte(v), "forged-higher", ""
	case 5:
		// empty file (a crash between create and first write — real writer uses
		// a temp file so this cannot happen at the final path, but external
		// truncation to zero can).
		return []byte{}, "empty", ""
	default:
		// rewound to a LOWER mark, correctly signed under the real key (an old
		// witness copied back over the current one). It verifies; oracle (a)
		// then checks the advance still leaves the mark >= cp1.
		lower := chained
		if lower > math.MinInt64 {
			lower--
		}
		rew := &auditverify.Checkpoint{
			ChainedEvents: lower,
			HeadID:        cp1.HeadID,
			HeadHash:      cp1.HeadHash,
			KeyVersion:    cp1.KeyVersion,
		}
		v := auditverify.EncodeHighWater(rew, auditverify.SignCheckpoint(rew, witnessFuzzKey))
		return []byte(v), "rewound", v
	}
}
