package auditjournal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
)

// TestValidate_TornTailWriteIsRepairedSilently simulates exactly what a
// kill -9 mid-append produces: a segment file whose last record is only
// partially present (the process died after write() but before the
// batch's fsync could even run, OR mid-write()). Per ADR-115 this must be
// treated as benign -- nothing was ever acknowledged -- and Validate must
// repair it (truncate) rather than refuse.
func TestValidate_TornTailWriteIsRepairedSilently(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := w.Submit(ctx, []byte(fmt.Sprintf("tail-%d", i))); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	path := singleSegmentPath(t, dir)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	fullSize := fi.Size()

	// Truncate off the last 30 bytes -- guaranteed to land inside the last
	// record's trailer/payload (recordFixedOverhead alone is 84 bytes), so
	// the last record is now physically incomplete with NOTHING after it.
	truncated := fullSize - 30
	if err := os.Truncate(path, truncated); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	result, err := Validate(dir)
	if err != nil {
		t.Fatalf("Validate returned an error for a benign torn tail write: %v", err)
	}
	if len(result.Records) != 4 {
		t.Fatalf("got %d surviving records, want 4 (the 5th was torn)", len(result.Records))
	}
	if result.TruncatedTailBytes == 0 {
		t.Fatalf("expected TruncatedTailBytes > 0")
	}

	fi2, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat after Validate: %v", err)
	}
	if fi2.Size() >= truncated {
		t.Fatalf("Validate did not actually truncate the file on disk: size=%d, was=%d", fi2.Size(), truncated)
	}

	// Re-open and append: the journal must resume cleanly, continuing the
	// chain and sequence from the 4 surviving records, not the 5 originally
	// written.
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after repair: %v", err)
	}
	seq, err := w2.Submit(ctx, []byte("after-repair"))
	if err != nil {
		t.Fatalf("Submit after repair: %v", err)
	}
	if seq != 4 {
		t.Fatalf("seq after repair = %d, want 4", seq)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	final, err := Validate(dir)
	if err != nil {
		t.Fatalf("Validate after resumed append: %v", err)
	}
	if len(final.Records) != 5 {
		t.Fatalf("got %d records after repair+append, want 5", len(final.Records))
	}
}

// TestValidate_MidJournalCorruptionFailsClosed corrupts a record in the
// MIDDLE of the journal, leaving an intact, self-consistent record after
// it. Per ADR-115 this is unambiguous evidence of corruption of
// already-acknowledged data (not a crash artifact) and Validate must
// refuse -- never silently repair or skip past it.
func TestValidate_MidJournalCorruptionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := w.Submit(ctx, []byte(fmt.Sprintf("mid-%d", i))); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	path := singleSegmentPath(t, dir)
	// Flip one byte inside record index 2's payload region. Each payload is
	// "mid-N" (5 bytes); record i starts at i*(recordFixedOverhead+5).
	const recLen = recordFixedOverhead + 5
	victimPayloadOffset := int64(2*recLen + 16 + 2) // +16 header, +2 into the 5-byte payload
	corruptByteAt(t, path, victimPayloadOffset)

	_, err = Validate(dir)
	if err == nil {
		t.Fatalf("Validate must fail closed on mid-journal corruption, got nil error")
	}
	var corruptErr *CorruptionError
	if !errors.As(err, &corruptErr) {
		t.Fatalf("expected *CorruptionError, got %T: %v", err, err)
	}
	t.Logf("correctly detected corruption: %v", corruptErr)

	// Open (which calls Validate internally) must also refuse -- a server
	// must not be able to start accepting new audit writes against a
	// corrupted journal.
	if _, err := Open(dir); err == nil {
		t.Fatalf("Open must refuse to start against a corrupted journal")
	}
}

// TestValidate_ChainMismatchFailsClosedEvenAtTail proves ErrChainMismatch
// (self-consistent bytes, wrong position) is NEVER reclassified as a benign
// tail write, unlike ErrCorrupt/ErrIncomplete -- see that error's doc
// comment. Swapping two whole, individually-intact records' byte ranges
// (same total length, so no truncation signal) produces exactly this shape
// even at the physical end of the file.
func TestValidate_ChainMismatchFailsClosedEvenAtTail(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Equal-length payloads so swapping is a pure reorder with no length
	// change.
	for i := 0; i < 3; i++ {
		if _, err := w.Submit(ctx, []byte(fmt.Sprintf("swp%d", i))); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	path := singleSegmentPath(t, dir)
	data, err := os.ReadFile(path) //nolint:gosec // test-only path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	const recLen = recordFixedOverhead + 4 // "swp0" etc. are 4 bytes
	if len(data) != 3*recLen {
		t.Fatalf("unexpected file size %d, want %d", len(data), 3*recLen)
	}
	// Swap record 1 and record 2 (the last record) wholesale -- record 2
	// now sits where record 1 belongs, breaking the chain link without
	// touching any individual record's own CRC/self-hash.
	rec1 := append([]byte{}, data[1*recLen:2*recLen]...)
	rec2 := append([]byte{}, data[2*recLen:3*recLen]...)
	swapped := append([]byte{}, data[:1*recLen]...)
	swapped = append(swapped, rec2...)
	swapped = append(swapped, rec1...)
	if err := os.WriteFile(path, swapped, 0o640); err != nil { //nolint:gosec // test-only path
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = Validate(dir)
	if err == nil {
		t.Fatalf("Validate must fail closed on a chain-mismatch at the tail, got nil error")
	}
	var corruptErr *CorruptionError
	if !errors.As(err, &corruptErr) {
		t.Fatalf("expected *CorruptionError, got %T: %v", err, err)
	}
	if !errors.Is(corruptErr.Reason, ErrChainMismatch) {
		t.Fatalf("expected ErrChainMismatch, got %v", corruptErr.Reason)
	}
}

func TestValidate_EmptyDirIsHealthy(t *testing.T) {
	dir := t.TempDir()
	result, err := Validate(dir)
	if err != nil {
		t.Fatalf("Validate on empty dir: %v", err)
	}
	if len(result.Records) != 0 || result.NextSeq != 0 {
		t.Fatalf("expected empty result, got %+v", result)
	}
	if result.HeadLocalHash != genesisLocalHash {
		t.Fatalf("expected genesis head hash on empty journal")
	}
}
