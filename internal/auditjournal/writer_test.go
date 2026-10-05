package auditjournal

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestWriter_AppendAndReplayRoundTrip(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const n = 50
	seqs := make([]uint64, n)
	for i := 0; i < n; i++ {
		seq, err := w.Submit(ctx, []byte(fmt.Sprintf("event-%d", i)))
		if err != nil {
			t.Fatalf("Submit(%d): %v", i, err)
		}
		seqs[i] = seq
	}
	for i := 1; i < n; i++ {
		if seqs[i] != seqs[i-1]+1 {
			t.Fatalf("seqs not contiguous: seqs[%d]=%d seqs[%d]=%d", i-1, seqs[i-1], i, seqs[i])
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	result, err := Validate(dir)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.TruncatedTailBytes != 0 {
		t.Fatalf("unexpected truncation after clean shutdown: %d bytes", result.TruncatedTailBytes)
	}
	if len(result.Records) != n {
		t.Fatalf("got %d records, want %d", len(result.Records), n)
	}
	for i, rec := range result.Records {
		want := fmt.Sprintf("event-%d", i)
		if string(rec.Payload) != want {
			t.Errorf("record %d payload = %q, want %q", i, rec.Payload, want)
		}
	}
}

func TestWriter_ConcurrentSubmitGroupCommits(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = w.Close() }()

	const n = 200
	type outcome struct {
		seq uint64
		err error
	}
	results := make(chan outcome, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			seq, err := w.Submit(ctx, []byte(fmt.Sprintf("concurrent-%d", i)))
			results <- outcome{seq, err}
		}(i)
	}
	seen := make(map[uint64]bool, n)
	for i := 0; i < n; i++ {
		o := <-results
		if o.err != nil {
			t.Fatalf("Submit error: %v", o.err)
		}
		if seen[o.seq] {
			t.Fatalf("duplicate seq assigned: %d", o.seq)
		}
		seen[o.seq] = true
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct seqs, want %d", len(seen), n)
	}
}

func TestWriter_SegmentRotation(t *testing.T) {
	dir := t.TempDir()
	// Small enough that a handful of records force multiple rotations.
	w, err := Open(dir, WithMaxSegmentBytes(200))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	const n = 40
	for i := 0; i < n; i++ {
		if _, err := w.Submit(ctx, []byte(fmt.Sprintf("rot-%03d", i))); err != nil {
			t.Fatalf("Submit(%d): %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	segs, err := listSegments(dir)
	if err != nil {
		t.Fatalf("listSegments: %v", err)
	}
	if len(segs) < 2 {
		t.Fatalf("expected rotation to produce multiple segments, got %d", len(segs))
	}

	result, err := Validate(dir)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(result.Records) != n {
		t.Fatalf("got %d records across segments, want %d", len(result.Records), n)
	}
	for i, rec := range result.Records {
		want := fmt.Sprintf("rot-%03d", i)
		if string(rec.Payload) != want {
			t.Errorf("record %d = %q, want %q (chain must survive segment rotation)", i, rec.Payload, want)
		}
	}
}

func TestWriter_OnBatchCommittedFeedsLiveReplicator(t *testing.T) {
	dir := t.TempDir()
	var fed []Record
	w, err := Open(dir, WithOnBatchCommitted(func(recs []Record) {
		fed = append(fed, recs...)
	}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if _, err := w.Submit(ctx, []byte(fmt.Sprintf("live-%d", i))); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	if len(fed) != 10 {
		t.Fatalf("onBatch fed %d records, want 10", len(fed))
	}
	for i, rec := range fed {
		want := fmt.Sprintf("live-%d", i)
		if string(rec.Payload) != want {
			t.Errorf("fed record %d = %q, want %q", i, rec.Payload, want)
		}
	}
}

func TestWriter_ResumesSeqAndChainAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	w1, err := Open(dir)
	if err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := w1.Submit(ctx, []byte(fmt.Sprintf("first-%d", i))); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}

	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open 2: %v", err)
	}
	seq, err := w2.Submit(ctx, []byte("second-0"))
	if err != nil {
		t.Fatalf("Submit after reopen: %v", err)
	}
	if seq != 5 {
		t.Fatalf("seq after reopen = %d, want 5 (must continue, not restart at 0)", seq)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("Close 2: %v", err)
	}

	result, err := Validate(dir)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(result.Records) != 6 {
		t.Fatalf("got %d records, want 6", len(result.Records))
	}
	// The chain must be intact across the Close/reopen boundary -- Validate
	// already proves this (it would return a *CorruptionError otherwise),
	// but assert explicitly that record 5 really does chain from record 4.
	if result.Records[5].LocalPrevHash != result.Records[4].LocalEntryHash {
		t.Fatalf("chain broken across reopen boundary")
	}
}

func TestWriter_WriteFailureDoesNotPoisonLaterAppends(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()

	if _, err := w.Submit(ctx, []byte("good-0")); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	// Swap in a writer that fails every subsequent Write, simulating a
	// transient I/O error that does NOT crash the process (see
	// writer_disk_full_test.go for the dedicated ENOSPC fail-closed test;
	// this test is about recovery/non-poisoning after such a failure).
	real := w.file
	w.file = &alwaysFailWriter{segmentWriter: real}
	if _, err := w.Submit(ctx, []byte("bad-1")); err == nil {
		t.Fatalf("expected Submit to fail while the writer is faulty")
	}

	// Restore a healthy writer at the SAME path and verify the next append
	// succeeds and the journal is NOT reported as corrupt -- i.e. the
	// failed attempt's partial bytes (if any) were rolled back rather than
	// leaving a poisoned gap.
	w.file = real
	seq, err := w.Submit(ctx, []byte("good-2"))
	if err != nil {
		t.Fatalf("Submit after recovering writer: %v", err)
	}
	if seq != 1 {
		t.Fatalf("seq after failed+recovered write = %d, want 1 (failed write must not consume a seq)", seq)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	result, err := Validate(dir)
	if err != nil {
		t.Fatalf("Validate reported the journal as corrupt after a non-crash write failure: %v", err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("got %d records, want 2 (good-0, good-2)", len(result.Records))
	}
}

type alwaysFailWriter struct {
	segmentWriter
}

func (a *alwaysFailWriter) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("injected write failure")
}

// corruptByteAt flips one byte in path at the given offset.
func corruptByteAt(t *testing.T, path string, offset int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0o640) //nolint:gosec // test-only path
	if err != nil {
		t.Fatalf("open for corruption: %v", err)
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, offset); err != nil {
		t.Fatalf("read for corruption: %v", err)
	}
	b[0] ^= 0xFF
	if _, err := f.WriteAt(b, offset); err != nil {
		t.Fatalf("write for corruption: %v", err)
	}
}

func singleSegmentPath(t *testing.T, dir string) string {
	t.Helper()
	segs, err := listSegments(dir)
	if err != nil {
		t.Fatalf("listSegments: %v", err)
	}
	if len(segs) != 1 {
		t.Fatalf("expected exactly one segment, got %d", len(segs))
	}
	return segs[0].Path
}
