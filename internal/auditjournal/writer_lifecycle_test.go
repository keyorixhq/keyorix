package auditjournal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWriter_NoOnBatchAfterClose pins coordinator review of #2758, item 1:
// once Close returns, onBatch is never called again, even with submitters
// still running. The store closes its replication channel right after
// Close, so a later onBatch would be a send on a closed channel (a panic in
// production). Submitters racing Close get ErrClosed, never a success for a
// record that onBatch did not see.
func TestWriter_NoOnBatchAfterClose(t *testing.T) {
	var closeReturned atomic.Bool
	var lateCalls atomic.Int64
	var seen atomic.Int64
	w, err := Open(t.TempDir(), WithOnBatchCommitted(func(recs []Record) {
		if closeReturned.Load() {
			lateCalls.Add(1)
		}
		seen.Add(int64(len(recs)))
	}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var acked atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				_, err := w.Submit(ctx, []byte("x"))
				if errors.Is(err, ErrClosed) {
					return
				}
				if err != nil {
					t.Errorf("Submit: %v", err)
					return
				}
				acked.Add(1)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	closeReturned.Store(true)
	time.Sleep(50 * time.Millisecond)
	wg.Wait()

	if n := lateCalls.Load(); n != 0 {
		t.Fatalf("onBatch called %d times after Close returned", n)
	}
	if acked.Load() == 0 {
		t.Fatal("no Submit succeeded before Close; the test exercised nothing")
	}
	if got, want := seen.Load(), acked.Load(); got != want {
		t.Fatalf("onBatch saw %d records, callers were acked for %d", got, want)
	}
	if _, err := w.Submit(ctx, []byte("after")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Submit after Close = %v, want ErrClosed", err)
	}
}

// TestWriter_FlusherRunsUntilClose pins coordinator review of #2758, item 3.
// The old flusher retired itself after an idle timeout, and a Submit that
// had already captured the old queue could strand its request there until
// ctx expired. The flusher now lives from Open to Close; this asserts it is
// still running after an idle period longer than the old timeout (200ms),
// and that a Submit after that idle period is answered at once.
func TestWriter_FlusherRunsUntilClose(t *testing.T) {
	w, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := w.Submit(ctx, []byte("first")); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	select {
	case <-w.flusherDone:
		t.Fatal("flusher exited while the writer is open")
	default:
	}
	start := time.Now()
	if _, err := w.Submit(ctx, []byte("after-idle")); err != nil {
		t.Fatalf("Submit after idle: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Submit after idle took %v", d)
	}
}

// TestWriter_SyncsDirectoryForNewSegments pins coordinator review of #2758,
// item 2: a new segment's directory entry is fsynced before any record in
// it is acknowledged, both at Open and at every rotation.
func TestWriter_SyncsDirectoryForNewSegments(t *testing.T) {
	dir := t.TempDir()
	var mu sync.Mutex
	calls := map[string]int{}
	orig := syncDirFn
	syncDirFn = func(d string) error {
		mu.Lock()
		calls[filepath.Clean(d)]++
		mu.Unlock()
		return orig(d)
	}
	defer func() { syncDirFn = orig }()
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls[filepath.Clean(dir)]
	}

	w, err := Open(dir, WithMaxSegmentBytes(1))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = w.Close() }()
	if count() == 0 {
		t.Fatal("Open did not fsync the journal directory")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		before := count()
		if _, err := w.Submit(ctx, []byte("rec")); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
		// Record 0 goes into the segment Open created; every later one
		// crosses the 1-byte limit and rotates first.
		if i > 0 && count() == before {
			t.Fatalf("record %d rotated into a new segment without a directory fsync", i)
		}
	}
	segs, err := listSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 3 {
		t.Fatalf("got %d segments, want 3", len(segs))
	}
}

// TestWriter_RotateFailureKeepsWriterUsable: a failed rotation (here, the
// new segment cannot be created) fails that batch closed and leaves the
// current segment open, so the next batch can still be written once the
// cause is gone. Closing the old segment first, as the original rotate did,
// left a closed file behind and failed every later batch.
func TestWriter_RotateFailureKeepsWriterUsable(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithMaxSegmentBytes(1))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = w.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := w.Submit(ctx, []byte("a")); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	realOpen := w.openSegment
	w.openSegment = func(string) (segmentWriter, error) { return nil, os.ErrPermission }
	if _, err := w.Submit(ctx, []byte("b")); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Submit during failing rotation = %v, want ErrPermission", err)
	}
	w.openSegment = realOpen
	seq, err := w.Submit(ctx, []byte("c"))
	if err != nil {
		t.Fatalf("Submit after rotation recovers: %v", err)
	}
	if seq != 1 {
		t.Fatalf("seq = %d, want 1 (the failed batch must not consume a seq)", seq)
	}
}
