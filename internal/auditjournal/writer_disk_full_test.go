package auditjournal

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"
)

// enospcSegment wraps a real segmentWriter and fails every Write once more
// than limitBytes total have been accepted, returning syscall.ENOSPC --
// simulating a genuinely full disk without needing real disk pressure
// (which isn't portable/safe to provision in a unit test). This exercises
// exactly the code path a real ENOSPC from the kernel would take; the
// syscall-level behaviour of ENOSPC itself is the OS's problem, not this
// package's.
type enospcSegment struct {
	segmentWriter
	limitBytes int64
	written    int64
}

func (e *enospcSegment) Write(p []byte) (int, error) {
	if e.written+int64(len(p)) > e.limitBytes {
		return 0, fmt.Errorf("auditjournal test: simulated disk full: %w", syscall.ENOSPC)
	}
	n, err := e.segmentWriter.Write(p)
	e.written += int64(n)
	return n, err
}

// TestWriter_DiskFullFailsClosed proves the ADR-115 requirement directly:
// when the journal append itself cannot be made durable (disk full), the
// caller gets an error -- never a success -- so a caller enforcing
// audit-before-disclosure (the real product's LogAuditEvent/GetSecret path)
// cannot proceed to disclose a secret believing its audit record landed.
func TestWriter_DiskFullFailsClosed(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()

	// First write succeeds normally.
	if _, err := w.Submit(ctx, []byte("before-full")); err != nil {
		t.Fatalf("Submit before full: %v", err)
	}

	// Now simulate the disk filling up: swap in a writer that accepts no
	// further bytes at all (limitBytes=0 -- this wrapper's own write
	// counter starts at 0 regardless of how much the real file already
	// holds, so 0 means "no more capacity").
	w.file = &enospcSegment{segmentWriter: w.file, limitBytes: 0}

	_, err = w.Submit(ctx, []byte("during-full"))
	if err == nil {
		t.Fatalf("Submit must fail when the journal disk is full, got nil error")
	}
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("expected the ENOSPC cause to be visible via errors.Is, got: %v", err)
	}

	// The failed write must not have corrupted on-disk state for the
	// record that WAS durable before the disk filled up, nor poisoned the
	// journal for a later, successful append once space is freed.
	underlying := w.file.(*enospcSegment).segmentWriter
	w.file = underlying

	seq, err := w.Submit(ctx, []byte("after-freed"))
	if err != nil {
		t.Fatalf("Submit after space freed: %v", err)
	}
	if seq != 1 {
		t.Fatalf("seq after disk-full recovery = %d, want 1 (the failed write must not consume a seq)", seq)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	result, err := Validate(dir)
	if err != nil {
		t.Fatalf("Validate after disk-full recovery: %v", err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("got %d records, want 2 (before-full, after-freed)", len(result.Records))
	}
	if string(result.Records[0].Payload) != "before-full" || string(result.Records[1].Payload) != "after-freed" {
		t.Fatalf("unexpected surviving records: %+v", result.Records)
	}
}

// TestWriter_DiskFullOnFirstWriteFailsClosed covers the c=1 case explicitly
// (PERF-4's own motivating scenario): a SOLO caller, nothing queued behind
// it, hits a full disk on its very first write.
func TestWriter_DiskFullOnFirstWriteFailsClosed(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	w.file = &enospcSegment{segmentWriter: w.file, limitBytes: 0}

	ctx := context.Background()
	_, err = w.Submit(ctx, []byte("solo-caller-secret-disclosure-event"))
	if err == nil {
		t.Fatalf("a solo caller's write must fail closed on a full disk, got nil error")
	}
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("expected ENOSPC cause, got: %v", err)
	}
}
