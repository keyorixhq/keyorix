package auditjournal

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// defaultMaxSegmentBytes bounds how large one segment file grows before
// Writer rotates to a new one (ADR-115: "segment-rotated at a fixed size so
// no single file grows unbounded and old, fully-replicated segments can be
// retired"). Rotation is only ever checked at a batch boundary (see
// commitBatch), never mid-batch -- a prototype-scope simplification: one
// batch can overshoot this bound by up to its own size, which is bounded in
// turn by appendQueueCapacity/appendMaxBatch and each record's
// maxPayloadLen cap.
const defaultMaxSegmentBytes = 64 << 20

// appendQueueCapacity/appendMaxBatch mirror store.auditQueueCapacity/
// auditFlusherMaxBatch's already-proven group-commit shape (#2420): a
// bounded channel (deliberate backpressure once full, rather than an
// unbounded in-memory backlog of not-yet-durable records) and a cap on how
// many records one fsync batch covers.
const (
	appendQueueCapacity = 4096
	appendMaxBatch      = 256
	appendIdleTimeout   = 200 * time.Millisecond
)

// segmentWriter is the subset of *os.File the Writer needs. Exists so a test
// can substitute a fault-injecting implementation (e.g. one that fails with
// ENOSPC after N bytes) without needing a real disk-full condition -- see
// writer_disk_full_test.go.
type segmentWriter interface {
	io.Writer
	Sync() error
	Truncate(size int64) error
	Close() error
}

func openRealSegment(path string) (segmentWriter, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600) // #nosec G304 -- path is derived from an operator-configured dir, not user input
}

type appendRequest struct {
	payload []byte
	done    chan appendResult
}

type appendResult struct {
	seq uint64
	err error
}

// Writer is the append-only, group-fsync-batched local audit journal writer
// for one replica (ADR-115). Safe for concurrent Submit calls; a single
// internal goroutine does all actual file I/O, batching whatever is queued
// when it wakes and issuing exactly one fsync per batch -- the same
// group-commit shape store.runAuditFlusher already uses for Postgres,
// applied to a local file.
//
// Zero value is not usable; construct with Open.
type Writer struct {
	dir             string
	maxSegmentBytes int64
	openSegment     func(path string) (segmentWriter, error)
	onBatch         func([]Record) // optional: called after a batch's fsync succeeds, before acking callers

	submitMu sync.Mutex
	queue    chan *appendRequest
	running  bool

	// Touched ONLY by the single flusher goroutine while running -- see
	// runFlusher. Safe without further locking because Open/Close and
	// runFlusher's own lifecycle guarantee at most one goroutine accesses
	// these at a time (the submit-side queue is the only cross-goroutine
	// handoff, and it carries no reference to these fields).
	file         segmentWriter
	fileSize     int64
	fileStartSeq uint64
	nextSeq      uint64
	chainHead    [32]byte

	closeOnce sync.Once
	closed    chan struct{}
}

// Option configures Open.
type Option func(*Writer)

// WithMaxSegmentBytes overrides defaultMaxSegmentBytes.
func WithMaxSegmentBytes(n int64) Option {
	return func(w *Writer) { w.maxSegmentBytes = n }
}

// WithOnBatchCommitted registers fn to be called, synchronously on the
// flusher goroutine, with every batch's records immediately after that
// batch's fsync succeeds and before any caller in the batch is acked. Used
// by the replicator (internal/storage/store) to replay newly-durable
// records without re-reading them from disk during normal operation. fn
// must not block indefinitely -- it runs on the same goroutine that would
// otherwise be acking callers and accepting the next batch.
func WithOnBatchCommitted(fn func([]Record)) Option {
	return func(w *Writer) { w.onBatch = fn }
}

// Open validates dir (see Validate — a benign torn tail write is repaired
// in place; real corruption is returned as a *CorruptionError and Open
// fails, per ADR-115's fail-closed requirement) and returns a Writer
// positioned to append the next record after whatever is already durably
// present.
func Open(dir string, opts ...Option) (*Writer, error) {
	result, err := Validate(dir)
	if err != nil {
		return nil, err
	}

	w := &Writer{
		dir:             dir,
		maxSegmentBytes: defaultMaxSegmentBytes,
		openSegment:     openRealSegment,
		nextSeq:         result.NextSeq,
		chainHead:       result.HeadLocalHash,
		closed:          make(chan struct{}),
	}
	for _, opt := range opts {
		opt(w)
	}

	segs, err := listSegments(dir)
	if err != nil {
		return nil, err
	}

	var path string
	var startSeq uint64
	var size int64
	if len(segs) > 0 {
		last := segs[len(segs)-1]
		if fi, statErr := os.Stat(last.Path); statErr == nil && fi.Size() < w.maxSegmentBytes {
			path, startSeq, size = last.Path, last.StartSeq, fi.Size()
		}
	}
	if path == "" {
		startSeq = w.nextSeq
		path = filepath.Join(dir, segmentName(startSeq))
	}

	f, err := w.openSegment(path)
	if err != nil {
		return nil, fmt.Errorf("auditjournal: open segment %s: %w", path, err)
	}
	w.file = f
	w.fileStartSeq = startSeq
	w.fileSize = size

	return w, nil
}

// Submit appends payload, waits for its batch's group fsync, and returns
// the record's assigned sequence number. Blocks until the batch commits (or
// fails) or ctx is done. A non-nil error means payload is NOT durable --
// per ADR-115, the caller must treat this exactly like a failed audit
// write: fail closed, never disclose.
func (w *Writer) Submit(ctx context.Context, payload []byte) (uint64, error) {
	req := &appendRequest{payload: payload, done: make(chan appendResult, 1)}

	w.submitMu.Lock()
	if !w.running {
		w.running = true
		w.queue = make(chan *appendRequest, appendQueueCapacity)
		go w.runFlusher(w.queue)
	}
	queue := w.queue
	w.submitMu.Unlock()

	select {
	case queue <- req:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	select {
	case res := <-req.done:
		return res.seq, res.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// Close stops the flusher goroutine (after any in-flight batch finishes)
// and closes the current segment file. Safe to call once; a Submit racing
// a concurrent Close may return early with an error -- callers are expected
// to stop submitting before closing, same contract as a context cancel.
func (w *Writer) Close() error {
	w.closeOnce.Do(func() { close(w.closed) })
	w.submitMu.Lock()
	running := w.running
	queue := w.queue
	w.submitMu.Unlock()
	if !running {
		return nil
	}
	// Send a sentinel with a cancelled context's shape by simply waiting for
	// the flusher's own idle exit -- simplest correct shutdown for a
	// prototype: stop producing new work and let the idle timeout retire the
	// goroutine, then close the file. The flusher never touches w.file after
	// marking itself not-running (see runFlusher), so this is race-free.
	_ = queue
	for {
		w.submitMu.Lock()
		stillRunning := w.running
		w.submitMu.Unlock()
		if !stillRunning {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// runFlusher is the single goroutine performing all file I/O for w. Mirrors
// store.runAuditFlusher's shape exactly (bounded queue, non-blocking drain
// up to appendMaxBatch, idle-exit after appendIdleTimeout) with local-file
// group fsync in place of a Postgres transaction.
func (w *Writer) runFlusher(queue chan *appendRequest) {
	for {
		var batch []*appendRequest
		select {
		case req := <-queue:
			batch = append(batch, req)
		case <-time.After(appendIdleTimeout):
			w.submitMu.Lock()
			select {
			case req := <-queue:
				batch = append(batch, req)
				w.submitMu.Unlock()
			default:
				w.running = false
				w.submitMu.Unlock()
				return
			}
		}
		for len(batch) < appendMaxBatch {
			select {
			case req := <-queue:
				batch = append(batch, req)
			default:
				goto commit
			}
		}
	commit:
		w.commitBatch(batch)
	}
}

// commitBatch encodes every request in batch onto the journal-local chain,
// rotating the segment first if it has crossed maxSegmentBytes, writes the
// whole batch in one Write call, and fsyncs exactly once before acking any
// request. On any I/O error, the file is truncated back to its last known
// good size (best-effort) so a FOLLOWING successful batch never appends
// after an in-place, non-crash write failure's leftover bytes -- without
// this, a write error that doesn't crash the process (unlike a real crash,
// which Validate's tail-truncation already handles) would leave a
// self-inconsistent gap in the middle of a file this process keeps using,
// which Validate would then (correctly, but confusingly) report as
// mid-journal corruption on the next restart.
func (w *Writer) commitBatch(batch []*appendRequest) {
	if w.fileSize >= w.maxSegmentBytes {
		if err := w.rotate(); err != nil {
			w.failBatch(batch, err)
			return
		}
	}

	var buf []byte
	records := make([]Record, 0, len(batch))
	seq := w.nextSeq
	head := w.chainHead
	seqs := make([]uint64, 0, len(batch))
	for _, req := range batch {
		enc, newHead := encodeRecord(seq, req.payload, head)
		buf = append(buf, enc...)
		records = append(records, Record{Seq: seq, Payload: req.payload, LocalPrevHash: head, LocalEntryHash: newHead})
		seqs = append(seqs, seq)
		head = newHead
		seq++
	}

	if _, err := w.file.Write(buf); err != nil {
		w.rollbackPartialWrite()
		w.failBatch(batch, fmt.Errorf("auditjournal: write: %w", err))
		return
	}
	if err := w.file.Sync(); err != nil {
		w.rollbackPartialWrite()
		w.failBatch(batch, fmt.Errorf("auditjournal: fsync: %w", err))
		return
	}

	w.fileSize += int64(len(buf))
	w.nextSeq = seq
	w.chainHead = head

	if w.onBatch != nil {
		w.onBatch(records)
	}
	for i, req := range batch {
		req.done <- appendResult{seq: seqs[i], err: nil}
	}
}

// rollbackPartialWrite truncates the current segment back to the last
// known-good size after a failed Write/Sync -- see commitBatch's doc
// comment. Best-effort: if the truncate itself fails there is nothing more
// this process can safely do, and the failure already returned to every
// caller in the batch tells them their write is NOT durable.
func (w *Writer) rollbackPartialWrite() {
	_ = w.file.Truncate(w.fileSize)
}

func (w *Writer) failBatch(batch []*appendRequest, err error) {
	for _, req := range batch {
		req.done <- appendResult{err: err}
	}
}

// rotate closes the current segment (fsyncing first) and opens a new one
// starting at w.nextSeq.
func (w *Writer) rotate() error {
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("auditjournal: fsync before rotate: %w", err)
	}
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("auditjournal: close before rotate: %w", err)
	}
	path := filepath.Join(w.dir, segmentName(w.nextSeq))
	f, err := w.openSegment(path)
	if err != nil {
		return fmt.Errorf("auditjournal: open new segment %s: %w", path, err)
	}
	w.file = f
	w.fileStartSeq = w.nextSeq
	w.fileSize = 0
	return nil
}
