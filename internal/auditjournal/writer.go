package auditjournal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
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
)

// ErrClosed is returned by Submit once Close has been called (or races it)
// and the request was not written. Like every Submit error it means the
// payload is NOT durable.
var ErrClosed = errors.New("auditjournal: writer closed")

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

// syncDir fsyncs a directory so a file created (or renamed) inside it has a
// durable directory entry. fsync on the file alone does not persist its
// dirent: after a crash the file, and every record in it, can be gone even
// though each record's own fsync succeeded (coordinator review of #2758,
// item 2). Keyorix ships no Windows build, where opening a directory for
// Sync is not supported.
//
// The writer calls it through syncDirFn so a test can observe the calls.
func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- operator-configured journal dir
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

var syncDirFn = syncDir

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
//
// Lifecycle: Open starts exactly one flusher goroutine and Close stops it.
// There is no idle exit and no lazy restart. The earlier design started the
// flusher on the first Submit and retired it after an idle timeout, which
// had two defects found in the coordinator's review of #2758: a Submit that
// captured the old queue just before the idle exit could strand its request
// until ctx expired (item 3), and Close could not stop the flusher, only
// wait for it to idle out, so a batch committed during Close still called
// onBatch after the store side had torn down (item 1, a send on a closed
// channel).
type Writer struct {
	dir             string
	maxSegmentBytes int64
	openSegment     func(path string) (segmentWriter, error)
	onBatch         func([]Record) // optional: called after a batch's fsync succeeds, before acking callers

	queue chan *appendRequest

	// Touched ONLY by the flusher goroutine between Open and Close (tests
	// may swap file between Submits; the queue/done channel handoffs order
	// those accesses).
	file         segmentWriter
	fileSize     int64
	fileStartSeq uint64
	nextSeq      uint64
	chainHead    [32]byte

	closeOnce   sync.Once
	closed      chan struct{} // closed by Close: stop accepting, drain, exit
	flusherDone chan struct{} // closed by the flusher when it has exited; no onBatch call happens after this
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
		queue:           make(chan *appendRequest, appendQueueCapacity),
		closed:          make(chan struct{}),
		flusherDone:     make(chan struct{}),
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
	// Persist the segment's directory entry (it may have just been created)
	// and the journal directory's own entry in its parent (listSegments may
	// have just created it) before any record is acknowledged.
	if err := syncDirFn(dir); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("auditjournal: fsync dir %s: %w", dir, err)
	}
	if err := syncDirFn(filepath.Dir(filepath.Clean(dir))); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("auditjournal: fsync parent of %s: %w", dir, err)
	}
	w.file = f
	w.fileStartSeq = startSeq
	w.fileSize = size

	go w.runFlusher()
	return w, nil
}

// Submit appends payload, waits for its batch's group fsync, and returns
// the record's assigned sequence number. Blocks until the batch commits (or
// fails), ctx is done, or the writer is closed. A non-nil error means
// payload is NOT durable -- per ADR-115, the caller must treat this exactly
// like a failed audit write: fail closed, never disclose.
func (w *Writer) Submit(ctx context.Context, payload []byte) (uint64, error) {
	req := &appendRequest{payload: payload, done: make(chan appendResult, 1)}

	select {
	case <-w.closed:
		return 0, ErrClosed
	default:
	}
	select {
	case w.queue <- req:
	case <-w.closed:
		return 0, ErrClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	select {
	case res := <-req.done:
		return res.seq, res.err
	case <-w.flusherDone:
		// The flusher answers every request it takes before it exits, so a
		// result may already be waiting; anything else was enqueued after
		// its final drain and was never written.
		select {
		case res := <-req.done:
			return res.seq, res.err
		default:
			return 0, ErrClosed
		}
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// Close stops accepting new records, lets the flusher commit everything
// already queued, waits for it to exit, and closes the current segment.
// After Close returns the onBatch callback is never invoked again, so its
// owner may release whatever the callback writes to. Safe to call more than
// once.
func (w *Writer) Close() error {
	var err error
	w.closeOnce.Do(func() {
		close(w.closed)
		<-w.flusherDone
		if w.file != nil {
			err = w.file.Close()
		}
	})
	return err
}

// runFlusher is the single goroutine performing all file I/O for w. Mirrors
// store.runAuditFlusher's shape (bounded queue, non-blocking drain up to
// appendMaxBatch) with local-file group fsync in place of a Postgres
// transaction. It blocks for the first request of a batch, so a solo
// caller is committed immediately with no batching window.
func (w *Writer) runFlusher() {
	defer close(w.flusherDone)
	for {
		var batch []*appendRequest
		select {
		case req := <-w.queue:
			batch = append(batch, req)
		case <-w.closed:
			w.drainOnClose()
			return
		}
		batch = w.fillBatch(batch)
		w.commitBatch(batch)
	}
}

// fillBatch adds whatever is already queued to batch, up to appendMaxBatch,
// without waiting.
func (w *Writer) fillBatch(batch []*appendRequest) []*appendRequest {
	for len(batch) < appendMaxBatch {
		select {
		case req := <-w.queue:
			batch = append(batch, req)
		default:
			return batch
		}
	}
	return batch
}

// drainOnClose commits every request still queued when Close was called, so
// a caller that got its request in before Close is answered with the real
// outcome rather than stranded.
func (w *Writer) drainOnClose() {
	for {
		batch := w.fillBatch(nil)
		if len(batch) == 0 {
			return
		}
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

// rotate opens a new segment starting at w.nextSeq, makes its directory
// entry durable, and only then closes the old one. If any step fails the
// old segment stays current and the batch fails closed; the next batch
// retries the rotation instead of finding a closed file.
func (w *Writer) rotate() error {
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("auditjournal: fsync before rotate: %w", err)
	}
	path := filepath.Join(w.dir, segmentName(w.nextSeq))
	f, err := w.openSegment(path)
	if err != nil {
		return fmt.Errorf("auditjournal: open new segment %s: %w", path, err)
	}
	// The new segment's dirent must be durable before the first record in it
	// is acknowledged (see syncDir).
	if err := syncDirFn(w.dir); err != nil {
		_ = f.Close()
		return fmt.Errorf("auditjournal: fsync dir after rotate: %w", err)
	}
	old := w.file
	w.file = f
	w.fileStartSeq = w.nextSeq
	w.fileSize = 0
	if err := old.Close(); err != nil {
		return fmt.Errorf("auditjournal: close previous segment: %w", err)
	}
	return nil
}
