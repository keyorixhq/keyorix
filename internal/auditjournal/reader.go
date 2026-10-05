package auditjournal

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// segmentExt is the extension for journal segment files. Segments are named
// by the starting sequence number of their first record, zero-padded to 20
// digits (covers the full uint64 range) so a plain lexical directory sort is
// also a numeric sort.
const segmentExt = ".seg"

// segmentFile is one on-disk segment, named by the sequence number of its
// first record.
type segmentFile struct {
	Path     string
	StartSeq uint64
}

func segmentName(startSeq uint64) string {
	return fmt.Sprintf("%020d%s", startSeq, segmentExt)
}

// listSegments returns every segment file in dir, sorted by StartSeq
// ascending. dir is created if it does not exist.
func listSegments(dir string) ([]segmentFile, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("auditjournal: create dir: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("auditjournal: read dir: %w", err)
	}
	var segs []segmentFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), segmentExt) {
			continue
		}
		numPart := strings.TrimSuffix(e.Name(), segmentExt)
		startSeq, err := strconv.ParseUint(numPart, 10, 64)
		if err != nil {
			continue // not one of ours
		}
		segs = append(segs, segmentFile{Path: filepath.Join(dir, e.Name()), StartSeq: startSeq})
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].StartSeq < segs[j].StartSeq })
	return segs, nil
}

// CorruptionError is returned by Validate when it finds damage to
// already-written, previously-acknowledged journal data -- as opposed to a
// benign torn tail write, which Validate repairs silently (see its doc
// comment). Per ADR-115, this must stop the journal (and, upstream, the
// server) from being used, not be auto-repaired.
type CorruptionError struct {
	Segment string // path of the segment containing the bad record
	Offset  int64  // byte offset within Segment where the bad record starts
	Reason  error  // the underlying decode error (ErrCorrupt or ErrChainMismatch)
}

func (e *CorruptionError) Error() string {
	return fmt.Sprintf("auditjournal: corruption detected in %s at offset %d: %v", e.Segment, e.Offset, e.Reason)
}

func (e *CorruptionError) Unwrap() error { return e.Reason }

// segBuf pairs a segment's identity with its fully-read bytes, for
// Validate's in-memory scan.
type segBuf struct {
	seg  segmentFile
	data []byte
}

// ValidationResult is Validate's report of a journal's health.
type ValidationResult struct {
	// Records holds every valid record found, across all segments, in
	// ascending Seq order.
	Records []Record
	// HeadLocalHash is the LocalEntryHash of the last valid record (or the
	// genesis constant if Records is empty) -- the chain's current head,
	// i.e. the prevHash the next Append call must chain onto.
	HeadLocalHash [32]byte
	// NextSeq is the sequence number the next appended record should use.
	NextSeq uint64
	// TruncatedTailBytes is how many trailing bytes of the last segment were
	// discarded as an incomplete, never-acknowledged tail write (0 if the
	// journal's last segment ended exactly on a record boundary). Validate
	// performs this truncation itself -- see its doc comment.
	TruncatedTailBytes int64
}

// Validate walks every segment in dir, in order, re-deriving the journal's
// local tamper-evidence chain from genesis and classifying the FIRST failure
// it finds (if any) as one of two things, per ADR-115:
//
//   - A benign, incomplete tail write: the failing record is followed by
//     NOTHING that decodes as a self-consistent record (CRC32 + self hash
//     check out, see selfConsistent) anywhere later in the journal. This is
//     exactly what a crash mid-append produces -- the group-fsync protocol
//     only acknowledges a caller after a WHOLE batch's fsync succeeds, so a
//     torn record at the physical end of the journal can only be in-flight,
//     unacknowledged data. Validate REPAIRS this itself: it truncates the
//     last segment at the last verified-good record boundary and returns
//     successfully (TruncatedTailBytes records how much was discarded).
//   - Corruption: the failing record IS followed, somewhere before the
//     journal's true end, by a self-consistent record -- i.e. there is
//     intact-looking data on the far side of the failure, which a simple
//     tail-crash cannot produce (an append-only writer physically cannot
//     write bytes, then a crash, then MORE self-consistent bytes). Validate
//     returns a *CorruptionError and performs NO repair -- per ADR-115 this
//     must stop the server from disclosing secrets until an operator
//     investigates, exactly as refuseIfAuditChainBroken already does for
//     the DB-side chain (ADR-029).
//
// An ErrChainMismatch failure (self-consistent bytes in the wrong place) is
// always corruption, regardless of position -- see that error's doc comment.
func Validate(dir string) (*ValidationResult, error) {
	segs, err := listSegments(dir)
	if err != nil {
		return nil, err
	}
	result := &ValidationResult{HeadLocalHash: genesisLocalHash}
	if len(segs) == 0 {
		return result, nil
	}

	bufs := make([]segBuf, len(segs))
	for i, s := range segs {
		data, err := os.ReadFile(s.Path) // #nosec G304 -- dir is operator-configured, not user input
		if err != nil {
			return nil, fmt.Errorf("auditjournal: read segment %s: %w", s.Path, err)
		}
		bufs[i] = segBuf{seg: s, data: data}
	}

	prevHash := genesisLocalHash
	var nextSeq uint64
	for i, sb := range bufs {
		off := int64(0)
		buf := sb.data
		for len(buf) > 0 {
			rec, consumed, decErr := decodeRecord(buf, prevHash)
			if decErr == nil {
				result.Records = append(result.Records, rec)
				prevHash = rec.LocalEntryHash
				nextSeq = rec.Seq + 1
				buf = buf[consumed:]
				off += int64(consumed)
				continue
			}

			if decErr == ErrChainMismatch { //nolint:errorlint // sentinel comparison intentional, decodeRecord never wraps
				return nil, &CorruptionError{Segment: sb.seg.Path, Offset: off, Reason: decErr}
			}

			// decErr is ErrIncomplete/ErrPayloadTooLarge/ErrCorrupt: decide
			// whether anything self-consistent follows, anywhere later in
			// THIS segment or any later one.
			if validateHasLaterSelfConsistentRecord(bufs, i, off+1) {
				return nil, &CorruptionError{Segment: sb.seg.Path, Offset: off, Reason: decErr}
			}

			// Benign tail: truncate this segment at off and stop scanning
			// entirely (nothing after a torn tail write is ever trusted,
			// and by construction there are no further segments once this
			// is reached -- segment rotation only ever happens at a clean
			// record boundary, never mid-record).
			discarded := int64(len(sb.data)) - off
			if discarded > 0 {
				if err := truncateSegment(sb.seg.Path, off); err != nil {
					return nil, fmt.Errorf("auditjournal: truncate incomplete tail of %s: %w", sb.seg.Path, err)
				}
			}
			result.TruncatedTailBytes = discarded
			result.HeadLocalHash = prevHash
			result.NextSeq = nextSeq
			return result, nil
		}
	}

	result.HeadLocalHash = prevHash
	result.NextSeq = nextSeq
	return result, nil
}

// validateHasLaterSelfConsistentRecord scans forward from (segs[fromSeg],
// byte offset fromOff) through the rest of fromSeg and every later segment,
// byte by byte, looking for a position where selfConsistent reports a
// fully-formed record. This is deliberately a brute-force resync scan (try
// every offset, not just record-aligned ones) -- the whole point is to
// detect bytes that happen to look like a valid record even though the
// reader's own sequential walk lost alignment at the failure point.
func validateHasLaterSelfConsistentRecord(bufs []segBuf, fromSeg int, fromOff int64) bool {
	for i := fromSeg; i < len(bufs); i++ {
		data := bufs[i].data
		start := int64(0)
		if i == fromSeg {
			start = fromOff
		}
		for p := start; p < int64(len(data)); p++ {
			if selfConsistent(data[p:]) {
				return true
			}
		}
	}
	return false
}

// truncateSegment discards every byte of path at or after offset off,
// fsyncing the truncated file so the repair itself is durable before
// Validate's caller resumes appending.
func truncateSegment(path string, off int64) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600) // #nosec G304 -- path comes from listSegments within an operator-configured dir
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := f.Truncate(off); err != nil {
		return err
	}
	return f.Sync()
}
