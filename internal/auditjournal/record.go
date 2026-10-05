// Package auditjournal implements the on-disk record format and the
// append-only, group-fsync-batched writer/reader for ADR-115's local audit
// journal prototype (PERF-4): a local durability point for audit events,
// sitting in front of (not replacing) the existing Postgres/SQLite
// audit_events table and its ADR-029 hash chain.
//
// This package knows nothing about Postgres, SQLite, or the ADR-029 global
// chain -- it only durably persists and replays byte payloads, each linked
// into a journal-local, journal-scoped tamper-evidence chain (see
// computeLocalEntryHash). The caller (internal/storage/store) is responsible
// for what the payload contains and for assigning the real, global
// audit_events prev_hash/entry_hash at replay time.
package auditjournal

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// recordMagic identifies a journal record ("KAJ1" = Keyorix Audit Journal v1).
const recordMagic uint32 = 0x4B414A31

// genesisLocalHash is the local_prev_hash of the first record ever appended
// to a given journal. Distinct from store.auditGenesisHash (ADR-029's global
// chain genesis) -- this chain is journal-local and provisional, never
// written into audit_events (see this package's doc comment).
var genesisLocalHash = sha256.Sum256([]byte("keyorix-audit-journal-genesis-v1"))

// maxPayloadLen bounds how large a single record's payload may declare
// itself to be, independent of how much of the file actually follows it.
// Without this cap, a corrupted or adversarial length prefix (4 bytes, up to
// 4GiB) would make the decoder attempt a multi-gigabyte allocation before
// any other validation runs -- a trivial denial-of-service via a single
// flipped bit, not a real audit event. 16MiB is far larger than any real
// audit event (description/diff fields are human-authored text) plus a
// large margin.
const maxPayloadLen = 16 << 20

// recordFixedOverhead is every byte of a record except its payload: magic(4)
// + seq(8) + payload_len(4) + local_prev_hash(32) + local_entry_hash(32) +
// crc32(4).
const recordFixedOverhead = 4 + 8 + 4 + 32 + 32 + 4

var (
	// ErrIncomplete means the bytes available do not contain a full record --
	// the expected, non-corruption shape of a torn tail write after a crash
	// mid-append.
	ErrIncomplete = errors.New("auditjournal: incomplete record (torn tail write)")

	// ErrPayloadTooLarge means the record's declared payload_len exceeds
	// maxPayloadLen. Handled the same way as ErrIncomplete by the reader's
	// position-dependent reclassification (see reader.go) -- a bogus huge
	// length from a torn/garbage write looks like this.
	ErrPayloadTooLarge = errors.New("auditjournal: declared payload length exceeds maximum")

	// ErrCorrupt means the record's own bytes are internally inconsistent:
	// the full declared length was present, but its CRC32 or its own
	// local_entry_hash (recomputed from its stored payload+local_prev_hash)
	// does not match what was stored. The record's CONTENT was damaged after
	// (or while) being written.
	ErrCorrupt = errors.New("auditjournal: corrupt record (crc or self hash mismatch)")

	// ErrChainMismatch means the record is internally self-consistent (CRC32
	// and self hash both check out) but its stored local_prev_hash does not
	// equal the hash the reader's chain walk expected at this position --
	// i.e. these are genuine, undamaged record bytes, just not the record
	// that belongs here (a row was reordered, deleted, or spliced in from
	// elsewhere). Unlike ErrCorrupt/ErrIncomplete, this is NEVER reclassified
	// as a benign tail write, regardless of position -- fully-formed,
	// self-consistent bytes in the wrong place is not what a crash mid-write
	// produces.
	ErrChainMismatch = errors.New("auditjournal: record does not chain from the expected predecessor")
)

// Record is one decoded journal entry.
type Record struct {
	Seq            uint64
	Payload        []byte
	LocalPrevHash  [32]byte
	LocalEntryHash [32]byte
}

// computeLocalEntryHash computes this journal's own provisional, per-record
// chain link: SHA256(payload || prevHash). This is NEVER the value written
// into audit_events.entry_hash -- that is assigned by the replicator against
// the real global chain head, using the existing ADR-029
// computeAuditEntryHash encoding. This hash exists only so a journal file is
// tamper-evident on its own, before anything in it is trusted enough to
// replay.
func computeLocalEntryHash(payload []byte, prevHash [32]byte) [32]byte {
	h := sha256.New()
	h.Write(payload)
	h.Write(prevHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// encodeRecord serializes seq+payload, chained onto prevHash, into the
// on-disk record format described in ADR-115:
//
//	[4B magic][8B seq][4B payload_len][payload][32B local_prev_hash]
//	[32B local_entry_hash][4B crc32]
//
// crc32 (IEEE) covers every preceding byte of the record. Returns the
// encoded bytes and the new local_entry_hash (the next call's prevHash).
func encodeRecord(seq uint64, payload []byte, prevHash [32]byte) ([]byte, [32]byte) {
	entryHash := computeLocalEntryHash(payload, prevHash)

	buf := make([]byte, recordFixedOverhead+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], recordMagic)
	binary.BigEndian.PutUint64(buf[4:12], seq)
	binary.BigEndian.PutUint32(buf[12:16], uint32(len(payload))) // #nosec G115 -- bounded by maxPayloadLen at every call site
	copy(buf[16:16+len(payload)], payload)
	off := 16 + len(payload)
	copy(buf[off:off+32], prevHash[:])
	copy(buf[off+32:off+64], entryHash[:])
	crc := crc32.ChecksumIEEE(buf[:off+64])
	binary.BigEndian.PutUint32(buf[off+64:off+68], crc)

	return buf, entryHash
}

// decodeRecord parses exactly one record from the start of buf, checking it
// against the chain-walk's expected predecessor hash (prevHash).
//
// Returns the decoded record (best-effort populated even on error, so a
// caller like Validate can inspect Seq/Payload for diagnostics), the number
// of bytes consumed (0 when the failure is structural -- too few bytes to
// know a length), and one of: nil, ErrIncomplete, ErrPayloadTooLarge,
// ErrCorrupt, or ErrChainMismatch. See each error's doc comment for the
// distinction the reader (reader.go) relies on.
//
// This function never panics and never allocates more than maxPayloadLen for
// attacker-controlled input -- the property FuzzDecodeRecord exists to prove.
func decodeRecord(buf []byte, prevHash [32]byte) (rec Record, consumed int, err error) {
	if len(buf) < 16 {
		return Record{}, 0, ErrIncomplete
	}
	magic := binary.BigEndian.Uint32(buf[0:4])
	if magic != recordMagic {
		return Record{}, 0, ErrIncomplete
	}
	seq := binary.BigEndian.Uint64(buf[4:12])
	payloadLen := binary.BigEndian.Uint32(buf[12:16])
	if payloadLen > maxPayloadLen {
		return Record{Seq: seq}, 0, ErrPayloadTooLarge
	}
	total := recordFixedOverhead + int(payloadLen)
	if len(buf) < total {
		return Record{Seq: seq}, 0, ErrIncomplete
	}

	payload := buf[16 : 16+payloadLen]
	off := 16 + int(payloadLen)
	var localPrev, localEntry [32]byte
	copy(localPrev[:], buf[off:off+32])
	copy(localEntry[:], buf[off+32:off+64])
	storedCRC := binary.BigEndian.Uint32(buf[off+64 : off+68])

	rec = Record{Seq: seq, Payload: payload, LocalPrevHash: localPrev, LocalEntryHash: localEntry}
	consumed = total

	computedCRC := crc32.ChecksumIEEE(buf[:off+64])
	if computedCRC != storedCRC {
		return rec, consumed, ErrCorrupt
	}
	if computeLocalEntryHash(payload, localPrev) != localEntry {
		return rec, consumed, ErrCorrupt
	}
	if localPrev != prevHash {
		return rec, consumed, ErrChainMismatch
	}
	return rec, consumed, nil
}

// selfConsistent reports whether buf begins with a record whose CRC32 and
// self hash both check out, WITHOUT regard to chain linkage -- i.e. decoding
// via decodeRecord returns nil or ErrChainMismatch. Used by Validate's
// forward resync scan to tell "fully-formed bytes exist later in the file"
// (mid-journal corruption) apart from "nothing valid follows" (a benign torn
// tail write) -- see that function's doc comment.
func selfConsistent(buf []byte) bool {
	_, _, err := decodeRecord(buf, [32]byte{})
	return err == nil || errors.Is(err, ErrChainMismatch)
}
