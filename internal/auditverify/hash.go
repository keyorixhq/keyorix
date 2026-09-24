package auditverify

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

// GenesisHash is the prev_hash of the first chained event — a fixed,
// visibly non-real 64-hex-char constant so the chain has a deterministic
// anchor. Must byte-for-byte match internal/storage/store's own
// auditGenesisHash; a differential test elsewhere in this module asserts
// that.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

func auditRowUintPtr(p *uint64) string {
	if p == nil {
		return ""
	}
	return strconv.FormatUint(*p, 10)
}

func auditRowBoolPtr(p *bool) string {
	if p == nil {
		return ""
	}
	return strconv.FormatBool(*p)
}

// ComputeEntryHash re-derives an audit row's entry_hash under the current
// (length-prefixed, post-#1452) encoding: SHA256 over each semantically
// meaningful field, in a fixed order, each preceded by its own big-endian
// uint64 byte length, followed by prevHash. This is an independent
// reimplementation of internal/storage/store's unexported
// computeAuditEntryHash — same field order, same encoding — verified
// byte-identical over shared fixtures by this module's differential test.
// It deliberately does NOT hash MachineIdentityID: neither does the
// original function, so duplicating that omission is required, not an
// oversight.
func ComputeEntryHash(e *AuditEventRow, prevHash string) string {
	h := sha256.New()
	var lenBuf [8]byte
	write := func(s string) {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		h.Write(lenBuf[:])
		h.Write([]byte(s))
	}

	write(prevHash)
	write(e.EventType)
	write(auditRowUintPtr(e.UserID))
	write(auditRowUintPtr(e.SecretNodeID))
	write(auditRowUintPtr(e.ProjectID))
	write(e.IPAddress)
	write(e.Description)
	write(auditRowBoolPtr(e.Success))
	write(strconv.FormatInt(e.EventTime.UnixMicro(), 10))
	write(e.Diff)
	write(auditRowUintPtr(e.ImpersonatedBy))
	write(auditRowUintPtr(e.ActingAs))
	write(strconv.FormatBool(e.Impersonation))
	write(e.ActorType)
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeEntryHashPre1452 reproduces the entry-hash derivation exactly as it
// stood immediately before commit 8425f9dc (#1452): each field NUL-
// terminated (not length-prefixed), in the same field order the current
// encoding still uses. Verbatim duplication of
// internal/storage/store.ComputeAuditEntryHashPre1452 — see that function's
// own doc comment for why it must never change. Needed here so an offline
// verifier run against a deployment that has not yet run the one-time
// re-encoding (the common case, not a corner case) can tell a legitimately
// old-encoded row from a tampered one, exactly as the online code does.
func ComputeEntryHashPre1452(e *AuditEventRow, prevHash string) string {
	h := sha256.New()
	write := func(s string) {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}

	write(prevHash)
	write(e.EventType)
	write(auditRowUintPtr(e.UserID))
	write(auditRowUintPtr(e.SecretNodeID))
	write(auditRowUintPtr(e.ProjectID))
	write(e.IPAddress)
	write(e.Description)
	write(auditRowBoolPtr(e.Success))
	write(strconv.FormatInt(e.EventTime.UnixMicro(), 10))
	write(e.Diff)
	write(auditRowUintPtr(e.ImpersonatedBy))
	write(auditRowUintPtr(e.ActingAs))
	write(strconv.FormatBool(e.Impersonation))
	write(e.ActorType)
	return hex.EncodeToString(h.Sum(nil))
}

// EntryHashMatchesAnyKnownEncoding reports whether e's stored EntryHash is
// what EITHER the current or the pre-#1452 encoding derives from e's own
// contents and stored PrevHash. Mirrors
// internal/storage/store.auditEntryHashMatchesAnyKnownEncoding — see its doc
// comment for why "either" is deliberate and not a weakening.
func EntryHashMatchesAnyKnownEncoding(e *AuditEventRow) bool {
	return ComputeEntryHash(e, e.PrevHash) == e.EntryHash ||
		ComputeEntryHashPre1452(e, e.PrevHash) == e.EntryHash
}
