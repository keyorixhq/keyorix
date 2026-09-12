// audit_chain_legacy_hash.go — the frozen pre-#1452 audit entry-hash encoding.
//
// #1452 (2026-08-16) replaced the NUL-delimited field encoding with a
// length-prefixed one, because the old scheme was not injective: a single
// NUL-separated write means "a\x00" + "bc" and "a" + "\x00bc" produce the
// identical byte stream and therefore the identical hash, so two different
// event contents could share an entry_hash. That fix was correct and is not
// revisited here.
//
// What the fix left behind is the need to READ history. Every audit_events row
// written before it carries a hash under the old encoding, and until #1474's
// one-time re-encoding runs, those rows are the only record there is. Without
// this function the current code cannot tell a legitimately old-encoded row
// from a tampered one -- it only knows the stored hash is not the hash it would
// compute now -- which is what let MigrateAuditChainEncoding rewrite tampered
// rows as readily as stale ones, and what made VerifyAuditChain report
// "event modified" after an ordinary upgrade.
//
// THIS FUNCTION MUST NEVER CHANGE. It is not "the hash function, previous
// version"; it is a description of bytes that already exist on disk in
// deployments we do not control. Refactoring it to share code with
// computeAuditEntryHash would mean a future change to the live encoder
// silently rewrites what history is understood to have said -- the precise
// failure this file exists to prevent. It is deliberately a verbatim copy,
// duplication and all.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ComputeAuditEntryHashPre1452 reproduces the entry-hash derivation exactly as
// it stood immediately before commit 8425f9dc (#1452): each field written
// followed by a single NUL byte, in the same field order the current encoding
// still uses. Verbatim, including the closures, so it can be diffed against
// `git show 8425f9dc^:internal/storage/store/local_audit_chain.go` line for
// line by anyone checking this claim.
// Exported solely so tests in other packages (internal/core's migration
// coverage) can build fixtures carrying GENUINE pre-#1452 hashes. Those tests
// previously wrote the literal string "legacy-"+hash[:16], which is not a hash
// under any encoding, so they proved only that the migration overwrites
// arbitrary bytes. Nothing in production calls this; it reads history, it never
// writes it.
func ComputeAuditEntryHashPre1452(e *models.AuditEvent, prevHash string) string {
	h := sha256.New()
	write := func(s string) {
		// codeql[go/weak-sensitive-data-hashing]
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	uptr := func(p *uint) string {
		if p == nil {
			return ""
		}
		return strconv.FormatUint(uint64(*p), 10)
	}
	bptr := func(p *bool) string {
		if p == nil {
			return ""
		}
		return strconv.FormatBool(*p)
	}

	write(prevHash)
	write(e.EventType)
	write(uptr(e.UserID))
	write(uptr(e.SecretNodeID))
	write(uptr(e.ProjectID))
	write(e.IPAddress)
	write(e.Description)
	write(bptr(e.Success))
	write(strconv.FormatInt(e.EventTime.UnixMicro(), 10))
	write(e.Diff)
	write(uptr(e.ImpersonatedBy))
	write(uptr(e.ActingAs))
	write(strconv.FormatBool(e.Impersonation))
	write(e.ActorType)
	return hex.EncodeToString(h.Sum(nil))
}

// auditEntryHashMatchesAnyKnownEncoding reports whether e's stored entry_hash
// is what EITHER the current or the pre-#1452 encoding derives from e's own
// contents and stored prev_hash.
//
// "Either" is deliberate and is not a weakening. A deployment that upgraded and
// then took live traffic before running the re-encoding has a chain whose older
// rows are legacy-encoded and whose newer rows are current-encoded; every one of
// those rows is honest. Requiring a single encoding across the whole chain would
// refuse that database, and refusing a legitimate migration teaches operators to
// reach for a force flag. A row that matches NEITHER encoding is the real signal:
// its stored hash corresponds to no derivation this code has ever produced from
// those contents.
func auditEntryHashMatchesAnyKnownEncoding(e *models.AuditEvent) bool {
	return computeAuditEntryHash(e, e.PrevHash) == e.EntryHash ||
		ComputeAuditEntryHashPre1452(e, e.PrevHash) == e.EntryHash
}
