// audit_legacy_hash.go — the frozen pre-#1452 audit entry-hash encoding, read
// only by accept-loss to tell an un-migrated row from a lost or modified one.
//
// THIS FUNCTION MUST NEVER CHANGE: it describes bytes already on disk in
// deployments we do not control. It is a verbatim copy of
// internal/storage/store.ComputeAuditEntryHashPre1452 (core may not import the
// store) and of internal/auditverify.ComputeEntryHashPre1452 (auditverify pulls
// in internal/notary, which ADR-109 keeps out of core's dependencies).
// TestAuditEntryHashPre1452_MatchesStoreAndAuditverify fails if a copy drifts.
package core

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditEntryHashPre1452 re-derives e's entry hash under the pre-#1452
// (NUL-terminated) encoding, from prevHash.
func auditEntryHashPre1452(e *models.AuditEvent, prevHash string) string {
	h := sha256.New()
	write := func(s string) {
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

// auditEntryHashIsPre1452 reports whether e's stored entry_hash is what the
// pre-#1452 encoding derives from e's own contents and stored prev_hash.
func auditEntryHashIsPre1452(e *models.AuditEvent) bool {
	return e.EntryHash != "" && auditEntryHashPre1452(e, e.PrevHash) == e.EntryHash
}
