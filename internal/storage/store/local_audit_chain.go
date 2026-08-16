// local_audit_chain.go — tamper-evidence hash chain over audit_events (ADR-029).
//
// Each audit event stores prev_hash (the prior chained event's entry_hash, or a
// genesis constant for the first) and entry_hash = SHA256(canonical(fields) ‖
// prev_hash). Any modification, deletion, insertion, or reordering of audit
// rows breaks the chain and is detected by VerifyAuditChain.
//
// Appends are serialized (process mutex + a Postgres transaction-scoped advisory
// lock) so the read-chain-head + insert critical section is atomic even though
// audit events are emitted from concurrent goroutines.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// auditGenesisHash is the prev_hash of the first chained event. A fixed, visibly
// non-real 64-hex-char constant so the chain has a deterministic anchor.
const auditGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// auditAdvisoryLockKey is the Postgres advisory-lock key guarding audit appends
// across processes (arbitrary constant, namespaced to this use).
const auditAdvisoryLockKey = 0x4B455941_55444954 // "KEYAUDIT"

// auditChainVerifyBatch bounds memory when re-walking the chain.
const auditChainVerifyBatch = 1000

// computeAuditEntryHash hashes an event's semantically meaningful fields plus
// prevHash, in a fixed order with null separators (so field boundaries are
// unambiguous). The DB-assigned id is excluded — it is unknown before insert and
// chain linkage already pins position. event_time is encoded as Unix
// microseconds to round-trip identically on Postgres (µs precision) and SQLite.
func computeAuditEntryHash(e *models.AuditEvent, prevHash string) string {
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

// LogAuditEvent appends an audit event, linking it into the tamper-evidence
// hash chain (ADR-029). The read-chain-head + insert is serialized so the chain
// stays well-formed under concurrent writers.
func (ls *LocalStorage) LogAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	// Truncate to microseconds before both hashing and storage so the stored
	// timestamp equals the hashed one on every backend (Postgres timestamptz is
	// µs-precision; an un-truncated nanosecond time would not round-trip).
	event.EventTime = event.EventTime.Truncate(time.Microsecond)

	// Normalize ActorType to the column default ("user", see models.AuditEvent)
	// BEFORE hashing. The hash covers ActorType, but the row is stored via GORM,
	// whose `default:user` tag rewrites an empty value to "user" at insert. Without
	// this, a caller that leaves ActorType unset (e.g. the sharing/impersonation
	// audit helpers) hashes over "" yet persists "user", so VerifyAuditChain later
	// recomputes over the stored "user" and false-fails an untampered chain. Pinning
	// the value here keeps the hashed and stored ActorType identical for every caller.
	if event.ActorType == "" {
		event.ActorType = "user"
	}

	// Same round-trip hazard for Success (`default:true`, models.AuditEvent): the
	// hash covers Success, but GORM rewrites a nil *bool to true at insert. Callers
	// that leave Success unset (every sharing_audit.go helper) would hash over ""
	// yet persist "true", so VerifyAuditChain recomputes over the stored true and
	// false-fails an untampered chain. Pin it to the column default before hashing.
	if event.Success == nil {
		t := true
		event.Success = &t
	}

	ls.auditChainMu.Lock()
	defer ls.auditChainMu.Unlock()

	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Cross-process serialization for multi-instance Postgres; no-op on SQLite.
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(auditAdvisoryLockKey)).Error; err != nil {
				return err
			}
		}

		var head struct{ EntryHash string }
		if err := tx.Model(&models.AuditEvent{}).
			Select("entry_hash").
			Order("id DESC").
			Limit(1).
			Scan(&head).Error; err != nil {
			return err
		}
		prev := head.EntryHash
		if prev == "" {
			prev = auditGenesisHash
		}

		event.PrevHash = prev
		event.EntryHash = computeAuditEntryHash(event, prev)
		return tx.Create(event).Error
	})
}

// VerifyAuditChain re-walks the hash chain by ascending id in bounded batches.
// A leading run of legacy rows (empty entry_hash, pre-ADR-029) is counted as an
// unchained prefix. From the first chained row, each row's prev_hash must equal
// the running previous entry_hash (genesis for the first) and its entry_hash
// must recompute from its stored fields. The first divergence stops the walk.
//
// anchor, when non-nil, is an ALREADY-AUTHENTICATED re-anchor point (see
// storage.AuditChainAnchor) written by a retention purge that removed the
// original earliest rows. This method trusts it literally — it does not, and
// cannot, re-verify its signature (no signing key at this layer); the caller
// must have done that. When the earliest surviving row's own prev_hash is
// still genesis (the purge only removed the unchained legacy prefix, emptied
// the table, or no purge ever ran), the anchor is superfluous and ignored —
// the walk proceeds exactly as it always has.
func (ls *LocalStorage) VerifyAuditChain(ctx context.Context, anchor *storage.AuditChainAnchor) (*storage.AuditChainVerification, error) {
	result := &storage.AuditChainVerification{Valid: true}

	prevHash := auditGenesisHash
	started := false
	var lastID uint
	var headID uint
	firstBatch := true

	for {
		var batch []*models.AuditEvent
		if err := ls.db.WithContext(ctx).
			Where("id > ?", lastID).
			Order("id ASC").
			Limit(auditChainVerifyBatch).
			Find(&batch).Error; err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		if firstBatch {
			firstBatch = false
			if head := batch[0]; anchor != nil && head.PrevHash != auditGenesisHash {
				if head.EntryHash == "" || head.ID != anchor.RowID ||
					head.PrevHash != anchor.PrevHash || head.EntryHash != anchor.EntryHash {
					brokenChain(result, head.ID,
						"earliest surviving audit row does not match the last retention re-anchor (rows removed outside a sanctioned purge, or the re-anchor is stale)")
					return result, nil
				}
				// The anchor authenticates head's prev_hash as a legitimate chain
				// position established before its predecessors were purged — seed
				// the walk from there instead of requiring genesis.
				prevHash = anchor.PrevHash
				started = true
			}
		}
		newPrev, newHead, newStarted, broke := verifyBatchEvents(batch, prevHash, started, result)
		if broke {
			return result, nil
		}
		prevHash, headID, started = newPrev, newHead, newStarted
		lastID = batch[len(batch)-1].ID
		if len(batch) < auditChainVerifyBatch {
			break
		}
	}

	// Record the verified head so an external monitor can anchor on it and detect
	// tail-truncation / re-seed (which a self-consistent shorter chain otherwise
	// passes). prevHash holds the last chained entry_hash, or genesis if none.
	result.HeadHash = prevHash
	result.HeadID = headID
	return result, nil
}

// verifyBatchEvents processes one page of audit events against the running hash chain.
// Returns the new prevHash, the last verified headID, the updated started flag, and
// whether a chain break was detected (in which case result is already marked broken).
func verifyBatchEvents(batch []*models.AuditEvent, prevHash string, started bool, result *storage.AuditChainVerification) (newPrev string, headID uint, newStarted bool, broke bool) {
	for _, e := range batch {
		if !started {
			if e.EntryHash == "" {
				result.UnchainedEvents++
				continue
			}
			started = true
		}
		if e.EntryHash == "" {
			brokenChain(result, e.ID, "missing entry hash on a chained event (chain data removed)")
			return prevHash, headID, started, true
		}
		if e.PrevHash != prevHash {
			brokenChain(result, e.ID, "prev_hash does not link to the preceding event (row inserted, deleted, or reordered)")
			return prevHash, headID, started, true
		}
		if computeAuditEntryHash(e, e.PrevHash) != e.EntryHash {
			brokenChain(result, e.ID, "entry_hash does not match the event contents (event modified)")
			return prevHash, headID, started, true
		}
		prevHash = e.EntryHash
		headID = e.ID
		result.ChainedEvents++
	}
	return prevHash, headID, started, false
}

// brokenChain marks a verification result as failed at the given event.
func brokenChain(r *storage.AuditChainVerification, id uint, reason string) *storage.AuditChainVerification {
	r.Valid = false
	idCopy := id
	r.FirstBrokenID = &idCopy
	r.Reason = reason
	return r
}
