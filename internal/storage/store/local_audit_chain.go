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
	"encoding/binary"
	"encoding/hex"
	"errors"
	// nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used
	// Used only for retry-backoff jitter (see the #nosec G404 at its call site below), never
	// for a security-sensitive value such as a token, key, or ID.
	mathrand "math/rand"
	"strconv"
	"strings"
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

// auditBusyRetryBaseDelay/auditBusyRetryMaxDelay bound LogAuditEvent's SQLite
// busy-retry backoff (#1727) -- see that loop's own doc comment for why it
// exists. Exponential from base, capped at max, jittered by up to half the
// current delay so many goroutines released by the same lock release don't
// all retry in lockstep.
const (
	auditBusyRetryBaseDelay = 20 * time.Millisecond
	auditBusyRetryMaxDelay  = 500 * time.Millisecond
)

// isSQLiteBusyErr reports whether err looks like a SQLite writer-lock
// contention error (SQLITE_BUSY / "database is locked"). Matches the
// driver-native message text, the same approach isUniqueViolation already
// uses (local_memberships.go) since this codebase doesn't set
// gorm.Config{TranslateError: true}.
func isSQLiteBusyErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(msg, "database is locked")
}

// computeAuditEntryHash hashes an event's semantically meaningful fields plus
// prevHash, in a fixed order, each field preceded by its own big-endian
// uint64 byte length ("length-prefixed" / TLV-style encoding). The DB-assigned
// id is excluded — it is unknown before insert and chain linkage already pins
// position. event_time is encoded as Unix microseconds to round-trip
// identically on Postgres (µs precision) and SQLite.
//
// Length-prefixing (not a delimiter byte) is required for the encoding to be
// injective: several of these fields are free-form strings that can
// legitimately (or, via IngestAuditEventProxy's raw passthrough on
// SQLite-backed deployments — Postgres TEXT columns reject embedded NUL
// outright, so this was only ever live there) contain ANY byte value,
// including a delimiter byte. A single NUL-separated write() (the prior
// scheme) is then non-injective: "a\x00" + "bc" and "a" + "\x00bc" concatenate
// to the identical byte stream and therefore hash identically, even though
// the field values differ — defeating the tamper-evidence guarantee this hash
// chain exists to provide. A length prefix carried out-of-band (as a fixed-
// width binary integer, never as characters that could themselves be part of
// the content) removes that ambiguity regardless of what bytes a field
// contains.
//
// BREAKING CHANGE / no backward compatibility with pre-fix hashes: this
// encoding is NOT the same byte stream the old NUL-delimited scheme produced,
// even for a field that never contained a NUL byte — so the change is a hash-
// format break, not a content-preserving refactor. VerifyAuditChain re-derives
// every row's entry_hash from this same function (see verifyBatchEvents), so
// on any deployment that already has chained audit_events rows written before
// this fix, re-verifying those rows post-upgrade WILL recompute a different
// hash than what is stored and report the chain broken at the first pre-
// upgrade row — indistinguishable, from VerifyAuditChain's callers' point of
// view, from real tampering. There is no per-row encoding-version marker in
// the schema to let verification pick the right algorithm per row (adding one
// is a real schema migration, out of scope here), and the existing retention
// re-anchor mechanism (audit_retention_anchor.go) does not help either — it
// only substitutes the genesis-prevHash requirement for the anchored row, it
// does not skip re-deriving that row's own entry_hash. Coordinating a fix for
// deployments with pre-existing audit history (e.g. a one-time migration that
// re-derives entry_hash/prev_hash for every existing row under this new
// encoding, in ascending id order, before the upgrade takes live traffic) is
// left to the integrating release process; this change intentionally does not
// attempt that migration itself, per this change's own review discussion.
//
// #G799 (go/weak-sensitive-data-hashing, false positive): the query's dataflow
// correctly traces AccountState's AccountPasswordResetRequired constant into
// this function's Description field write, then flags SHA256 as "insecure for
// password hashing" -- but that constant is an account-status ENUM VALUE
// ("this account currently requires a password reset"), not a credential; no
// real password/secret value ever reaches this function. SHA256 is also the
// deliberately correct choice here regardless: this hash is a tamper-evidence
// chain link (integrity, not credential storage/verification), where a fast,
// deterministic, collision-resistant hash is exactly what's wanted -- a slow
// password KDF (bcrypt/argon2/scrypt) on every audit-log write would be a
// severe, pointless performance regression with no security benefit, since
// the threat model here is "detect tampering," not "resist offline brute-
// forcing a stored hash." See the `write` closure below.
func computeAuditEntryHash(e *models.AuditEvent, prevHash string) string {
	h := sha256.New()
	var lenBuf [8]byte
	write := func(s string) {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		h.Write(lenBuf[:])
		// codeql[go/weak-sensitive-data-hashing]
		h.Write([]byte(s))
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
	// #1650: detach from the caller's cancellation before the transaction below runs —
	// see auditWriteContext's doc comment for the full rationale.
	ctx, cancel := auditWriteContext(ctx)
	defer cancel()

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

	// #1727: retry a SQLite writer-lock timeout instead of surfacing it straight to
	// emitAudit, which just logs and drops it. SQLite's own _busy_timeout
	// (factory.go's sqliteBusyTimeoutMillis, 10s) already retries internally once a
	// transaction requests the write lock, but a 30-minute sustained-load
	// measurement (docs/adr-100-mlockall-removal-deployment-swap-control.md) still
	// exhausted that budget 704 times out of ~27k iterations (~2.6%): SQLite's busy
	// handler makes no fairness guarantee across competing connections, so a
	// transaction that starts AFTER the mutation it's auditing (this one, always)
	// can be repeatedly overtaken by new arrivals for the full 10s and never get a
	// turn. auditChainMu above already serializes this transaction against every
	// OTHER audit append; it does nothing against concurrent writers on unrelated
	// tables (secret_nodes, users, ...), which is where the real contention comes
	// from. A short, jittered, bounded-by-ctx backoff loop re-enters the queue on a
	// transient SQLITE_BUSY instead of giving up after one exhausted busy_timeout
	// window -- closing the gap for the dominant real-world case (transient
	// contention, not a genuinely stuck writer) without an unbounded retry storm:
	// ctx already carries auditWriteTimeout's 10s deadline (detached from the
	// caller's own cancellation above), so this loop can never outlive that.
	delay := auditBusyRetryBaseDelay
	for {
		txErr := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
		if txErr == nil || !isSQLiteBusyErr(txErr) {
			return txErr
		}
		// #nosec G404 -- jitter for retry timing, not a security-sensitive value.
		jittered := delay/2 + time.Duration(mathrand.Int63n(int64(delay/2+1)))
		select {
		case <-ctx.Done():
			return txErr
		case <-time.After(jittered):
		}
		if delay *= 2; delay > auditBusyRetryMaxDelay {
			delay = auditBusyRetryMaxDelay
		}
	}
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

// MigrateAuditChainEncoding re-derives entry_hash/prev_hash for every chained
// audit_events row under computeAuditEntryHash's current encoding, in one
// transaction spanning the whole migration (holding the same cross-process
// exclusivity LogAuditEvent uses for its own append, so no concurrently
// appended row can interleave against a partially-migrated chain). See the
// storage.Storage interface doc for the full contract, including why callers
// must still ensure no other process reaches this database concurrently.
func (ls *LocalStorage) MigrateAuditChainEncoding(ctx context.Context, dryRun bool, anchor *storage.AuditChainAnchor) (*storage.AuditChainMigrationResult, error) {
	result := &storage.AuditChainMigrationResult{}

	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(auditAdvisoryLockKey)).Error; err != nil {
				return err
			}
		}

		prevHash := auditGenesisHash
		started := false
		var lastID uint
		firstBatch := true
		firstChainedID := uint(0)
		firstChainedNewHash := ""
		anchorApplies := false

		for {
			var batch []*models.AuditEvent
			if err := tx.
				Where("id > ?", lastID).
				Order("id ASC").
				Limit(auditChainVerifyBatch).
				Find(&batch).Error; err != nil {
				return err
			}
			if len(batch) == 0 {
				break
			}
			if firstBatch {
				firstBatch = false
				// Mirror VerifyAuditChain's exact applicability rule: only seed from
				// the anchor if the earliest row that WOULD start the chain (first
				// non-empty-entry_hash row) currently carries a non-genesis
				// prev_hash — i.e. a prior purge genuinely moved the chain start.
				for _, e := range batch {
					if e.EntryHash == "" {
						continue
					}
					if anchor != nil && e.PrevHash != auditGenesisHash {
						prevHash = anchor.PrevHash
						anchorApplies = true
					}
					break
				}
			}
			for _, e := range batch {
				if !started {
					if e.EntryHash == "" {
						result.UnchainedRowsSkipped++
						continue
					}
					started = true
					firstChainedID = e.ID
				}
				newHash := computeAuditEntryHash(e, prevHash)
				if e.ID == firstChainedID {
					firstChainedNewHash = newHash
				}
				if e.PrevHash != prevHash || e.EntryHash != newHash {
					if err := tx.Model(&models.AuditEvent{}).Where("id = ?", e.ID).
						Updates(map[string]interface{}{"prev_hash": prevHash, "entry_hash": newHash}).Error; err != nil {
						return err
					}
				}
				prevHash = newHash
				result.HeadID = e.ID
				result.RowsMigrated++
			}
			lastID = batch[len(batch)-1].ID
			if len(batch) < auditChainVerifyBatch {
				break
			}
		}

		result.HeadHash = prevHash
		if anchorApplies && firstChainedID != 0 {
			// The earliest migrated row is the anchor's row; the caller must
			// re-sign the anchor with this row's newly computed entry_hash (its
			// PrevHash is unchanged — it represents an already-purged predecessor
			// that cannot be recomputed under any encoding).
			result.AnchorRowID = firstChainedID
			result.AnchorNewEntryHash = firstChainedNewHash
		}
		if dryRun {
			return errAuditMigrationDryRun
		}
		return nil
	})
	if err != nil && !errors.Is(err, errAuditMigrationDryRun) {
		return nil, err
	}
	return result, nil
}

// errAuditMigrationDryRun is a sentinel used to force MigrateAuditChainEncoding's
// transaction to roll back after computing (but never persisting) its result.
var errAuditMigrationDryRun = errors.New("audit chain migration dry run")

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
