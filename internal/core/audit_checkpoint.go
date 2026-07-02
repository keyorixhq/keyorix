// audit_checkpoint.go — signed checkpoints over the audit hash chain (ADR-029).
//
// The hash chain alone makes any modification/insertion/deletion of a present
// row detectable, but an unanchored on-box re-walk cannot catch tail-truncation
// or a genesis re-seed: a shorter, self-consistent chain still verifies. A
// checkpoint closes that gap on-box. It records (chained_events, head_id,
// head_hash) and signs them with an HMAC keyed by a DEK-derived key the running
// server holds in memory but the database/DBA does not (see
// encryption.Service.AuditCheckpointKey). Verifying the live chain against the
// latest signed checkpoint then detects a drop below the certified length or a
// rewrite of the certified head — tampering a DB-level actor cannot hide without
// the signing key.
package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/notary"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditHighWaterKey is the system_metadata key holding the signed audit high-water
// mark — the greatest chained-events count ever certified. Unlike the append-only
// checkpoint rows, this is a SINGLE overwritten row, so an attacker cannot "delete the
// newer ones" to surface an older authentic checkpoint: the high-water always attests
// the maximum reached. Lowering it requires the signing key (forgery-proof); leaving it
// while truncating the chain is caught as a regression; deleting it mid-run is caught by
// the in-memory watermark. See ADR-029.
const auditHighWaterKey = "audit_checkpoint_highwater" // #nosec G101 -- metadata key name, not a credential

// SetAuditCheckpointKey wires the DEK-derived HMAC key (and the DEK key version
// it was derived from) used to sign and verify audit checkpoints. Called at
// startup when encryption is enabled; with no key set, checkpoints are
// unavailable and VerifyAuditChain runs without on-box checkpoint enforcement.
func (c *KeyorixCore) SetAuditCheckpointKey(key []byte, keyVersion string) {
	c.auditCkptKey = key
	c.auditCkptKeyVersion = keyVersion
}

// AuditCheckpointsAvailable reports whether signed checkpoints can be written
// (i.e. a signing key is configured — encryption is enabled).
func (c *KeyorixCore) AuditCheckpointsAvailable() bool {
	return len(c.auditCkptKey) > 0
}

// SeedAuditWatermark loads the persisted high-water mark into the in-memory watermark
// at startup, so anti-rollback survives a process restart. Without this the in-memory
// watermark resets to 0 on every restart, and an attacker who deleted/garbled the
// persistent mark before a restart could then truncate the trail undetected (the
// restart erases the only remaining proof of the certified length). Best-effort: a read
// error or absent/invalid mark leaves the watermark at 0 (and a missing mark while
// checkpoints exist is separately flagged as tamper by enforceAuditHighWater).
func (c *KeyorixCore) SeedAuditWatermark(ctx context.Context) {
	if !c.AuditCheckpointsAvailable() {
		return
	}
	floor, _, _, _, err := c.auditHighWaterFloor(ctx)
	if err != nil {
		log.Printf("audit high-water: failed to seed in-memory watermark at startup: %v", err)
		return
	}
	c.bumpWatermark(floor)
}

// checkpointExists reports whether any signed checkpoint row exists — i.e. whether
// checkpointing has ever been initialized for this trail. Once it has, the persistent
// high-water mark must exist too (advanceAuditHighWater writes it with every
// checkpoint), so a missing/malformed mark alongside an existing checkpoint is tampering.
func (c *KeyorixCore) checkpointExists(ctx context.Context) (bool, error) {
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return false, err
	}
	return cp != nil, nil
}

// SetCheckpointNotary wires an external notary (RFC 3161 TSA) that anchors each
// freshly-written checkpoint for a forge-proof proof-of-existence (ADR-029).
// Called at startup when audit.checkpoint_notary is enabled; left unset, no
// external anchoring is performed.
func (c *KeyorixCore) SetCheckpointNotary(n notary.Notary) {
	c.checkpointNotary = n
}

// SetCheckpointAnchorRoots wires the trusted TSA root pool used to verify stored
// checkpoint anchors (the issuer trust anchor). Without it, VerifyCheckpointAnchor
// fails closed rather than trusting an unverifiable token.
func (c *KeyorixCore) SetCheckpointAnchorRoots(roots *x509.CertPool) {
	c.checkpointAnchorRoots = roots
}

// anchorCheckpoint best-effort anchors a checkpoint's canonical bytes with the
// configured notary and persists the receipt on the row. A notary/storage failure
// is logged and swallowed: an unanchored checkpoint is still a valid checkpoint,
// and the next write retries — anchoring must never fail checkpointing.
func (c *KeyorixCore) anchorCheckpoint(ctx context.Context, cp *models.AuditCheckpoint) {
	if c.checkpointNotary == nil {
		return
	}
	rec, err := c.checkpointNotary.Anchor(ctx, []byte(checkpointCanonical(cp)))
	if err != nil {
		log.Printf("audit checkpoint #%d: external anchor failed (left unanchored): %v", cp.ID, err)
		return
	}
	if err := c.storage.UpdateAuditCheckpointAnchor(ctx, cp.ID, rec.Token, rec.Time, rec.Provider); err != nil {
		log.Printf("audit checkpoint #%d: anchored but failed to persist receipt: %v", cp.ID, err)
		return
	}
	at := rec.Time
	cp.AnchorToken = rec.Token
	cp.AnchoredAt = &at
	cp.AnchorProvider = rec.Provider
}

// VerifyCheckpointAnchor re-verifies a checkpoint's external-notary receipt: it
// confirms the stored RFC 3161 token is valid and bound to this exact checkpoint
// (its canonical bytes), returning the authority-asserted time. ok is false with a
// nil error when the checkpoint carries no anchor (none was configured/succeeded).
func (c *KeyorixCore) VerifyCheckpointAnchor(cp *models.AuditCheckpoint) (anchoredAt time.Time, ok bool, err error) {
	if cp == nil || len(cp.AnchorToken) == 0 {
		return time.Time{}, false, nil
	}
	at, err := notary.VerifyReceipt(c.checkpointAnchorRoots, []byte(checkpointCanonical(cp)), cp.AnchorToken)
	if err != nil {
		return time.Time{}, true, err
	}
	return at, true, nil
}

// WriteAuditCheckpoint verifies the audit chain and, if it is intact, appends a
// fresh signed checkpoint of the current head. It returns (nil, false, nil) when
// checkpoints are unavailable (no signing key / encryption disabled), and an
// error when the chain does not verify — refusing to notarise a tampered state,
// and refusing to re-baseline over a truncation already flagged by an existing
// checkpoint (VerifyAuditChain enforces prior checkpoints).
func (c *KeyorixCore) WriteAuditCheckpoint(ctx context.Context) (*models.AuditCheckpoint, bool, error) {
	if !c.AuditCheckpointsAvailable() {
		return nil, false, nil
	}
	// Verify the raw chain (walk only, no checkpoint enforcement) so we never sign
	// a head over a broken chain.
	raw, err := c.storage.VerifyAuditChain(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to verify audit chain: %w", err)
	}
	if !raw.Valid {
		return nil, false, fmt.Errorf("refusing to checkpoint a chain that does not verify: %s", raw.Reason)
	}
	// Refuse to re-baseline over a truncation that an AUTHENTICATED prior checkpoint
	// proves — otherwise a scheduled write would silently bless a shortened chain and
	// erase the evidence. An unverifiable prior checkpoint (a stale one after a DEK
	// rotation) does not block re-baselining; that is how the system recovers from a
	// key rotation.
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return nil, false, err
	}
	if cp != nil {
		if c.checkpointSignatureValid(cp) {
			if reason, tampered, err := c.checkpointTruncation(ctx, raw.ChainedEvents, cp); err != nil {
				return nil, false, err
			} else if tampered {
				return nil, false, fmt.Errorf("refusing to checkpoint: %s", reason)
			}
		} else if cp.KeyVersion == c.auditCkptKeyVersion {
			// The prior checkpoint claims the CURRENT signing-key version yet fails its
			// signature. That is tampering, not a DEK rotation (a rotation would carry a
			// superseded key_version). Re-baselining here would let a DB-level actor
			// launder a tail-truncation by flipping one signature byte: the read path
			// flags this as Valid=false, but a silent re-baseline would write a fresh,
			// authentic checkpoint over the shortened chain and erase that signal. Fail
			// closed and leave the tamper signal standing for an operator to investigate.
			return nil, false, fmt.Errorf("refusing to checkpoint: latest checkpoint #%d fails its signature under the current key version %q — the checkpoint row was tampered with, not rotated", cp.ID, cp.KeyVersion)
		}
		// else: signature fails AND key_version is superseded → consistent with a DEK
		// rotation; fall through and re-baseline under the new key (recovery path).
	}
	// Refuse to checkpoint a chain that sits below the certified high-water mark —
	// otherwise a scheduled write would launder a truncation into a fresh, authentic
	// checkpoint (and a fresh high-water), erasing the rollback evidence.
	floor, _, hwTampered, hwReason, err := c.auditHighWaterFloor(ctx)
	if err != nil {
		return nil, false, err
	}
	if hwTampered {
		return nil, false, fmt.Errorf("refusing to checkpoint: %s", hwReason)
	}
	if raw.ChainedEvents < floor {
		return nil, false, fmt.Errorf("refusing to checkpoint: the audit trail (%d events) is below the certified high-water mark (%d) — a truncation must be investigated, not re-baselined", raw.ChainedEvents, floor)
	}
	newCP := &models.AuditCheckpoint{
		ChainedEvents: raw.ChainedEvents,
		HeadID:        raw.HeadID,
		HeadHash:      raw.HeadHash,
		KeyVersion:    c.auditCkptKeyVersion,
	}
	newCP.Signature = c.signCheckpoint(newCP)
	if err := c.storage.CreateAuditCheckpoint(ctx, newCP); err != nil {
		return nil, false, fmt.Errorf("failed to write audit checkpoint: %w", err)
	}
	// Best-effort external anchor (RFC 3161) — never fails the checkpoint write.
	c.anchorCheckpoint(ctx, newCP)
	// Advance the persistent + in-memory high-water mark to this certified length.
	c.advanceAuditHighWater(ctx, newCP)
	return newCP, true, nil
}

// enforceAuditCheckpoint augments a chain-walk verdict with on-box checkpoint
// verification. It loads the latest checkpoint and authenticates it with the
// current signing key FIRST: the HMAC covers every field (including key_version),
// so nothing the checkpoint claims is trusted until the signature verifies. A row
// altered without the key fails here — there is no field a DB-level actor can set
// to skip enforcement. Once authenticated, the live chain must still be at least
// as long as the checkpoint certified, with the certified head row unchanged; any
// shortfall or head rewrite flips Valid to false.
//
// A signature that does not verify is treated as a tamper signal (Valid=false). It
// also fires for a stale checkpoint signed under a superseded DEK version after a
// key rotation — by design: we cannot re-verify an old-key signature on-box, and
// silently trusting the unauthenticated key_version field would reopen the bypass.
// WriteAuditCheckpoint re-baselines under the new key (it does not block on an
// unverifiable checkpoint), clearing the state on the next checkpoint write.
func (c *KeyorixCore) enforceAuditCheckpoint(ctx context.Context, v *storage.AuditChainVerification) error {
	if !c.AuditCheckpointsAvailable() {
		return nil
	}
	// Anti-rollback: check the live chain against the certified high-water mark first.
	// This runs even when every checkpoint row has been deleted (the high-water is a
	// separate, single, signed row), so deleting newer checkpoints to surface an older
	// authentic one no longer hides a tail-truncation.
	if err := c.enforceAuditHighWater(ctx, v); err != nil {
		return err
	}
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return err
	}
	if cp == nil {
		return nil // no checkpoint row; the high-water check above still applied
	}

	v.Checkpointed = true

	if !c.checkpointSignatureValid(cp) {
		c.failCheckpoint(v, nil,
			fmt.Sprintf("audit checkpoint #%d does not verify under the current signing key — the checkpoint was tampered, or a DEK rotation occurred and no fresh checkpoint has been written yet", cp.ID))
		return nil
	}
	reason, tampered, err := c.checkpointTruncation(ctx, v.ChainedEvents, cp)
	if err != nil {
		return err
	}
	if tampered {
		var brokenID *uint
		if cp.HeadID != 0 {
			id := cp.HeadID
			brokenID = &id
		}
		c.failCheckpoint(v, brokenID, reason)
	}
	// When an external-notary trust root is configured and the latest checkpoint carries
	// an anchor, re-verify the RFC 3161 receipt binds this exact checkpoint. Without this
	// the anchor was written but never checked on the read path — a forged/invalid token
	// would go unnoticed. Only enforced when roots are configured (opt-in); an anchor that
	// fails to verify against a configured root is a tamper signal.
	if c.checkpointAnchorRoots != nil && len(cp.AnchorToken) > 0 {
		if _, _, aerr := c.VerifyCheckpointAnchor(cp); aerr != nil {
			c.failCheckpoint(v, nil,
				fmt.Sprintf("audit checkpoint #%d external anchor failed verification against the configured trust root: %v", cp.ID, aerr))
		}
	}
	return nil
}

// checkpointTruncation compares the live chain length and certified head against an
// already-authenticated checkpoint, returning (reason, true) when the chain has
// been truncated below it or its certified head row was removed/rewritten. The
// caller MUST have validated cp's signature first.
func (c *KeyorixCore) checkpointTruncation(ctx context.Context, chainedEvents int64, cp *models.AuditCheckpoint) (string, bool, error) {
	if chainedEvents < cp.ChainedEvents {
		return fmt.Sprintf("audit trail truncated below signed checkpoint #%d: it certified %d chained events, only %d remain",
			cp.ID, cp.ChainedEvents, chainedEvents), true, nil
	}
	if cp.HeadID == 0 {
		// The checkpoint certified the empty/genesis chain (no chained events yet);
		// there is no head row to compare. The count check above is the only
		// invariant — the chain only ever grows — so this is not a truncation.
		return "", false, nil
	}
	hash, found, err := c.storage.AuditEntryHashByID(ctx, cp.HeadID)
	if err != nil {
		return "", false, err
	}
	if !found {
		return fmt.Sprintf("audit event #%d certified by checkpoint #%d is missing (tail-truncation or genesis re-seed)", cp.HeadID, cp.ID), true, nil
	}
	if hash != cp.HeadHash {
		return fmt.Sprintf("audit event #%d hash differs from signed checkpoint #%d (certified head was rewritten)", cp.HeadID, cp.ID), true, nil
	}
	return "", false, nil
}

// failCheckpoint records a checkpoint-detected tamper on the verdict without
// clobbering a more specific chain-walk failure that may already be present.
func (c *KeyorixCore) failCheckpoint(v *storage.AuditChainVerification, brokenID *uint, reason string) {
	v.Valid = false
	v.CheckpointReason = reason
	if v.Reason == "" {
		v.Reason = reason
	}
	if v.FirstBrokenID == nil && brokenID != nil {
		v.FirstBrokenID = brokenID
	}
}

// checkpointCanonical is the exact byte string signed/verified for a checkpoint.
// Null-separated and version-prefixed so fields cannot be ambiguously re-split.
func checkpointCanonical(cp *models.AuditCheckpoint) string {
	return fmt.Sprintf("v1\x00%d\x00%d\x00%s\x00%s", cp.ChainedEvents, cp.HeadID, cp.HeadHash, cp.KeyVersion)
}

func (c *KeyorixCore) signCheckpoint(cp *models.AuditCheckpoint) string {
	mac := hmac.New(sha256.New, c.auditCkptKey)
	mac.Write([]byte(checkpointCanonical(cp)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *KeyorixCore) checkpointSignatureValid(cp *models.AuditCheckpoint) bool {
	return c.checkpointSigMatches(cp, cp.Signature)
}

// checkpointSigMatches reports whether sig is the valid HMAC over cp's canonical bytes.
// Used for both a checkpoint row (sig == cp.Signature) and the high-water mark (where
// the signature is stored alongside the canonical fields, not on the cp struct).
func (c *KeyorixCore) checkpointSigMatches(cp *models.AuditCheckpoint, sig string) bool {
	return hmac.Equal([]byte(c.signCheckpoint(cp)), []byte(sig))
}

// --- audit high-water mark (anti-rollback for checkpoints) ---------------------

// bumpWatermark raises the in-memory monotonic high-water mark to n (never lowers it).
func (c *KeyorixCore) bumpWatermark(n int64) {
	c.auditWatermarkMu.Lock()
	if n > c.auditMaxCertified {
		c.auditMaxCertified = n
	}
	c.auditWatermarkMu.Unlock()
}

// watermark returns the in-memory monotonic high-water mark.
func (c *KeyorixCore) watermark() int64 {
	c.auditWatermarkMu.Lock()
	defer c.auditWatermarkMu.Unlock()
	return c.auditMaxCertified
}

// auditHighWaterValue serializes a high-water mark: the checkpoint canonical bytes
// (chained_events, head_id, head_hash, key_version) plus the HMAC signature, all
// null-separated so the fields cannot be ambiguously re-split.
func auditHighWaterValue(cp *models.AuditCheckpoint, sig string) string {
	return checkpointCanonical(cp) + "\x00" + sig
}

// parseAuditHighWater parses a stored high-water value back into a checkpoint snapshot
// and its signature. ok is false on any malformed value (treated as "no mark").
func parseAuditHighWater(val string) (cp *models.AuditCheckpoint, sig string, ok bool) {
	parts := strings.Split(val, "\x00")
	if len(parts) != 6 || parts[0] != "v1" {
		return nil, "", false
	}
	chained, err1 := strconv.ParseInt(parts[1], 10, 64)
	headID, err2 := strconv.ParseUint(parts[2], 10, 64)
	if err1 != nil || err2 != nil {
		return nil, "", false
	}
	return &models.AuditCheckpoint{
		ChainedEvents: chained,
		HeadID:        uint(headID),
		HeadHash:      parts[3],
		KeyVersion:    parts[4],
	}, parts[5], true
}

// auditHighWaterFloor returns the greatest chained-events count this server can prove
// the trail previously reached: the max of the in-memory watermark and a signature-valid
// persistent high-water under the current key. found reports whether a persistent mark
// exists; tampered/reason flag a persistent mark that fails its signature under the
// CURRENT key version (a superseded version is treated as a DEK rotation and ignored, so
// the system can recover after a key rotation — symmetric with checkpoint enforcement).
func (c *KeyorixCore) auditHighWaterFloor(ctx context.Context) (floor int64, found, tampered bool, reason string, err error) {
	floor = c.watermark()
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
	if err != nil {
		return 0, false, false, "", err
	}
	if !ok {
		return floor, false, false, "", nil
	}
	cp, sig, parsed := parseAuditHighWater(val)
	if !parsed {
		// A malformed mark under a configured key is itself suspicious, but we cannot
		// attribute it; treat as absent rather than asserting a specific floor.
		return floor, false, false, "", nil
	}
	if c.checkpointSigMatches(cp, sig) {
		if cp.ChainedEvents > floor {
			floor = cp.ChainedEvents
		}
		return floor, true, false, "", nil
	}
	if cp.KeyVersion == c.auditCkptKeyVersion {
		return floor, true, true,
			fmt.Sprintf("audit high-water mark fails its signature under the current key version %q — the high-water row was tampered with", cp.KeyVersion), nil
	}
	// Signature fails AND key_version is superseded → consistent with a DEK rotation;
	// ignore the stale mark (the next checkpoint write re-establishes it under the new key).
	return floor, true, false, "", nil
}

// enforceAuditHighWater flags the verdict if the live chain has regressed below the
// certified high-water mark (the anti-rollback check that catches deletion of newer
// checkpoints + tail-truncation, which the latest-checkpoint comparison alone misses),
// then raises the in-memory watermark to the just-verified length.
func (c *KeyorixCore) enforceAuditHighWater(ctx context.Context, v *storage.AuditChainVerification) error {
	floor, found, tampered, reason, err := c.auditHighWaterFloor(ctx)
	if err != nil {
		return err
	}
	exists, err := c.checkpointExists(ctx)
	if err != nil {
		return err
	}
	switch {
	case !found && !tampered:
		// A persistent mark that is absent or malformed (found=false, tampered=false) is
		// a rollback attempt WHEN signed checkpoints exist: advanceAuditHighWater writes
		// the mark with every checkpoint, so a checkpoint without a valid mark means the
		// mark was deleted or garbled to erase the certified length so a truncation reads
		// clean. (With no checkpoint we cannot attribute it — a fresh trail legitimately
		// has neither.)
		if exists {
			tampered = true
			reason = "audit high-water mark is missing or malformed although signed checkpoints exist — the anti-rollback mark was deleted or tampered with"
		}
	case found && !tampered && !exists:
		// The inverse and equally load-bearing case (#215): a validly-signed mark proves
		// a checkpoint was written and certified at some point in this install's history
		// — advanceAuditHighWater only ever persists the mark alongside a successful
		// checkpoint write, and nothing in this codebase ever prunes checkpoint rows. An
		// empty audit_checkpoints table alongside a still-valid mark therefore means the
		// checkpoint row(s) were deleted out from under it. The count-based floor
		// comparison below cannot catch this alone when the event count wasn't also
		// reduced — an attacker who tampers content and re-chains the hashes forward from
		// the tamper point stays self-consistent and doesn't shrink the row count, only
		// deleting audit_checkpoints defeats the head-hash comparison that would
		// otherwise catch it. This mark/table cross-check closes that gap independent of
		// count.
		tampered = true
		reason = "signed audit checkpoints existed previously (a valid high-water mark proves it) but the audit_checkpoints table is now empty — the checkpoint row(s) were deleted"
	}
	if found || tampered || floor > 0 {
		v.Checkpointed = true
	}
	switch {
	case tampered:
		c.failCheckpoint(v, nil, reason)
	case v.ChainedEvents < floor:
		c.failCheckpoint(v, nil,
			fmt.Sprintf("audit trail truncated below the certified high-water mark: %d events were previously certified, only %d remain", floor, v.ChainedEvents))
	}
	c.bumpWatermark(v.ChainedEvents)
	return nil
}

// advanceAuditHighWater persists (and bumps the in-memory) high-water mark to cp after a
// checkpoint write. The mark only ever advances; it is signed with the current key.
func (c *KeyorixCore) advanceAuditHighWater(ctx context.Context, cp *models.AuditCheckpoint) {
	floor, _, _, _, err := c.auditHighWaterFloor(ctx)
	if err == nil && cp.ChainedEvents < floor {
		// Never lower the mark (a legitimate grow only raises it). Should not happen —
		// WriteAuditCheckpoint refuses to checkpoint below the floor — but be defensive.
		c.bumpWatermark(floor)
		return
	}
	val := auditHighWaterValue(cp, c.signCheckpoint(cp))
	if err := c.storage.SetSystemMetadata(ctx, auditHighWaterKey, val); err != nil {
		log.Printf("audit high-water: failed to persist mark at %d events: %v", cp.ChainedEvents, err)
	}
	c.bumpWatermark(cp.ChainedEvents)
}
