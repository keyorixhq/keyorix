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
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/notary"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

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
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return err
	}
	if cp == nil {
		return nil // none written yet
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
	return hmac.Equal([]byte(c.signCheckpoint(cp)), []byte(cp.Signature))
}
