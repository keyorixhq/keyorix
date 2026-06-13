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
	"encoding/hex"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
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
	v, err := c.VerifyAuditChain(ctx)
	if err != nil {
		return nil, false, err
	}
	if !v.Valid {
		reason := v.Reason
		if reason == "" {
			reason = v.CheckpointReason
		}
		return nil, false, fmt.Errorf("refusing to checkpoint a chain that does not verify: %s", reason)
	}
	cp := &models.AuditCheckpoint{
		ChainedEvents: v.ChainedEvents,
		HeadID:        v.HeadID,
		HeadHash:      v.HeadHash,
		KeyVersion:    c.auditCkptKeyVersion,
	}
	cp.Signature = c.signCheckpoint(cp)
	if err := c.storage.CreateAuditCheckpoint(ctx, cp); err != nil {
		return nil, false, fmt.Errorf("failed to write audit checkpoint: %w", err)
	}
	return cp, true, nil
}

// enforceAuditCheckpoint augments a chain-walk verdict with on-box checkpoint
// verification: it loads the latest signed checkpoint and, if its signature is
// authentic and current, requires the live chain to still be at least as long as
// the checkpoint certified, with the certified head row unchanged. Any shortfall
// or head rewrite flips Valid to false. A checkpoint signed under a superseded
// DEK version is recorded but not enforced (it cannot be re-verified after a key
// rotation). A signature that does not recompute is itself a tamper signal.
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
	if cp.KeyVersion != c.auditCkptKeyVersion {
		v.CheckpointReason = fmt.Sprintf(
			"latest audit checkpoint #%d was signed under key version %q (current %q); not enforced after a key rotation",
			cp.ID, cp.KeyVersion, c.auditCkptKeyVersion)
		return nil
	}

	v.Checkpointed = true

	if !c.checkpointSignatureValid(cp) {
		c.failCheckpoint(v, nil,
			fmt.Sprintf("audit checkpoint #%d signature is invalid — the checkpoint row was tampered (forged without the signing key)", cp.ID))
		return nil
	}
	if v.ChainedEvents < cp.ChainedEvents {
		c.failCheckpoint(v, nil,
			fmt.Sprintf("audit trail truncated below signed checkpoint #%d: it certified %d chained events, only %d remain",
				cp.ID, cp.ChainedEvents, v.ChainedEvents))
		return nil
	}
	hash, found, err := c.storage.AuditEntryHashByID(ctx, cp.HeadID)
	if err != nil {
		return err
	}
	headID := cp.HeadID
	if !found {
		c.failCheckpoint(v, &headID,
			fmt.Sprintf("audit event #%d certified by checkpoint #%d is missing (tail-truncation or genesis re-seed)", cp.HeadID, cp.ID))
		return nil
	}
	if hash != cp.HeadHash {
		c.failCheckpoint(v, &headID,
			fmt.Sprintf("audit event #%d hash differs from signed checkpoint #%d (certified head was rewritten)", cp.HeadID, cp.ID))
		return nil
	}
	return nil
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
