// keymanager_state.go — the in-memory key material readers see, published as one
// immutable snapshot (#4376, docs/design/2026-11-15-key-custody-availability.md §2.5).
//
// Locks, in the only order they are ever nested:
//
//	rotateMu → <dek_path>.lock (flock)   RotateKEKPassphraseWithPrepare
//	rotateMu → mu                        Initialize, Wipe, the wipe step after a KEK rotation
//	mu → <dek_path>.lock (flock)         RotateDEKWithSweep, RewrapDEKWithPrepare (until item 2)
//
// No code takes mu while holding the flock, and no code takes rotateMu while
// holding mu or the flock, so the three cannot deadlock. A rotation that keeps
// mu off its disk I/O (RotateKEKPassphraseWithPrepare) builds the whole next
// keyState in locals and publishes it with one state.Store after its rename and
// directory fsync are durable; readers take mu.RLock only for the Load and the
// copy, so they wait on such a rotation's fsync never. They still wait on the
// writers that hold mu across their work (RotateDEKWithSweep's sweep, on
// purpose; Initialize; Wipe).
package encryption

// keyState is one generation of the key manager's in-memory key material. It is
// immutable once published: a writer builds a new value and Stores it, it never
// edits a published one. The byte slices may be shared with the previous
// generation (a KEK rotation keeps the same dek slice); a superseded slice is
// wiped only under mu.Lock, after the new state is published, so no reader is
// mid-copy (readers copy under mu.RLock).
type keyState struct {
	dek []byte
	// dekSnapshot is the raw wrapped-DEK bytes read from disk at the moment dek
	// was last set (Initialize/RotateDEKWithSweep) or rewrapped. It lets a
	// rotation detect — under the exclusive key lock — whether another process
	// has changed dek.key since, so it never overwrites a concurrently-completed
	// rotation with a stale value (#195).
	dekSnapshot []byte
	keyVersion  string
	// evidenceSignKey/evidenceSignKeyID are a 32-byte HMAC key and its public
	// fingerprint, derived from the KEK (NOT the DEK) via HKDF-SHA256 at
	// Initialize time — before the KEK is wiped below. Used to sign/verify
	// exported compliance-evidence packs (internal/core/evidence_signing.go).
	// Deriving from the KEK rather than the DEK is the point (#268): a routine
	// DEK rotation (RotateDEKWithSweep, ADR-010) re-wraps a brand-new DEK under
	// the SAME KEK, so this key — and its fingerprint — is completely unaffected
	// by it, and a previously-signed evidence pack stays verifiable across a DEK
	// rotation. Only a genuine KEK change (rotate-kek, KEK-provider migration,
	// RewrapDEK / ADR-041 — a far rarer, deliberate operator action) changes it; when that
	// happens VerifyEvidenceSignature correctly reports an older signature as
	// made under a superseded key version rather than as tampered, same as
	// before. Never persisted to disk — held only in memory, like dek.
	evidenceSignKey   []byte
	evidenceSignKeyID string
	// auditCheckpointKey/auditCheckpointKeyID are a 32-byte HMAC key and its public
	// fingerprint, derived from the KEK (NOT the DEK) via HKDF-SHA256 at Initialize
	// time — before the KEK is wiped below. Used to sign/verify audit-chain
	// checkpoints (ADR-029, internal/core/audit_checkpoint.go). Deriving from the
	// KEK rather than the DEK is the point (#502, mirroring #268's fix for
	// evidenceSignKey above): a routine DEK rotation (RotateDEKWithSweep, ADR-010)
	// re-wraps a brand-new DEK under the SAME KEK, so this key — and its
	// fingerprint — is completely unaffected by it, and a checkpoint signed before a
	// DEK rotation stays verifiable after one (previously, deriving from the DEK
	// meant every DEK rotation followed by a server restart caused every existing
	// checkpoint to fail its signature check and `audit verify` to report the trail
	// invalid until the next checkpoint write re-baselined it — a real, if
	// self-healing, false-tamper-alarm window). Only a genuine KEK change
	// (rotate-kek, KEK-provider migration, RewrapDEK / ADR-041 — a far rarer,
	// deliberate operator action) changes it; when that happens the existing superseded-key
	// handling in enforceAuditCheckpoint/writeAuditCheckpointLocked correctly
	// treats the stale checkpoint as needing re-baselining rather than as tampered,
	// same as before. Never persisted to disk — held only in memory, like
	// dek/evidenceSignKey.
	auditCheckpointKey   []byte
	auditCheckpointKeyID string
	// backupManifestKey/backupManifestKeyID are a 32-byte HMAC key and its
	// public fingerprint, derived from the KEK via
	// auditverify.DeriveBackupManifestKey at Initialize time -- the exact
	// same treatment as auditCheckpointKey immediately above (KEK-derived
	// so a DEK rotation never invalidates an already-signed manifest;
	// re-derived on KEK rotation; wiped on shutdown), but its own
	// independently domain-separated key: design-b3-backup-v2.md §5.2's
	// explicit decision that the manifest-signing key must never be the
	// audit-checkpoint key reused for a second protocol. Never persisted to
	// disk -- held only in memory, like every other key here.
	backupManifestKey   []byte
	backupManifestKeyID string
}

// published returns the published state. It is never nil after NewKeyManager.
func (km *KeyManager) published() *keyState {
	return km.state.Load()
}

// nextState returns a copy of the published state for a writer to edit and Store.
func (km *KeyManager) nextState() *keyState {
	next := *km.state.Load()
	return &next
}
