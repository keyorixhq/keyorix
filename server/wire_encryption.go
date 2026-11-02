package main

import (
	"context"
	"fmt"
	"log"
)

// wireSecretEncryption is a core wiring step (coreWiringSteps in main.go).
func wireSecretEncryption(cw *coreWiring) error {
	coreService, encSvc := cw.core, cw.encSvc
	if encSvc != nil {
		// Wire the initialised encryption service for secret VALUES at rest (ADR-004
		// envelope encryption). Without this, storage.encryption.enabled would derive a
		// KEK but never actually encrypt any secret value — every secret would persist as
		// plaintext. Fail closed immediately after wiring: if encryption was configured
		// but did not actually engage, refuse to start rather than silently store
		// plaintext in a secrets manager.
		coreService.SetSecretValueEncryptor(encSvc)
		if !coreService.SecretValueEncryptionActive() {
			return fmt.Errorf("storage.encryption is enabled but secret-value encryption did not engage (encryptor not initialised) — refusing to start to avoid storing secrets in plaintext")
		}
		// Wire the same initialised service for reversibly-encrypted auth secrets (the
		// TOTP MFA secret, which cannot be hashed).
		coreService.SetAuthEncryptor(encSvc)
		// Derive the audit-checkpoint signing key from the KEK (ADR-029; KEK-derived so
		// a DEK rotation does not change it) so signed checkpoints — and on-box
		// truncation detection — are available. Unavailable when encryption is off
		// (no KEK).
		if key, keyVer, ok := encSvc.AuditCheckpointKey(); ok {
			coreService.SetAuditCheckpointKey(key, keyVer)
			// Finish carrying the audit verification state over after a key change
			// interrupted between its key-file commit and its database step
			// (docs/design-audit-key-transition.md). A no-op otherwise; a record
			// that cannot be trusted is left alone and reported as a
			// discontinuity by the next verification.
			if _, err := coreService.CompleteAuditKeyTransition(context.Background()); err != nil {
				log.Printf("SECURITY: audit key transition not completed at startup: %v", err)
			}
			// Restore the in-memory anti-rollback watermark from the persisted high-water
			// mark so a process restart cannot reset it to zero (ADR-029).
			coreService.SeedAuditWatermark(context.Background())
		}
		// Derive the evidence-pack signing key from the KEK (not the DEK — #268, so a
		// routine DEK rotation does not invalidate previously-signed packs) so
		// scheduled evidence exports are signed (and verifiable). Unavailable when
		// encryption is off.
		if key, keyVer, ok := encSvc.EvidenceSignKey(); ok {
			coreService.SetEvidenceSignKey(key, keyVer)
		}
	}
	return nil
}
