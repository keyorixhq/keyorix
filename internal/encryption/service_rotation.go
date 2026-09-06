// service_rotation.go — DEK rotation, key ops, and shutdown for Service.
//
// RotateDEKWithSweep, ValidateKeyFiles, FixKeyFilePermissions,
// GetKeyVersion, CleanPendingDEK, Shutdown.
// For encrypt/decrypt see service.go.
package encryption

import (
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"gorm.io/gorm"
)

// RotateDEKWithSweep performs a true DEK rotation with a full re-encryption
// sweep of all DEK-encrypted database rows (ADR-010).
//
// The DB transaction is owned here: committed on sweep success, rolled back on
// any failure. The old DEK remains active if anything fails. This is a
// write-locking operation — avoid accepting write traffic during the sweep.
//
// Returns the completed SweepResult so callers (the rotate CLI) can report every
// field of it to the operator, not just the subset logged below.
func (s *Service) RotateDEKWithSweep(passphrase string, db *gorm.DB) (*SweepResult, error) {
	s.mu.RLock()
	if !s.initialized {
		s.mu.RUnlock()
		return nil, fmt.Errorf("encryption service not initialized")
	}
	s.mu.RUnlock()

	// Refuse to rotate against a live server (#92): if a server holding this DEK
	// is running, promoting a new DEK here would leave it silently encrypting new
	// writes under the OLD key and unable to decrypt rows the sweep re-encrypts,
	// until its next restart — a permanent-loss window if that restart is delayed
	// or never happens. AcquireExclusiveKeyLock is released by the deferred
	// Shutdown() the CLI already calls after this function returns.
	if err := s.AcquireExclusiveKeyLock(); err != nil {
		return nil, fmt.Errorf("refusing to rotate: %w — stop the running server before rotating", err)
	}

	var sweepResult *SweepResult
	sweepFn := func(oldSvc, newSvc *EncryptionService, newKeyVersion string) error {
		tx := db.Begin()
		if tx.Error != nil {
			return fmt.Errorf("failed to begin transaction: %w", tx.Error)
		}
		defer func() {
			if recover() != nil {
				tx.Rollback()
			}
		}()

		result, err := SweepAllTables(tx, oldSvc, newSvc, newKeyVersion, false)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("sweep failed: %w", err)
		}
		if err := tx.Commit().Error; err != nil {
			return fmt.Errorf("failed to commit sweep transaction: %w", err)
		}

		// Log (and, via the returned SweepResult, report to the CLI operator) every
		// field of the result — not just the original 5 of 8 "Swept" counts. The 3
		// previously-omitted fields here (mfa_secrets, dynamic_secret_configs,
		// dynamic_secret_leases) are exactly the tables #422's sweep-gap fix added;
		// silently under-reporting them left an operator with no visibility into
		// whether that fix's own sweeps ran, even after the data itself was safe.
		log.Printf("✅ Sweep committed: %d secret_versions, %d api_tokens, %d api_clients, %d password_resets, %d mfa_secrets, %d dynamic_secret_configs, %d dynamic_secret_leases re-encrypted (%d legacy AAD upgraded)",
			result.SecretVersionsSwept, result.APITokensSwept,
			result.APIClientsSwept, result.AccountResetsSwept, result.MFASecretsSwept,
			result.DynamicSecretConfigsSwept, result.DynamicSecretLeasesSwept, result.LegacyAADUpgraded)
		sweepResult = result
		return nil
	}

	if err := s.keyManager.RotateDEKWithSweep(passphrase, sweepFn); err != nil {
		return nil, fmt.Errorf("DEK rotation with sweep failed: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	dek := s.keyManager.GetDEK()
	encSvc, err := NewEncryptionService(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to recreate encryption service after rotation: %w", err)
	}
	// The old encryption service wraps the now-superseded DEK (a distinct copy from
	// s.keyManager.GetDEK(), not the km.currentDEK slice the key manager itself
	// already wipes) and is about to be discarded — wipe its DEK copy from memory
	// here, like every other DEK-bearing variable in this package.
	if s.encryptionService != nil {
		wipeBytes(s.encryptionService.dek)
	}
	s.encryptionService = encSvc
	return sweepResult, nil
}

// PreviewRotationSweep performs a READ-ONLY dry run of the same table/row
// traversal RotateDEKWithSweep's sweep uses, so an operator can see exactly what a
// real rotation would touch — table names and row counts — before committing to
// that write-locking, irreversible operation.
//
// It makes NO changes whatsoever: the current encryption service is used as BOTH
// oldSvc and newSvc (no new DEK is generated, nothing is written to the key
// directory), SweepAllTables is invoked with dryRun=true (which skips every
// per-row Updates() write while still performing every SELECT/decrypt/re-encrypt/
// count step, so the preview is accurate and would surface a row that couldn't be
// decrypted), and the wrapping transaction is unconditionally rolled back —
// never committed — regardless of outcome.
func (s *Service) PreviewRotationSweep(db *gorm.DB) (*SweepResult, error) {
	s.mu.RLock()
	if !s.initialized {
		s.mu.RUnlock()
		return nil, fmt.Errorf("encryption service not initialized")
	}
	svc := s.encryptionService
	keyVersion := s.keyManager.GetKeyVersion()
	s.mu.RUnlock()

	tx := db.Begin()
	if tx.Error != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}
	// Always rolled back — a dry run must never persist anything, no matter what.
	defer tx.Rollback()
	defer func() {
		if recover() != nil {
			tx.Rollback()
		}
	}()

	result, err := SweepAllTables(tx, svc, svc, keyVersion, true)
	if err != nil {
		return nil, fmt.Errorf("dry-run sweep preview failed: %w", err)
	}
	return result, nil
}

// UpgradeAuthAAD re-encrypts every legacy (pre-#94), no-AAD row in the AAD-bound auth
// tables (mfa_secrets, dynamic_secret_configs, dynamic_secret_leases) UNDER THE
// CURRENT DEK — no key rotation involved. Rows already AAD-bound are re-encrypted
// too (a fresh nonce, same AAD), so the sweep is idempotent and safe to re-run.
//
// This exists so closing the #94 AAD-transplant exposure for these tables doesn't
// require an operator to perform a full, write-locking DEK rotation (RotateDEKWithSweep)
// — a live install can run this on its own schedule (or a one-off CLI invocation)
// while the DEK stays exactly as it was. secret_versions rows are NOT touched here:
// they've been AAD-bound since the M2 migration and are only ever upgraded as a
// side effect of a real DEK rotation's sweep.
//
// The DB transaction is owned here, matching RotateDEKWithSweep: committed on
// success, rolled back on any failure.
func (s *Service) UpgradeAuthAAD(db *gorm.DB) (*SweepResult, error) {
	s.mu.RLock()
	if !s.initialized {
		s.mu.RUnlock()
		return nil, fmt.Errorf("encryption service not initialized")
	}
	svc := s.encryptionService
	keyVersion := s.keyManager.GetKeyVersion()
	s.mu.RUnlock()

	tx := db.Begin()
	if tx.Error != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}
	defer func() {
		if recover() != nil {
			tx.Rollback()
		}
	}()

	result := &SweepResult{}
	sweptMFA, legacyMFA, err := sweepMFASecrets(tx, svc, svc, keyVersion, false)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("mfa_secrets AAD upgrade failed: %w", err)
	}
	result.MFASecretsSwept = sweptMFA
	result.LegacyAADUpgraded += legacyMFA

	sweptDynConfigs, legacyDynConfigs, err := sweepDynamicSecretConfigs(tx, svc, svc, keyVersion, false)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("dynamic_secret_configs AAD upgrade failed: %w", err)
	}
	result.DynamicSecretConfigsSwept = sweptDynConfigs
	result.LegacyAADUpgraded += legacyDynConfigs

	sweptDynLeases, legacyDynLeases, err := sweepDynamicSecretLeases(tx, svc, svc, keyVersion, false)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("dynamic_secret_leases AAD upgrade failed: %w", err)
	}
	result.DynamicSecretLeasesSwept = sweptDynLeases
	result.LegacyAADUpgraded += legacyDynLeases

	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to commit AAD upgrade transaction: %w", err)
	}
	log.Printf("✅ AAD upgrade committed: %d mfa_secrets, %d dynamic_secret_configs, %d dynamic_secret_leases re-encrypted (%d legacy AAD upgraded)",
		result.MFASecretsSwept, result.DynamicSecretConfigsSwept, result.DynamicSecretLeasesSwept, result.LegacyAADUpgraded)
	return result, nil
}

// RotateKEKPassphrase changes the master passphrase without re-encrypting the
// database. It re-wraps the current DEK under a new KEK derived from
// newPassphrase + a fresh random salt. The DEK value is unchanged, so all
// existing ciphertext stays valid. Evidence-signing and audit-checkpoint key
// fingerprints will change because those keys are KEK-derived.
//
// The old passphrase is verified against the on-disk wrapped DEK before any
// file is modified. The server must be stopped (exclusive key lock must not
// be held by another process) before running this command.
func (s *Service) RotateKEKPassphrase(oldPassphrase, newPassphrase string) error {
	s.mu.RLock()
	if !s.initialized {
		s.mu.RUnlock()
		return fmt.Errorf("encryption service not initialized")
	}
	s.mu.RUnlock()

	// Self-enforce the same exclusive server-vs-CLI lock RotateDEKWithSweep and
	// RewrapDEKWithProvider already take internally, rather than relying solely on
	// the CLI caller (rotate-kek) to acquire it first, as defense in depth.
	// Idempotent — a no-op if this Service (or its caller) already holds it.
	if err := s.AcquireExclusiveKeyLock(); err != nil {
		return fmt.Errorf("refusing to rotate KEK: %w — stop the running server before rotating", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyManager.RotateKEKPassphrase(oldPassphrase, newPassphrase)
}

// RewrapDEKWithProvider re-wraps the in-memory DEK with a KEK from newProvider and
// atomically replaces the on-disk wrapped DEK (ADR-041 KEK-provider migration). The
// DEK value is unchanged, so every existing ciphertext stays valid — only the
// wrapping key changes; no data is re-encrypted and no DB lock is taken. The
// service must already be Initialized with the CURRENT provider. The caller should
// then verify the new provider unwraps the DEK before discarding the previous
// wrapped-DEK backup.
func (s *Service) RewrapDEKWithProvider(newProvider crypto.KeyProvider) error {
	s.mu.RLock()
	if !s.initialized {
		s.mu.RUnlock()
		return fmt.Errorf("encryption service not initialized")
	}
	s.mu.RUnlock()

	// Refuse to re-wrap against a live server (#92, mirroring RotateDEKWithSweep):
	// without this, a concurrent `migrate-provider` run and a live server (or a
	// concurrent rotation) could race on the same dek.key.pending → dek.key path.
	// AcquireExclusiveKeyLock is released by the deferred Shutdown() the CLI
	// already calls after this function returns.
	if err := s.AcquireExclusiveKeyLock(); err != nil {
		return fmt.Errorf("refusing to re-wrap DEK: %w — stop the running server before migrating the KEK provider", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyManager.RewrapDEK(newProvider)
}

// ValidateKeyFiles validates encryption key files exist with correct
// permissions -- the DEK/salt (ADR-004) plus any KeyProviderConfig-driven key
// material (TPM/cloud-KMS wrapped-KEK blob, Shamir share files) s.config
// declares; see internal/keyfiles.Registry.
func (s *Service) ValidateKeyFiles() error {
	return s.keyManager.ValidateKeyFiles(s.config)
}

// FixKeyFilePermissions fixes key file permissions to 0600, for the same set
// ValidateKeyFiles checks.
func (s *Service) FixKeyFilePermissions() error {
	return s.keyManager.FixKeyFilePermissions(s.config)
}

// GetKeyVersion returns the current key version string.
func (s *Service) GetKeyVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.initialized {
		return "unknown"
	}
	return s.keyManager.GetKeyVersion()
}

// CleanPendingDEK removes a leftover dek.key.pending file from an interrupted rotation.
// Call at startup before Initialize.
func (s *Service) CleanPendingDEK() {
	s.keyManager.CleanPendingDEK()
}

// AcquireExclusiveKeyLock takes an exclusive, non-blocking OS advisory lock on
// the key directory, so no OTHER process using the same DEK — another server
// instance, or a concurrent rotation — can hold it at the same time (#92). The
// server calls this once at startup (held for its whole lifetime); rotation
// calls it at the start of RotateDEKWithSweep (held only for the sweep). Either
// way it is released by Shutdown. Idempotent: a second call while already held
// by this Service is a no-op.
func (s *Service) AcquireExclusiveKeyLock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized {
		return fmt.Errorf("encryption service not initialized")
	}
	if s.serverLock != nil {
		return nil
	}
	f, err := acquireExclusiveKeyLock(s.keyManager.baseDir)
	if err != nil {
		return err
	}
	s.serverLock = f
	return nil
}

// AcquireSharedKeyLock takes a shared, non-blocking OS advisory lock on the same
// key-directory lock file AcquireExclusiveKeyLock uses (#196). It is for local,
// short-lived CLI commands that read (or, for upgrade-aad, write under) the
// CURRENT DEK without themselves rotating it — status/validate/fix-perms/
// upgrade-aad/init. Unlike AcquireExclusiveKeyLock, any number of Services can
// hold the shared lock at the same time, so ordinary concurrent CLI invocations
// never contend with each other over it — but it is refused outright while a
// live server or an in-progress rotation/migrate-provider holds the lock
// exclusively, so those commands fail fast instead of racing a DEK that's
// concurrently being replaced. Released by Shutdown, same as the exclusive
// lock. Idempotent: a second call while this Service already holds either kind
// of lock is a no-op.
func (s *Service) AcquireSharedKeyLock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized {
		return fmt.Errorf("encryption service not initialized")
	}
	if s.serverLock != nil {
		return nil
	}
	f, err := acquireSharedKeyLock(s.keyManager.baseDir)
	if err != nil {
		return err
	}
	s.serverLock = f
	return nil
}

// Shutdown cleanly wipes the DEK from memory and releases the exclusive key
// lock, if this Service was holding one.
func (s *Service) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keyManager != nil {
		s.keyManager.Wipe()
	}
	// s.keyManager.Wipe() only zeroes km.currentDEK — s.encryptionService.dek is a
	// separate copy (made via s.keyManager.GetDEK() in Initialize/RotateDEKWithSweep)
	// and was never wiped, unlike every other DEK-bearing variable in this package.
	if s.encryptionService != nil {
		wipeBytes(s.encryptionService.dek)
		s.encryptionService = nil
	}
	releaseKeyLock(s.serverLock)
	s.serverLock = nil
	s.initialized = false
}
