// service_rotation.go — DEK rotation, key ops, and shutdown for Service.
//
// RotateDEKWithSweep, RotateDEK, ValidateKeyFiles, FixKeyFilePermissions,
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
func (s *Service) RotateDEKWithSweep(passphrase string, db *gorm.DB) error {
	s.mu.RLock()
	if !s.initialized {
		s.mu.RUnlock()
		return fmt.Errorf("encryption service not initialized")
	}
	s.mu.RUnlock()

	sweepFn := func(oldSvc, newSvc *EncryptionService, newKeyVersion string) error {
		tx := db.Begin()
		if tx.Error != nil {
			return fmt.Errorf("failed to begin transaction: %w", tx.Error)
		}
		defer func() {
			if r := recover(); r != nil {
				tx.Rollback()
			}
		}()

		result, err := SweepAllTables(tx, oldSvc, newSvc, newKeyVersion)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("sweep failed: %w", err)
		}
		if err := tx.Commit().Error; err != nil {
			return fmt.Errorf("failed to commit sweep transaction: %w", err)
		}

		log.Printf("✅ Sweep committed: %d secret_versions, %d sessions, %d api_tokens, %d api_clients, %d password_resets re-encrypted (%d legacy AAD upgraded)",
			result.SecretVersionsSwept, result.SessionsSwept, result.APITokensSwept,
			result.APIClientsSwept, result.PasswordResetsSwept, result.LegacyAADUpgraded)
		return nil
	}

	if err := s.keyManager.RotateDEKWithSweep(passphrase, sweepFn); err != nil {
		return fmt.Errorf("DEK rotation with sweep failed: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	dek := s.keyManager.GetDEK()
	encSvc, err := NewEncryptionService(dek)
	if err != nil {
		return fmt.Errorf("failed to recreate encryption service after rotation: %w", err)
	}
	s.encryptionService = encSvc
	return nil
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
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	result := &SweepResult{}
	sweptMFA, legacyMFA, err := sweepMFASecrets(tx, svc, svc, keyVersion)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("mfa_secrets AAD upgrade failed: %w", err)
	}
	result.MFASecretsSwept = sweptMFA
	result.LegacyAADUpgraded += legacyMFA

	sweptDynConfigs, legacyDynConfigs, err := sweepDynamicSecretConfigs(tx, svc, svc, keyVersion)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("dynamic_secret_configs AAD upgrade failed: %w", err)
	}
	result.DynamicSecretConfigsSwept = sweptDynConfigs
	result.LegacyAADUpgraded += legacyDynConfigs

	sweptDynLeases, legacyDynLeases, err := sweepDynamicSecretLeases(tx, svc, svc, keyVersion)
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

// RotateDEK rotates the DEK without re-encrypting existing secrets.
// DEPRECATED: Use RotateDEKWithSweep instead. See ADR-010.
func (s *Service) RotateDEK(passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return fmt.Errorf("encryption service not initialized")
	}
	if err := s.keyManager.RotateDEK(passphrase); err != nil {
		return fmt.Errorf("failed to rotate DEK: %w", err)
	}
	dek := s.keyManager.GetDEK()
	encSvc, err := NewEncryptionService(dek)
	if err != nil {
		return fmt.Errorf("failed to recreate encryption service: %w", err)
	}
	s.encryptionService = encSvc
	return nil
}

// RewrapDEKWithProvider re-wraps the in-memory DEK with a KEK from newProvider and
// atomically replaces the on-disk wrapped DEK (ADR-041 KEK-provider migration). The
// DEK value is unchanged, so every existing ciphertext stays valid — only the
// wrapping key changes; no data is re-encrypted and no DB lock is taken. The
// service must already be Initialized with the CURRENT provider. The caller should
// then verify the new provider unwraps the DEK before discarding the previous
// wrapped-DEK backup.
func (s *Service) RewrapDEKWithProvider(newProvider crypto.KeyProvider) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized {
		return fmt.Errorf("encryption service not initialized")
	}
	return s.keyManager.RewrapDEK(newProvider)
}

// ValidateKeyFiles validates encryption key files exist with correct permissions.
func (s *Service) ValidateKeyFiles() error {
	return s.keyManager.ValidateKeyFiles()
}

// FixKeyFilePermissions fixes key file permissions to 0600.
func (s *Service) FixKeyFilePermissions() error {
	return s.keyManager.FixKeyFilePermissions()
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

// Shutdown cleanly wipes the DEK from memory.
func (s *Service) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keyManager != nil {
		s.keyManager.Wipe()
	}
	s.initialized = false
}
