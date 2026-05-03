// service_rotation.go — DEK rotation, key ops, and shutdown for Service.
//
// RotateDEKWithSweep, RotateDEK, ValidateKeyFiles, FixKeyFilePermissions,
// GetKeyVersion, CleanPendingDEK, Shutdown.
// For encrypt/decrypt see service.go.
package encryption

import (
	"fmt"
	"log"

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
