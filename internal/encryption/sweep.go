package encryption

// sweep.go — Re-encryption sweep for DEK rotation (ADR-010)
//
// Called by RotateDEKWithSweep after a new DEK is generated but BEFORE the
// old DEK is replaced in memory. The sweep re-encrypts every database row
// that holds DEK-encrypted ciphertext.
//
// Invariant: on success, no row in the database holds ciphertext encrypted
// under the old DEK. The caller is responsible for wiping the old DEK from
// memory after this function returns nil.
//
// Secret value SAFETY: plaintext values pass through memory transiently
// during this sweep. They are never logged, returned to callers, or written
// anywhere other than back to the originating database row.

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

const sweepBatchSize = 500

// SweepResult holds statistics from a completed sweep.
type SweepResult struct {
	SecretVersionsSwept int
	SessionsSwept       int
	APITokensSwept      int
	APIClientsSwept     int
	PasswordResetsSwept int
	LegacyAADUpgraded   int // rows that were legacy (no AAD) and are now AAD-bound
}

// SweepAllTables re-encrypts every DEK-encrypted row within a single DB
// transaction. oldSvc decrypts, newSvc re-encrypts.
//
// The function is called while both old and new DEK services are live in
// memory — do not call after the old DEK has been wiped.
func SweepAllTables(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string) (*SweepResult, error) {
	result := &SweepResult{}

	sweptVersions, legacyUpgraded, err := sweepSecretVersions(tx, oldSvc, newSvc, newKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("secret_versions sweep failed: %w", err)
	}
	result.SecretVersionsSwept = sweptVersions
	result.LegacyAADUpgraded = legacyUpgraded

	sweptSessions, err := sweepSessions(tx, oldSvc, newSvc, newKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("sessions sweep failed: %w", err)
	}
	result.SessionsSwept = sweptSessions

	sweptAPITokens, err := sweepAPITokens(tx, oldSvc, newSvc, newKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("api_tokens sweep failed: %w", err)
	}
	result.APITokensSwept = sweptAPITokens

	sweptClients, err := sweepAPIClients(tx, oldSvc, newSvc, newKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("api_clients sweep failed: %w", err)
	}
	result.APIClientsSwept = sweptClients

	sweptResets, err := sweepPasswordResets(tx, oldSvc, newSvc, newKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("password_resets sweep failed: %w", err)
	}
	result.PasswordResetsSwept = sweptResets

	return result, nil
}

// sweepSecretVersions re-encrypts all secret_versions rows in batches.
// Handles two cases:
//   - AAD-bound rows (aad_version = "v1"): reconstructs AAD from row metadata,
//     decrypts with old AAD-aware path, re-encrypts with new DEK + same AAD.
//   - Legacy rows (no aad_version): decrypts without AAD, re-encrypts with
//     new DEK + correct AAD (upgrade). This completes the M2 AAD migration.
//
// Returns (rowsSwept, legacyRowsUpgraded, error).
func sweepSecretVersions(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string) (int, int, error) {
	var offset int
	var totalSwept, totalLegacyUpgraded int

	// Pre-fetch a map of secretNodeID → namespaceID to avoid N+1 queries.
	// SecretNode table is small relative to SecretVersion.
	nodeNamespaceMap := make(map[uint]uint)
	var nodes []models.SecretNode
	if err := tx.Select("id, namespace_id").Find(&nodes).Error; err != nil {
		return 0, 0, fmt.Errorf("failed to fetch secret nodes for AAD reconstruction: %w", err)
	}
	for _, n := range nodes {
		nodeNamespaceMap[n.ID] = n.NamespaceID
	}

	for {
		var batch []models.SecretVersion
		if err := tx.Offset(offset).Limit(sweepBatchSize).Find(&batch).Error; err != nil {
			return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to fetch secret_versions batch at offset %d: %w", offset, err)
		}
		if len(batch) == 0 {
			break
		}

		for _, version := range batch {
			// Skip rows with no encrypted data (encryption-disabled installations)
			if len(version.EncryptedValue) == 0 {
				continue
			}

			encrypted, err := DeserializeEncryptedData(version.EncryptedValue)
			if err != nil {
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to deserialize secret_version id=%d: %w", version.ID, err)
			}

			namespaceID, ok := nodeNamespaceMap[version.SecretNodeID]
			if !ok {
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("no namespace found for secret_node_id=%d (version id=%d)", version.SecretNodeID, version.ID)
			}
			aad := SecretAAD(version.SecretNodeID, namespaceID, version.VersionNumber)

			var plaintext []byte
			isLegacy := encrypted.Metadata.AADVersion == ""

			if isLegacy {
				// Legacy row: decrypt without AAD
				plaintext, err = oldSvc.Decrypt(encrypted)
				if err != nil {
					return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to decrypt legacy secret_version id=%d: %w", version.ID, err)
				}
			} else {
				// AAD-bound row: decrypt with AAD
				plaintext, err = oldSvc.DecryptWithAAD(encrypted, aad)
				if err != nil {
					return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to decrypt AAD-bound secret_version id=%d: %w", version.ID, err)
				}
			}

			// Re-encrypt with new DEK + AAD (all rows get AAD after this sweep)
			newEncrypted, err := newSvc.EncryptWithAAD(plaintext, newKeyVersion, aad)
			if err != nil {
				wipeBytes(plaintext)
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to re-encrypt secret_version id=%d: %w", version.ID, err)
			}
			wipeBytes(plaintext)

			newEncryptedBytes, err := SerializeEncryptedData(newEncrypted)
			if err != nil {
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to serialize re-encrypted secret_version id=%d: %w", version.ID, err)
			}

			metadataBytes, err := json.Marshal(newEncrypted.Metadata)
			if err != nil {
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to marshal metadata for secret_version id=%d: %w", version.ID, err)
			}

			updates := map[string]interface{}{
				"encrypted_value":     newEncryptedBytes,
				"encryption_metadata": models.JSON(metadataBytes),
			}
			if err := tx.Model(&models.SecretVersion{}).Where("id = ?", version.ID).Updates(updates).Error; err != nil {
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to update re-encrypted secret_version id=%d: %w", version.ID, err)
			}

			totalSwept++
			if isLegacy {
				totalLegacyUpgraded++
			}
		}

		offset += sweepBatchSize
		log.Printf("[sweep] secret_versions: %d rows processed", totalSwept)
	}

	return totalSwept, totalLegacyUpgraded, nil
}

// sweepSessions re-encrypts all encrypted_session_token rows.
func sweepSessions(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string) (int, error) {
	var sessions []models.Session
	if err := tx.Find(&sessions).Error; err != nil {
		return 0, fmt.Errorf("failed to fetch sessions: %w", err)
	}

	swept := 0
	for _, session := range sessions {
		if len(session.EncryptedSessionToken) == 0 {
			continue
		}

		encrypted, err := DeserializeEncryptedData(session.EncryptedSessionToken)
		if err != nil {
			return swept, fmt.Errorf("failed to deserialize session id=%d: %w", session.ID, err)
		}

		plaintext, err := oldSvc.Decrypt(encrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to decrypt session id=%d: %w", session.ID, err)
		}

		newEncrypted, err := newSvc.Encrypt(plaintext, newKeyVersion)
		wipeBytes(plaintext)
		if err != nil {
			return swept, fmt.Errorf("failed to re-encrypt session id=%d: %w", session.ID, err)
		}

		newEncryptedBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to serialize session id=%d: %w", session.ID, err)
		}

		metadataBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, fmt.Errorf("failed to marshal session metadata id=%d: %w", session.ID, err)
		}

		updates := map[string]interface{}{
			"encrypted_session_token": newEncryptedBytes,
			"session_token_metadata":  models.JSON(metadataBytes),
		}
		if err := tx.Model(&models.Session{}).Where("id = ?", session.ID).Updates(updates).Error; err != nil {
			return swept, fmt.Errorf("failed to update session id=%d: %w", session.ID, err)
		}
		swept++
	}

	return swept, nil
}

// sweepAPITokens re-encrypts all encrypted_token rows in api_tokens.
func sweepAPITokens(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string) (int, error) {
	var tokens []models.APIToken
	if err := tx.Find(&tokens).Error; err != nil {
		return 0, fmt.Errorf("failed to fetch api_tokens: %w", err)
	}

	swept := 0
	for _, token := range tokens {
		if len(token.EncryptedToken) == 0 {
			continue
		}

		encrypted, err := DeserializeEncryptedData(token.EncryptedToken)
		if err != nil {
			return swept, fmt.Errorf("failed to deserialize api_token id=%d: %w", token.ID, err)
		}

		plaintext, err := oldSvc.Decrypt(encrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to decrypt api_token id=%d: %w", token.ID, err)
		}

		newEncrypted, err := newSvc.Encrypt(plaintext, newKeyVersion)
		wipeBytes(plaintext)
		if err != nil {
			return swept, fmt.Errorf("failed to re-encrypt api_token id=%d: %w", token.ID, err)
		}

		newEncryptedBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to serialize api_token id=%d: %w", token.ID, err)
		}

		metadataBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, fmt.Errorf("failed to marshal api_token metadata id=%d: %w", token.ID, err)
		}

		updates := map[string]interface{}{
			"encrypted_token": newEncryptedBytes,
			"token_metadata":  models.JSON(metadataBytes),
		}
		if err := tx.Model(&models.APIToken{}).Where("id = ?", token.ID).Updates(updates).Error; err != nil {
			return swept, fmt.Errorf("failed to update api_token id=%d: %w", token.ID, err)
		}
		swept++
	}

	return swept, nil
}

// sweepAPIClients re-encrypts all encrypted_client_secret rows in api_clients.
func sweepAPIClients(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string) (int, error) {
	var clients []models.APIClient
	if err := tx.Find(&clients).Error; err != nil {
		return 0, fmt.Errorf("failed to fetch api_clients: %w", err)
	}

	swept := 0
	for _, client := range clients {
		if len(client.EncryptedClientSecret) == 0 {
			continue
		}

		encrypted, err := DeserializeEncryptedData(client.EncryptedClientSecret)
		if err != nil {
			return swept, fmt.Errorf("failed to deserialize api_client id=%d: %w", client.ID, err)
		}

		plaintext, err := oldSvc.Decrypt(encrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to decrypt api_client id=%d: %w", client.ID, err)
		}

		newEncrypted, err := newSvc.Encrypt(plaintext, newKeyVersion)
		wipeBytes(plaintext)
		if err != nil {
			return swept, fmt.Errorf("failed to re-encrypt api_client id=%d: %w", client.ID, err)
		}

		newEncryptedBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to serialize api_client id=%d: %w", client.ID, err)
		}

		metadataBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, fmt.Errorf("failed to marshal api_client metadata id=%d: %w", client.ID, err)
		}

		updates := map[string]interface{}{
			"encrypted_client_secret": newEncryptedBytes,
			"client_secret_metadata":  models.JSON(metadataBytes),
		}
		if err := tx.Model(&models.APIClient{}).Where("id = ?", client.ID).Updates(updates).Error; err != nil {
			return swept, fmt.Errorf("failed to update api_client id=%d: %w", client.ID, err)
		}
		swept++
	}

	return swept, nil
}

// sweepPasswordResets re-encrypts all encrypted_token rows in password_resets.
func sweepPasswordResets(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string) (int, error) {
	var resets []models.PasswordReset
	if err := tx.Find(&resets).Error; err != nil {
		return 0, fmt.Errorf("failed to fetch password_resets: %w", err)
	}

	swept := 0
	for _, reset := range resets {
		if len(reset.EncryptedToken) == 0 {
			continue
		}

		encrypted, err := DeserializeEncryptedData(reset.EncryptedToken)
		if err != nil {
			return swept, fmt.Errorf("failed to deserialize password_reset id=%d: %w", reset.ID, err)
		}

		plaintext, err := oldSvc.Decrypt(encrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to decrypt password_reset id=%d: %w", reset.ID, err)
		}

		newEncrypted, err := newSvc.Encrypt(plaintext, newKeyVersion)
		wipeBytes(plaintext)
		if err != nil {
			return swept, fmt.Errorf("failed to re-encrypt password_reset id=%d: %w", reset.ID, err)
		}

		newEncryptedBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to serialize password_reset id=%d: %w", reset.ID, err)
		}

		metadataBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, fmt.Errorf("failed to marshal password_reset metadata id=%d: %w", reset.ID, err)
		}

		updates := map[string]interface{}{
			"encrypted_token": newEncryptedBytes,
			"token_metadata":  models.JSON(metadataBytes),
		}
		if err := tx.Model(&models.PasswordReset{}).Where("id = ?", reset.ID).Updates(updates).Error; err != nil {
			return swept, fmt.Errorf("failed to update password_reset id=%d: %w", reset.ID, err)
		}
		swept++
	}

	return swept, nil
}
