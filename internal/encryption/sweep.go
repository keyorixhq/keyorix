// sweep.go — SweepAllTables orchestrator and sweepSecretVersions (AAD-aware).
//
// Called by RotateDEKWithSweep inside a DB transaction. Re-encrypts every
// DEK-encrypted row so no ciphertext remains under the old DEK.
//
// sweepSecretVersions is here because it requires AAD reconstruction logic
// (namespace lookup, SecretAAD, legacy-vs-bound path). The simpler auth-table
// sweepers (sessions, API tokens, clients, password resets) live in sweep_auth.go.
//
// Invariant: on nil return, every row holds ciphertext under the new DEK.
// Secret values are transient in memory only — never logged or returned.
package encryption

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
	LegacyAADUpgraded   int
}

// SweepAllTables re-encrypts every DEK-encrypted row within a single DB transaction.
// oldSvc decrypts; newSvc re-encrypts. Called while both DEK services are live in memory.
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
//
// Two cases:
//   - AAD-bound rows (aad_version="v1"): reconstruct AAD, decrypt with old
//     AAD-aware path, re-encrypt with new DEK + same AAD.
//   - Legacy rows (no aad_version): decrypt without AAD, re-encrypt with new
//     DEK + correct AAD (completes the M2 AAD migration).
//
// Returns (rowsSwept, legacyRowsUpgraded, error).
func sweepSecretVersions(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string) (int, int, error) {
	var offset int
	var totalSwept, totalLegacyUpgraded int

	// Pre-fetch secretNodeID → namespaceID to avoid N+1 queries.
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

			isLegacy := encrypted.Metadata.AADVersion == ""
			var plaintext []byte
			if isLegacy {
				plaintext, err = oldSvc.Decrypt(encrypted)
			} else {
				plaintext, err = oldSvc.DecryptWithAAD(encrypted, aad)
			}
			if err != nil {
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to decrypt secret_version id=%d: %w", version.ID, err)
			}

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

			if err := tx.Model(&models.SecretVersion{}).Where("id = ?", version.ID).Updates(map[string]interface{}{
				"encrypted_value":     newEncryptedBytes,
				"encryption_metadata": models.JSON(metadataBytes),
			}).Error; err != nil {
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
