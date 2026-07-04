// remote_secrets.go — Secret node and version operations for RemoteStorage.
//
// Covers: CreateSecret, GetSecret, GetSecretByName, UpdateSecret, DeleteSecret,
//
//	ListSecrets, CreateSecretVersion, GetSecretVersion, GetSecretVersions,
//	GetLatestSecretVersion, ListSecretVersions, IncrementSecretReadCount.
//
// All operations proxy to the Keyorix REST API via the embedded HTTPClient.
// For the local (GORM) equivalent see local_secrets.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CreateSecret creates a new secret via remote API.
func (rs *RemoteStorage) CreateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/secrets", secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create secret failed: %s", resp.Error.Error())
	}
	var result models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetSecret retrieves a secret by ID via remote API.
func (rs *RemoteStorage) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get secret failed: %s", resp.Error.Error())
	}
	var result models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetSecretByName retrieves a secret by name and scope context via remote API.
func (rs *RemoteStorage) GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error) {
	path := fmt.Sprintf("/api/v1/secrets/by-name/%s?project_id=%d&environment_id=%d",
		url.PathEscape(name), projectID, environmentID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret by name: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get secret by name failed: %s", resp.Error.Error())
	}
	var result models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// UpdateSecret updates an existing secret via remote API.
func (rs *RemoteStorage) UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d", secret.ID)
	resp, err := rs.client.Put(ctx, path, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to update secret: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("update secret failed: %s", resp.Error.Error())
	}
	var result models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// DeleteSecret deletes a secret by ID via remote API.
func (rs *RemoteStorage) DeleteSecret(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/secrets/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete secret failed: %s", resp.Error.Error())
	}
	return nil
}

// GetSecretIncludingDeleted is not available in remote mode; restore resolves server-side.
func (rs *RemoteStorage) GetSecretIncludingDeleted(_ context.Context, _ uint) (*models.SecretNode, error) {
	return nil, remoteUnsupported("GetSecretIncludingDeleted")
}

func (rs *RemoteStorage) RestoreSecret(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/secrets/%d/restore", id)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to restore secret: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("restore secret failed: %s", resp.Error.Error())
	}
	return nil
}

// Retention purge runs server-side (ADR-032/033); not available in remote mode.
func (rs *RemoteStorage) PurgeDeletedSecretsBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("PurgeDeletedSecretsBefore")
}

// Data-retention purges run server-side (the scheduler); not available remotely.
func (rs *RemoteStorage) DeleteAnomalyAlertsBefore(_ context.Context, _, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("DeleteAnomalyAlertsBefore")
}

func (rs *RemoteStorage) DeleteClosedAccessReviewsBefore(_ context.Context, _ time.Time) (int64, int64, error) {
	return 0, 0, remoteUnsupported("DeleteClosedAccessReviewsBefore")
}

func (rs *RemoteStorage) DeleteExpiredBreakGlassBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("DeleteExpiredBreakGlassBefore")
}

func (rs *RemoteStorage) DeleteResolvedAccessRequestsBefore(_ context.Context, _ time.Time) (int64, int64, error) {
	return 0, 0, remoteUnsupported("DeleteResolvedAccessRequestsBefore")
}

// ListSecrets lists secrets with optional filtering via remote API.
// Query parameters are built from the non-nil fields of filter.
func (rs *RemoteStorage) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	path := buildSecretFilterPath(filter)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list secrets: %w", err)
	}
	if !resp.Success {
		return nil, 0, fmt.Errorf("list secrets failed: %s", resp.Error.Error())
	}
	var result struct {
		Secrets []*models.SecretNode `json:"secrets"`
		Total   int64                `json:"total"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Secrets, result.Total, nil
}

// ListProjectSecretsForDrift is not available in remote mode; drift detection aggregates server-side.
func (rs *RemoteStorage) ListProjectSecretsForDrift(_ context.Context, _ uint) ([]storage.DriftSecretRow, error) {
	return nil, fmt.Errorf("ListProjectSecretsForDrift not available in remote mode")
}

// ListOrphanedSecrets is not available in remote mode; the orphaned-owner JOIN runs server-side.
func (rs *RemoteStorage) ListOrphanedSecrets(_ context.Context, _ uint) ([]*models.SecretNode, error) {
	return nil, fmt.Errorf("ListOrphanedSecrets not available in remote mode")
}

// GetSecretTags / SetSecretTags are not available in remote mode; tag storage is server-side.
func (rs *RemoteStorage) GetSecretTags(_ context.Context, _ uint) ([]string, error) {
	return nil, fmt.Errorf("GetSecretTags not available in remote mode")
}

func (rs *RemoteStorage) SetSecretTags(_ context.Context, _ uint, _ []string) error {
	return fmt.Errorf("SetSecretTags not available in remote mode")
}

// buildSecretFilterPath constructs the /api/v1/secrets query string from filter fields.
func buildSecretFilterPath(filter *storage.SecretFilter) string {
	if filter == nil {
		return "/api/v1/secrets"
	}
	params := newQueryBuilder()
	params.addUint("project_id", filter.ProjectID)
	params.addUint("environment_id", filter.EnvironmentID)
	params.addString("type", filter.Type)
	params.addString("created_by", filter.CreatedBy)
	params.addUint("owner_id", filter.OwnerID)
	params.addTime("expires_before", filter.ExpiresBefore)
	params.addTime("created_after", filter.CreatedAfter)
	params.addTime("created_before", filter.CreatedBefore)
	params.addTags("tags", filter.Tags)
	params.addPage(filter.Page, filter.PageSize)
	return "/api/v1/secrets" + params.String()
}

// --- Version operations ---

// CreateSecretVersion creates a new version of a secret via remote API.
func (rs *RemoteStorage) CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d/versions", version.SecretNodeID)
	resp, err := rs.client.Post(ctx, path, version)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret version: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create secret version failed: %s", resp.Error.Error())
	}
	var result models.SecretVersion
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetSecretVersion retrieves a specific version of a secret via remote API.
func (rs *RemoteStorage) GetSecretVersion(ctx context.Context, secretID uint, version int) (*models.SecretVersion, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d/versions/%d", secretID, version)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret version: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get secret version failed: %s", resp.Error.Error())
	}
	var result models.SecretVersion
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// ListSecretVersions lists all versions of a secret via remote API.
func (rs *RemoteStorage) ListSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d/versions", secretID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list secret versions: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list secret versions failed: %s", resp.Error.Error())
	}
	var result []*models.SecretVersion
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// GetSecretVersions is an alias for ListSecretVersions, satisfying the interface.
func (rs *RemoteStorage) GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	return rs.ListSecretVersions(ctx, secretID)
}

// GetLatestSecretVersion retrieves the most recent version of a secret via remote API.
// SetSecretCertNotAfter is a server-side concern (the certificate scan runs on the
// server); the remote client never invokes it.
func (rs *RemoteStorage) SetSecretCertNotAfter(_ context.Context, _ uint, _ *time.Time) error {
	return remoteUnsupported("SetSecretCertNotAfter")
}

func (rs *RemoteStorage) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d/versions/latest", secretID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest secret version: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get latest secret version failed: %s", resp.Error.Error())
	}
	var result models.SecretVersion
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// IncrementSecretReadCount increments the read counter for a secret version via remote API.
func (rs *RemoteStorage) IncrementSecretReadCount(ctx context.Context, versionID uint) error {
	path := fmt.Sprintf("/api/v1/secret-versions/%d/increment-read-count", versionID)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to increment read count: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("increment read count failed: %s", resp.Error.Error())
	}
	return nil
}

// TryIncrementSecretReadCount is the max-reads burn-after-N-reads gate
// (internal/core/storage/interface.go). LocalStorage implements it as a real
// conditional `UPDATE ... WHERE read_count < maxReads` (local_secrets.go) so
// concurrent readers can never collectively exceed the cap.
//
// The server exposes no REST endpoint for this conditional check-and-increment
// today — only a plain, non-conditional increment-read-count route is proxyable
// via IncrementSecretReadCount, and even that route isn't currently registered
// in router.go (confirmed: no /secret-versions/{id}/increment-read-count route
// exists server-side). Blindly delegating to the unconditional increment would
// silently defeat maxReads for any deployment/future code path that reaches this
// method through storage.type: remote — it would always report success without
// ever checking the cap. Fail closed instead: report unsupported so the caller
// (readVersionValue, internal/core/versions.go) takes its existing fail-closed
// branch and refuses the read, rather than silently granting an unbounded number
// of reads on a max-reads-limited secret (#188).
//
// This method is not on the live remote value-read path today — the CLI's
// value-read path goes through a separate, already max-reads-enforcing HTTP
// endpoint on the server, not through core.KeyorixCore/RemoteStorage — so this
// closes a latent landmine, not a currently-exploitable gap. A real fix that
// preserves remote-mode support for max-reads secrets would require a new
// atomic conditional-increment REST endpoint mirroring LocalStorage's semantics;
// that is a larger scope than this fix and remains a documented gap.
func (rs *RemoteStorage) TryIncrementSecretReadCount(_ context.Context, _ uint, _ int) (bool, error) {
	return false, remoteUnsupported("TryIncrementSecretReadCount")
}

// TryIncrementSecretNodeReadCount mirrors TryIncrementSecretReadCount: the
// authoritative enforcement runs server-side against local storage, so a remote
// client is never on the enforcement hot path. Not expected to be called from a
// CLI/remote context (KeyorixCore always runs against LocalStorage server-side);
// fails loud rather than silently reporting success if it ever is.
func (rs *RemoteStorage) TryIncrementSecretNodeReadCount(ctx context.Context, secretID uint, maxReads int) (bool, error) {
	return false, fmt.Errorf("remote storage: max-reads enforcement is server-side only")
}
