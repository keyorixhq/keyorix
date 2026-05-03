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
func (rs *RemoteStorage) GetSecretByName(ctx context.Context, name string, namespaceID, zoneID, environmentID uint) (*models.SecretNode, error) {
	path := fmt.Sprintf("/api/v1/secrets/by-name/%s?namespace_id=%d&zone_id=%d&environment_id=%d",
		name, namespaceID, zoneID, environmentID)
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

// buildSecretFilterPath constructs the /api/v1/secrets query string from filter fields.
func buildSecretFilterPath(filter *storage.SecretFilter) string {
	if filter == nil {
		return "/api/v1/secrets"
	}
	params := newQueryBuilder()
	params.addUint("namespace_id", filter.NamespaceID)
	params.addUint("zone_id", filter.ZoneID)
	params.addUint("environment_id", filter.EnvironmentID)
	params.addString("type", filter.Type)
	params.addString("created_by", filter.CreatedBy)
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
