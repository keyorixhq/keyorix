// remote_sharing.go — ShareRecord operations for RemoteStorage.
//
// Covers: CreateShareRecord, GetShareRecord, UpdateShareRecord, DeleteShareRecord,
//
//	ListSharesBySecret, ListSharesByUser, ListSharesByOwner, ListSharesByGroup,
//	ListSharedSecrets, CheckSharePermission.
//
// For the local (GORM) equivalent see local_sharing.go (not yet implemented).
package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CreateShareRecord creates a new share record via remote API.
func (rs *RemoteStorage) CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/shares", share)
	if err != nil {
		return nil, fmt.Errorf("failed to create share record: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create share record failed: %s", resp.Error.Error())
	}
	var result models.ShareRecord
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetShareRecord retrieves a share record by ID via remote API.
func (rs *RemoteStorage) GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error) {
	path := fmt.Sprintf("/api/v1/shares/%d", shareID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get share record: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get share record failed: %s", resp.Error.Error())
	}
	var result models.ShareRecord
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// UpdateShareRecord updates an existing share record via remote API.
func (rs *RemoteStorage) UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	path := fmt.Sprintf("/api/v1/shares/%d", share.ID)
	resp, err := rs.client.Put(ctx, path, share)
	if err != nil {
		return nil, fmt.Errorf("failed to update share record: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("update share record failed: %s", resp.Error.Error())
	}
	var result models.ShareRecord
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// DeleteShareRecord deletes a share record via remote API.
func (rs *RemoteStorage) DeleteShareRecord(ctx context.Context, shareID uint) error {
	path := fmt.Sprintf("/api/v1/shares/%d", shareID)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete share record: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete share record failed: %s", resp.Error.Error())
	}
	return nil
}

// ListSharesBySecret lists all share records for a given secret via remote API.
func (rs *RemoteStorage) ListSharesBySecret(ctx context.Context, secretID uint) ([]*models.ShareRecord, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d/shares", secretID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list shares by secret: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list shares by secret failed: %s", resp.Error.Error())
	}
	var result []*models.ShareRecord
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// ListSharesByUser lists all share records where userID is the recipient via remote API.
func (rs *RemoteStorage) ListSharesByUser(ctx context.Context, userID uint) ([]*models.ShareRecord, error) {
	path := fmt.Sprintf("/api/v1/users/%d/shares", userID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list shares by user: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list shares by user failed: %s", resp.Error.Error())
	}
	var result []*models.ShareRecord
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// ListSharesByOwner lists share records by owner. Not yet implemented; returns empty slice.
func (rs *RemoteStorage) ListSharesByOwner(_ context.Context, _ uint) ([]*models.ShareRecord, error) {
	return []*models.ShareRecord{}, nil
}

// ListSharesByGroup lists all share records where groupID is the recipient via remote API.
func (rs *RemoteStorage) ListSharesByGroup(ctx context.Context, groupID uint) ([]*models.ShareRecord, error) {
	path := fmt.Sprintf("/api/v1/groups/%d/shares", groupID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list shares by group: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list shares by group failed: %s", resp.Error.Error())
	}
	var result []*models.ShareRecord
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// ListSharedSecrets lists all secrets shared with userID via remote API.
func (rs *RemoteStorage) ListSharedSecrets(ctx context.Context, userID uint) ([]*models.SecretNode, error) {
	path := fmt.Sprintf("/api/v1/users/%d/shared-secrets", userID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list shared secrets: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list shared secrets failed: %s", resp.Error.Error())
	}
	var result []*models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// CheckSharePermission returns the permission level a user has on a secret via remote API.
func (rs *RemoteStorage) CheckSharePermission(ctx context.Context, secretID, userID uint) (string, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d/permissions?user_id=%d", secretID, userID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return "", fmt.Errorf("failed to check share permission: %w", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("check share permission failed: %s", resp.Error.Error())
	}
	var result struct {
		Permission string `json:"permission"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Permission, nil
}
