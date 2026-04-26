package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RemoteStorage implements the Storage interface for remote API calls
type RemoteStorage struct {
	client *HTTPClient
}

// NewRemoteStorage creates a new remote storage instance
func NewRemoteStorage(config *Config) (*RemoteStorage, error) {
	client, err := NewHTTPClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	return &RemoteStorage{
		client: client,
	}, nil
}

func (rs *RemoteStorage) CreatePermission(_ context.Context, _ *models.Permission) (*models.Permission, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

func (rs *RemoteStorage) AssignPermissionToRole(_ context.Context, _, _ uint) error {
	return fmt.Errorf("not supported in remote storage")
}

func (rs *RemoteStorage) CreateNamespace(_ context.Context, _ *models.Namespace) (*models.Namespace, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

func (rs *RemoteStorage) CreateZone(_ context.Context, _ *models.Zone) (*models.Zone, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

func (rs *RemoteStorage) CreateEnvironment(_ context.Context, _ *models.Environment) (*models.Environment, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

// ListNamespaces is not supported in remote mode; returns an empty list.
func (rs *RemoteStorage) ListNamespaces(_ context.Context) ([]*models.Namespace, error) {
	return nil, fmt.Errorf("not implemented in remote storage")
}

// ListZones is not supported in remote mode.
func (rs *RemoteStorage) ListZones(_ context.Context) ([]*models.Zone, error) {
	return nil, fmt.Errorf("not implemented in remote storage")
}

// ListEnvironments is not supported in remote mode; returns an empty list.
func (rs *RemoteStorage) ListEnvironments(_ context.Context) ([]*models.Environment, error) {
	return nil, fmt.Errorf("not implemented in remote storage")
}

// CreateSecret creates a new secret via remote API
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

// GetSecret retrieves a secret by ID via remote API
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

// UpdateSecret updates an existing secret via remote API
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

// DeleteSecret deletes a secret by ID via remote API
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

// ListSecrets lists secrets with optional filtering via remote API
func (rs *RemoteStorage) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	path := "/api/v1/secrets"

	// Add query parameters for filtering
	if filter != nil {
		path += "?"
		params := []string{}

		if filter.NamespaceID != nil {
			params = append(params, fmt.Sprintf("namespace_id=%d", *filter.NamespaceID))
		}
		if filter.ZoneID != nil {
			params = append(params, fmt.Sprintf("zone_id=%d", *filter.ZoneID))
		}
		if filter.EnvironmentID != nil {
			params = append(params, fmt.Sprintf("environment_id=%d", *filter.EnvironmentID))
		}
		if filter.Type != nil {
			params = append(params, fmt.Sprintf("type=%s", *filter.Type))
		}
		if filter.CreatedBy != nil {
			params = append(params, fmt.Sprintf("created_by=%s", *filter.CreatedBy))
		}
		if filter.CreatedAfter != nil {
			params = append(params, fmt.Sprintf("created_after=%s", filter.CreatedAfter.Format("2006-01-02T15:04:05Z")))
		}
		if filter.CreatedBefore != nil {
			params = append(params, fmt.Sprintf("created_before=%s", filter.CreatedBefore.Format("2006-01-02T15:04:05Z")))
		}
		if len(filter.Tags) > 0 {
			for _, tag := range filter.Tags {
				params = append(params, fmt.Sprintf("tags=%s", tag))
			}
		}
		if filter.Page > 0 {
			params = append(params, fmt.Sprintf("page=%d", filter.Page))
		}
		if filter.PageSize > 0 {
			params = append(params, fmt.Sprintf("page_size=%d", filter.PageSize))
		}

		// Join parameters
		for i, param := range params {
			if i > 0 {
				path += "&"
			}
			path += param
		}
	}

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

// CreateSecretVersion creates a new version of a secret via remote API
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

// GetSecretVersion retrieves a specific version of a secret via remote API
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

// ListSecretVersions lists all versions of a secret via remote API
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

// GetLatestSecretVersion retrieves the latest version of a secret via remote API
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

// GetSecretByName retrieves a secret by name and context via remote API
func (rs *RemoteStorage) GetSecretByName(ctx context.Context, name string, namespaceID, zoneID, environmentID uint) (*models.SecretNode, error) {
	path := fmt.Sprintf("/api/v1/secrets/by-name/%s?namespace_id=%d&zone_id=%d&environment_id=%d", name, namespaceID, zoneID, environmentID)
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

// GetSecretVersions retrieves all versions of a secret via remote API
func (rs *RemoteStorage) GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	return rs.ListSecretVersions(ctx, secretID)
}

// IncrementSecretReadCount increments the read count for a secret version via remote API
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

// CreateShareRecord creates a new share record via remote API
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

// GetShareRecord retrieves a share record by ID via remote API
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

// UpdateShareRecord updates an existing share record via remote API
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

// DeleteShareRecord deletes a share record via remote API
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

// ListSharesBySecret lists all share records for a secret via remote API
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

// ListSharesByUser lists all share records where the user is the recipient via remote API
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

// ListSharesByOwner lists shares by owner via remote API (not implemented; empty list).
func (rs *RemoteStorage) ListSharesByOwner(ctx context.Context, ownerID uint) ([]*models.ShareRecord, error) {
	return []*models.ShareRecord{}, nil
}

// ListSharesByGroup lists all share records where the group is the recipient via remote API
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

// ListSharedSecrets lists all secrets shared with a user via remote API
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

// CheckSharePermission checks if a user has permission to access a secret via remote API
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

// Health checks the health of the remote storage connection
func (rs *RemoteStorage) Health(ctx context.Context) error {
	resp, err := rs.client.Get(ctx, "/health")
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("health check failed: %s", resp.Error.Error())
	}

	return nil
}

// User Management Methods

// CreateUser creates a new user via remote API
func (rs *RemoteStorage) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/users", user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("create user failed: %s", resp.Error.Error())
	}

	var result models.User
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// GetUser retrieves a user by ID via remote API
func (rs *RemoteStorage) GetUser(ctx context.Context, id uint) (*models.User, error) {
	path := fmt.Sprintf("/api/v1/users/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("get user failed: %s", resp.Error.Error())
	}

	var result models.User
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// GetUserByEmail retrieves a user by email via remote API
func (rs *RemoteStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	path := fmt.Sprintf("/api/v1/users/by-email/%s", email)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("get user by email failed: %s", resp.Error.Error())
	}

	var result models.User
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// UpdateUser updates an existing user via remote API
func (rs *RemoteStorage) UpdateUser(ctx context.Context, user *models.User) (*models.User, error) {
	path := fmt.Sprintf("/api/v1/users/%d", user.ID)
	resp, err := rs.client.Put(ctx, path, user)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("update user failed: %s", resp.Error.Error())
	}

	var result models.User
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// DeleteUser deletes a user via remote API
func (rs *RemoteStorage) DeleteUser(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/users/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("delete user failed: %s", resp.Error.Error())
	}

	return nil
}

// ListUsers lists users with optional filtering via remote API
func (rs *RemoteStorage) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	path := "/api/v1/users"

	// Add query parameters for filtering
	if filter != nil {
		path += "?"
		params := []string{}

		if filter.Search != nil {
			params = append(params, fmt.Sprintf("search=%s", *filter.Search))
		}
		if filter.Username != nil {
			params = append(params, fmt.Sprintf("username=%s", *filter.Username))
		}
		if filter.Email != nil {
			params = append(params, fmt.Sprintf("email=%s", *filter.Email))
		}
		if filter.IsActive != nil {
			params = append(params, fmt.Sprintf("is_active=%t", *filter.IsActive))
		}
		if filter.CreatedAfter != nil {
			params = append(params, fmt.Sprintf("created_after=%s", filter.CreatedAfter.Format("2006-01-02T15:04:05Z")))
		}
		if filter.Page > 0 {
			params = append(params, fmt.Sprintf("page=%d", filter.Page))
		}
		if filter.PageSize > 0 {
			params = append(params, fmt.Sprintf("page_size=%d", filter.PageSize))
		}

		// Join parameters
		for i, param := range params {
			if i > 0 {
				path += "&"
			}
			path += param
		}
	}

	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}

	if !resp.Success {
		return nil, 0, fmt.Errorf("list users failed: %s", resp.Error.Error())
	}

	var result struct {
		Users []*models.User `json:"users"`
		Total int64          `json:"total"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, 0, fmt.Errorf("failed to parse response: %w", err)
	}

	return result.Users, result.Total, nil
}

// GetUserByUsername retrieves a user by username via remote API (not implemented)
func (rs *RemoteStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	return nil, fmt.Errorf("GetUserByUsername not implemented for remote storage")
}

// CreateGroup creates a group via remote API (not implemented)
func (rs *RemoteStorage) CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	return nil, fmt.Errorf("CreateGroup not implemented for remote storage")
}

// GetGroup retrieves a group by ID via remote API (not implemented)
func (rs *RemoteStorage) GetGroup(ctx context.Context, id uint) (*models.Group, error) {
	return nil, fmt.Errorf("GetGroup not implemented for remote storage")
}

// UpdateGroup updates a group via remote API (not implemented)
func (rs *RemoteStorage) UpdateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	return nil, fmt.Errorf("UpdateGroup not implemented for remote storage")
}

// DeleteGroup deletes a group via remote API (not implemented)
func (rs *RemoteStorage) DeleteGroup(ctx context.Context, id uint) error {
	return fmt.Errorf("DeleteGroup not implemented for remote storage")
}

// ListGroups lists groups via remote API (not implemented)
func (rs *RemoteStorage) ListGroups(ctx context.Context) ([]*models.Group, error) {
	return nil, fmt.Errorf("ListGroups not implemented for remote storage")
}

// AddUserToGroup adds a user to a group via remote API (not implemented)
func (rs *RemoteStorage) AddUserToGroup(ctx context.Context, userID, groupID uint) error {
	return fmt.Errorf("AddUserToGroup not implemented for remote storage")
}

// RemoveUserFromGroup removes a user from a group via remote API (not implemented)
func (rs *RemoteStorage) RemoveUserFromGroup(ctx context.Context, userID, groupID uint) error {
	return fmt.Errorf("RemoveUserFromGroup not implemented for remote storage")
}

// ListGroupMembers lists group members via remote API (not implemented)
func (rs *RemoteStorage) ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error) {
	return nil, fmt.Errorf("ListGroupMembers not implemented for remote storage")
}

// Role Management Methods

// CreateRole creates a new role via remote API
func (rs *RemoteStorage) CreateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/roles", role)
	if err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("create role failed: %s", resp.Error.Error())
	}

	var result models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// GetRole retrieves a role by ID via remote API
func (rs *RemoteStorage) GetRole(ctx context.Context, id uint) (*models.Role, error) {
	path := fmt.Sprintf("/api/v1/roles/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("get role failed: %s", resp.Error.Error())
	}

	var result models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// GetRoleByName retrieves a role by name via remote API
func (rs *RemoteStorage) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	path := fmt.Sprintf("/api/v1/roles/by-name/%s", name)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get role by name: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("get role by name failed: %s", resp.Error.Error())
	}

	var result models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// UpdateRole updates an existing role via remote API
func (rs *RemoteStorage) UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	path := fmt.Sprintf("/api/v1/roles/%d", role.ID)
	resp, err := rs.client.Put(ctx, path, role)
	if err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("update role failed: %s", resp.Error.Error())
	}

	var result models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// DeleteRole deletes a role via remote API
func (rs *RemoteStorage) DeleteRole(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/roles/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("delete role failed: %s", resp.Error.Error())
	}

	return nil
}

// ListRoles lists all roles via remote API
func (rs *RemoteStorage) ListRoles(ctx context.Context) ([]*models.Role, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/roles")
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("list roles failed: %s", resp.Error.Error())
	}

	var result []*models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// RBAC Operations

// AssignRole assigns a role to a user via remote API
func (rs *RemoteStorage) AssignRole(ctx context.Context, userID, roleID uint) error {
	payload := map[string]uint{
		"user_id": userID,
		"role_id": roleID,
	}
	resp, err := rs.client.Post(ctx, "/api/v1/rbac/assign-role", payload)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("assign role failed: %s", resp.Error.Error())
	}

	return nil
}

// RemoveRole removes a role from a user via remote API
func (rs *RemoteStorage) RemoveRole(ctx context.Context, userID, roleID uint) error {
	payload := map[string]uint{
		"user_id": userID,
		"role_id": roleID,
	}
	resp, err := rs.client.Post(ctx, "/api/v1/rbac/remove-role", payload)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("remove role failed: %s", resp.Error.Error())
	}

	return nil
}

// GetUserRoles retrieves all roles for a user via remote API
func (rs *RemoteStorage) GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error) {
	path := fmt.Sprintf("/api/v1/users/%d/roles", userID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("get user roles failed: %s", resp.Error.Error())
	}

	var result []*models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// CheckPermission checks if a user has a specific permission via remote API
func (rs *RemoteStorage) CheckPermission(ctx context.Context, userID uint, resource, action string) (bool, error) {
	path := fmt.Sprintf("/api/v1/rbac/check-permission?user_id=%d&resource=%s&action=%s", userID, resource, action)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}

	if !resp.Success {
		return false, fmt.Errorf("check permission failed: %s", resp.Error.Error())
	}

	var result struct {
		HasPermission bool `json:"has_permission"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}

	return result.HasPermission, nil
}

// GetUserPermissions retrieves all permissions for a user via remote API
func (rs *RemoteStorage) GetUserPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	path := fmt.Sprintf("/api/v1/users/%d/permissions", userID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("get user permissions failed: %s", resp.Error.Error())
	}

	var result []*storage.Permission
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// Audit Logging

// LogAuditEvent logs an audit event via remote API
func (rs *RemoteStorage) LogAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	resp, err := rs.client.Post(ctx, "/api/v1/audit/events", event)
	if err != nil {
		return fmt.Errorf("failed to log audit event: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("log audit event failed: %s", resp.Error.Error())
	}

	return nil
}

// CreateSecretAccessLog is a no-op for remote storage; access logging is handled server-side.
func (rs *RemoteStorage) CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error {
	return nil
}

// GetAuditLogs retrieves audit logs with filtering via remote API
func (rs *RemoteStorage) GetAuditLogs(ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	path := "/api/v1/audit/events"

	// Add query parameters for filtering
	if filter != nil {
		path += "?"
		params := []string{}

		if filter.UserID != nil {
			params = append(params, fmt.Sprintf("user_id=%d", *filter.UserID))
		}
		if filter.Action != nil {
			params = append(params, fmt.Sprintf("action=%s", *filter.Action))
		}
		if filter.Resource != nil {
			params = append(params, fmt.Sprintf("resource=%s", *filter.Resource))
		}
		if filter.Success != nil {
			params = append(params, fmt.Sprintf("success=%t", *filter.Success))
		}
		if filter.StartTime != nil {
			params = append(params, fmt.Sprintf("start_time=%s", filter.StartTime.Format("2006-01-02T15:04:05Z")))
		}
		if filter.EndTime != nil {
			params = append(params, fmt.Sprintf("end_time=%s", filter.EndTime.Format("2006-01-02T15:04:05Z")))
		}
		if filter.Page > 0 {
			params = append(params, fmt.Sprintf("page=%d", filter.Page))
		}
		if filter.PageSize > 0 {
			params = append(params, fmt.Sprintf("page_size=%d", filter.PageSize))
		}

		// Join parameters
		for i, param := range params {
			if i > 0 {
				path += "&"
			}
			path += param
		}
	}

	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get audit logs: %w", err)
	}

	if !resp.Success {
		return nil, 0, fmt.Errorf("get audit logs failed: %s", resp.Error.Error())
	}

	var result struct {
		Events []*models.AuditEvent `json:"events"`
		Total  int64                `json:"total"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, 0, fmt.Errorf("failed to parse response: %w", err)
	}

	return result.Events, result.Total, nil
}

// GetRBACAuditLogs retrieves RBAC audit logs with filtering via remote API
func (rs *RemoteStorage) GetRBACAuditLogs(ctx context.Context, filter *storage.RBACAuditFilter) ([]*storage.RBACAuditLog, int64, error) {
	path := "/api/v1/audit/rbac"

	// Add query parameters for filtering
	if filter != nil {
		path += "?"
		params := []string{}

		if filter.UserID != nil {
			params = append(params, fmt.Sprintf("user_id=%d", *filter.UserID))
		}
		if filter.Action != nil {
			params = append(params, fmt.Sprintf("action=%s", *filter.Action))
		}
		if filter.TargetType != nil {
			params = append(params, fmt.Sprintf("target_type=%s", *filter.TargetType))
		}
		if filter.TargetID != nil {
			params = append(params, fmt.Sprintf("target_id=%d", *filter.TargetID))
		}
		if filter.StartTime != nil {
			params = append(params, fmt.Sprintf("start_time=%s", filter.StartTime.Format("2006-01-02T15:04:05Z")))
		}
		if filter.EndTime != nil {
			params = append(params, fmt.Sprintf("end_time=%s", filter.EndTime.Format("2006-01-02T15:04:05Z")))
		}
		if filter.Page > 0 {
			params = append(params, fmt.Sprintf("page=%d", filter.Page))
		}
		if filter.PageSize > 0 {
			params = append(params, fmt.Sprintf("page_size=%d", filter.PageSize))
		}

		// Join parameters
		for i, param := range params {
			if i > 0 {
				path += "&"
			}
			path += param
		}
	}

	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get RBAC audit logs: %w", err)
	}

	if !resp.Success {
		return nil, 0, fmt.Errorf("get RBAC audit logs failed: %s", resp.Error.Error())
	}

	var result struct {
		Logs  []*storage.RBACAuditLog `json:"logs"`
		Total int64                   `json:"total"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, 0, fmt.Errorf("failed to parse response: %w", err)
	}

	return result.Logs, result.Total, nil
}

// Session Management

// CreateSession creates a new session via remote API
func (rs *RemoteStorage) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/sessions", session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("create session failed: %s", resp.Error.Error())
	}

	var result models.Session
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// GetSession retrieves a session by token via remote API
func (rs *RemoteStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	path := fmt.Sprintf("/api/v1/sessions/%s", token)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("get session failed: %s", resp.Error.Error())
	}

	var result models.Session
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// DeleteSession deletes a session via remote API
func (rs *RemoteStorage) DeleteSession(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/sessions/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("delete session failed: %s", resp.Error.Error())
	}

	return nil
}

// CleanupExpiredSessions cleans up expired sessions via remote API
func (rs *RemoteStorage) CleanupExpiredSessions(ctx context.Context) error {
	resp, err := rs.client.Post(ctx, "/api/v1/sessions/cleanup", nil)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("cleanup expired sessions failed: %s", resp.Error.Error())
	}

	return nil
}

// API Client Management

// CreateAPIClient creates a new API client via remote API
func (rs *RemoteStorage) CreateAPIClient(ctx context.Context, client *models.APIClient) (*models.APIClient, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/api-clients", client)
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("create API client failed: %s", resp.Error.Error())
	}

	var result models.APIClient
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// GetAPIClient retrieves an API client by client ID via remote API
func (rs *RemoteStorage) GetAPIClient(ctx context.Context, clientID string) (*models.APIClient, error) {
	path := fmt.Sprintf("/api/v1/api-clients/%s", clientID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get API client: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("get API client failed: %s", resp.Error.Error())
	}

	var result models.APIClient
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// RevokeAPIClient revokes an API client via remote API
func (rs *RemoteStorage) RevokeAPIClient(ctx context.Context, clientID string) error {
	path := fmt.Sprintf("/api/v1/api-clients/%s/revoke", clientID)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to revoke API client: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("revoke API client failed: %s", resp.Error.Error())
	}

	return nil
}

// Health and Maintenance

// HealthCheck checks the health of the remote storage connection
func (rs *RemoteStorage) HealthCheck(ctx context.Context) error {
	return rs.Health(ctx)
}

// GetUserGroups retrieves all groups a user is a member of via remote API
func (rs *RemoteStorage) GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error) {
	// For now, return empty groups since group functionality is not fully implemented
	// This is a placeholder implementation to satisfy the interface
	return []*models.Group{}, nil
}

// GetStats retrieves storage statistics via remote API
func (rs *RemoteStorage) GetStats(ctx context.Context) (*storage.StorageStats, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/stats")
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("get stats failed: %s", resp.Error.Error())
	}

	var result storage.StorageStats
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// SaveStatsSnapshot is a no-op for remote storage — snapshots are managed server-side.
func (rs *RemoteStorage) SaveStatsSnapshot(ctx context.Context, snapshot *models.StatsSnapshot) error {
	return nil
}

// GetPreviousStatsSnapshot is not supported in remote storage mode.
func (rs *RemoteStorage) GetPreviousStatsSnapshot(ctx context.Context, userID uint) (*models.StatsSnapshot, error) {
	return nil, fmt.Errorf("stats snapshots not available in remote mode")
}

func (rs *RemoteStorage) ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error) {
	return nil, fmt.Errorf("ListSecretAccessLogs not available in remote mode")
}

func (rs *RemoteStorage) CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error {
	return fmt.Errorf("CreateAnomalyAlert not available in remote mode")
}

func (rs *RemoteStorage) ListAnomalyAlerts(ctx context.Context, unacknowledgedOnly bool) ([]models.AnomalyAlert, error) {
	return nil, fmt.Errorf("ListAnomalyAlerts not available in remote mode")
}

func (rs *RemoteStorage) AcknowledgeAnomalyAlert(ctx context.Context, id uint) error {
	return fmt.Errorf("AcknowledgeAnomalyAlert not available in remote mode")
}
