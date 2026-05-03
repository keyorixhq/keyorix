// remote_users.go — User and Group operations for RemoteStorage.
//
// Covers: CreateUser, GetUser, GetUserByEmail, GetUserByUsername, UpdateUser,
//
//	DeleteUser, RestoreUser, ListUsers, GetUserGroups,
//	CreateGroup, GetGroup, UpdateGroup, DeleteGroup, ListGroups,
//	AddUserToGroup, RemoveUserFromGroup, ListGroupMembers.
//
// Group methods (CreateGroup … ListGroupMembers) are stubs — not yet implemented
// on the remote API. For the local (GORM) equivalent see local_users.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- Users ---

// CreateUser creates a new user via remote API.
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

// GetUser retrieves a user by ID via remote API.
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

// GetUserByEmail retrieves a user by email via remote API.
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

// GetUserByUsername is not implemented for remote storage.
func (rs *RemoteStorage) GetUserByUsername(_ context.Context, _ string) (*models.User, error) {
	return nil, fmt.Errorf("GetUserByUsername not implemented for remote storage")
}

// UpdateUser updates an existing user via remote API.
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

// DeleteUser deletes a user via remote API.
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

// RestoreUser restores a soft-deleted user via remote API.
func (rs *RemoteStorage) RestoreUser(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/users/%d/restore", id)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to restore user: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("restore user failed: %s", resp.Error.Error())
	}
	return nil
}

// ListUsers lists users with optional filtering via remote API.
func (rs *RemoteStorage) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	path := buildUserFilterPath(filter)
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

// buildUserFilterPath constructs the /api/v1/users query string.
func buildUserFilterPath(filter *storage.UserFilter) string {
	if filter == nil {
		return "/api/v1/users"
	}
	params := newQueryBuilder()
	params.addString("search", filter.Search)
	params.addString("username", filter.Username)
	params.addString("email", filter.Email)
	params.addBool("is_active", filter.IsActive)
	params.addTime("created_after", filter.CreatedAfter)
	params.addPage(filter.Page, filter.PageSize)
	return "/api/v1/users" + params.String()
}

// GetUserGroups returns all groups a user belongs to.
// Returns an empty slice — group membership resolution is not yet implemented remotely.
func (rs *RemoteStorage) GetUserGroups(_ context.Context, _ uint) ([]*models.Group, error) {
	return []*models.Group{}, nil
}

// --- Groups (stubs — not yet implemented on remote API) ---

func (rs *RemoteStorage) CreateGroup(_ context.Context, _ *models.Group) (*models.Group, error) {
	return nil, fmt.Errorf("CreateGroup not implemented for remote storage")
}

func (rs *RemoteStorage) GetGroup(_ context.Context, _ uint) (*models.Group, error) {
	return nil, fmt.Errorf("GetGroup not implemented for remote storage")
}

func (rs *RemoteStorage) UpdateGroup(_ context.Context, _ *models.Group) (*models.Group, error) {
	return nil, fmt.Errorf("UpdateGroup not implemented for remote storage")
}

func (rs *RemoteStorage) DeleteGroup(_ context.Context, _ uint) error {
	return fmt.Errorf("DeleteGroup not implemented for remote storage")
}

func (rs *RemoteStorage) ListGroups(_ context.Context) ([]*models.Group, error) {
	return nil, fmt.Errorf("ListGroups not implemented for remote storage")
}

func (rs *RemoteStorage) AddUserToGroup(_ context.Context, _, _ uint) error {
	return fmt.Errorf("AddUserToGroup not implemented for remote storage")
}

func (rs *RemoteStorage) RemoveUserFromGroup(_ context.Context, _, _ uint) error {
	return fmt.Errorf("RemoveUserFromGroup not implemented for remote storage")
}

func (rs *RemoteStorage) ListGroupMembers(_ context.Context, _ uint) ([]*models.User, error) {
	return nil, fmt.Errorf("ListGroupMembers not implemented for remote storage")
}
