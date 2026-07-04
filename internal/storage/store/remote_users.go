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
	"net/url"
	"time"

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

// LockUserForUpdate has no row lock to take over HTTP — each remote API call is already
// atomic server-side, and the server's own LocalStorage takes the real FOR UPDATE lock
// when it runs the lockout accounting. So this is a plain read.
func (rs *RemoteStorage) LockUserForUpdate(ctx context.Context, id uint) (*models.User, error) {
	return rs.GetUser(ctx, id)
}

// GetUserByEmail retrieves a user by email via remote API.
func (rs *RemoteStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	path := fmt.Sprintf("/api/v1/users/by-email/%s", url.PathEscape(email))
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
	return nil, remoteUnsupported("GetUserByUsername")
}

func (rs *RemoteStorage) GetUserByExternalID(_ context.Context, _ string) (*models.User, error) {
	return nil, remoteUnsupported("GetUserByExternalID")
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

// UpdateLastLogin is not available in remote mode — last_login_at is stamped
// server-side inside the login handler, which always runs against LocalStorage.
func (rs *RemoteStorage) UpdateLastLogin(_ context.Context, _ uint, _ time.Time) error {
	return fmt.Errorf("UpdateLastLogin not available in remote mode")
}

// SetAccountState always hard-fails: account_state has no field in the wire format
// UpdateUser sends (core.UpdateUserRequest only carries username/email/display_name/
// active — see server/http/handlers/users_crud.go and core.UpdateUser), so there is no
// way to actually persist this upstream. Returning an error here — instead of silently
// falling through to a generic write that would just no-op the field — is the whole
// point of this method (#454): setAccountState (admin suspend/reactivate) and
// UpdateSCIMUser (SCIM deprovision/reactivate) must see a hard failure, not a false
// "success" that leaves the account's login-blocking state unchanged.
func (rs *RemoteStorage) SetAccountState(_ context.Context, _ uint, _ string, _ time.Time) error {
	return fmt.Errorf("account_state cannot be persisted through remote storage: the "+
		"upstream PUT /api/v1/users/{id} endpoint does not accept this field: %w", ErrRemoteUnsupported)
}

// SetPasswordHash always hard-fails: password_hash is tagged json:"-" on models.User
// (internal/storage/models/models.go), so it never even reaches the JSON body a
// RemoteStorage UpdateUser call sends — there is no way to persist a password change
// through the remote API at all. Returning an error here — instead of falling through
// to a generic write that would just no-op the field — is the #484 analogue of
// SetAccountState above (#454): applyNewPassword (self-service ChangePassword and the
// setup-token consume flow) must see a hard failure, not a false "success" that leaves
// the stored password hash unchanged.
func (rs *RemoteStorage) SetPasswordHash(_ context.Context, _ uint, _ string, _ time.Time) error {
	return fmt.Errorf("password_hash cannot be persisted through remote storage: the "+
		"upstream PUT /api/v1/users/{id} endpoint does not accept this field: %w", ErrRemoteUnsupported)
}

// UpdateLoginLockoutState always returns ErrRemoteUnsupported: none of the four
// login-lockout columns are expressible in the wire format either (#454), so, unlike
// SetAccountState above, the caller (login_lockout.go) treats this as the same
// "permanent architectural gap" #452 already established for the login rate limiter —
// log a loud one-time operator warning and fail OPEN, rather than blocking every login
// under storage.type: remote.
func (rs *RemoteStorage) UpdateLoginLockoutState(_ context.Context, _ uint, _ int, _, _ *time.Time, _ int) error {
	return remoteUnsupported("UpdateLoginLockoutState")
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

// Retention purge runs server-side (ADR-032); not available in remote mode.
func (rs *RemoteStorage) PurgeDeletedUsersBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("PurgeDeletedUsersBefore")
}

func (rs *RemoteStorage) PurgeDeletedProjectsBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("PurgeDeletedProjectsBefore")
}

func (rs *RemoteStorage) PurgeDeletedEnvironmentsBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("PurgeDeletedEnvironmentsBefore")
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

func (rs *RemoteStorage) ListUsersInStateBefore(_ context.Context, _ string, _ time.Time) ([]*models.User, error) {
	return nil, remoteUnsupported("ListUsersInStateBefore")
}

func (rs *RemoteStorage) CreateUserWithRoleGrants(_ context.Context, _ *models.User, _ []storage.RoleGrant) (*models.User, error) {
	return nil, remoteUnsupported("CreateUserWithRoleGrants")
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
	return nil, remoteUnsupported("CreateGroup")
}

func (rs *RemoteStorage) GetGroup(_ context.Context, _ uint) (*models.Group, error) {
	return nil, remoteUnsupported("GetGroup")
}

func (rs *RemoteStorage) UpdateGroup(_ context.Context, _ *models.Group) (*models.Group, error) {
	return nil, remoteUnsupported("UpdateGroup")
}

func (rs *RemoteStorage) DeleteGroup(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteGroup")
}

func (rs *RemoteStorage) RestoreGroup(_ context.Context, _ uint) error {
	return remoteUnsupported("RestoreGroup")
}

func (rs *RemoteStorage) ListGroups(_ context.Context) ([]*models.Group, error) {
	return nil, remoteUnsupported("ListGroups")
}

func (rs *RemoteStorage) ListGroupsPage(_ context.Context, _, _ int) ([]*models.Group, int64, error) {
	return nil, 0, remoteUnsupported("ListGroupsPage")
}

func (rs *RemoteStorage) AddUserToGroup(_ context.Context, _, _ uint) error {
	return remoteUnsupported("AddUserToGroup")
}

func (rs *RemoteStorage) RemoveUserFromGroup(_ context.Context, _, _ uint) error {
	return remoteUnsupported("RemoveUserFromGroup")
}

func (rs *RemoteStorage) ListGroupMembers(_ context.Context, _ uint) ([]*models.User, error) {
	return nil, remoteUnsupported("ListGroupMembers")
}

// --- Password history (ADR-025) ---
// Password changes are processed server-side in remote mode, so history is
// recorded and checked there; these are stubs.

func (rs *RemoteStorage) AddPasswordHistory(_ context.Context, _ uint, _ string, _ time.Time) error {
	return nil
}

func (rs *RemoteStorage) RecentPasswordHashes(_ context.Context, _ uint, _ int) ([]string, error) {
	return nil, nil
}

func (rs *RemoteStorage) PrunePasswordHistory(_ context.Context, _ uint, _ int) error {
	return nil
}
