package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// CreateUserRequest represents a request to create a new user.
type CreateUserRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=50,alphanum"`
	Email       string `json:"email" validate:"required,email"`
	DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
	Password    string `json:"password" validate:"required,min=8"`
	IsActive    *bool  `json:"is_active,omitempty"`
}

// UpdateUserRequest represents a request to update an existing user.
type UpdateUserRequest struct {
	ID          uint
	Username    string
	Email       string
	DisplayName string
	IsActive    *bool
}

// CreateGroupRequest represents a request to create a new group.
type CreateGroupRequest struct {
	Name        string
	Description string
}

// UpdateGroupRequest represents a request to update an existing group.
type UpdateGroupRequest struct {
	ID          uint
	Name        string
	Description string
}

// ── Users ─────────────────────────────────────────────────────────────────────

// CreateUser creates a new user with business logic validation.
func (c *KeyorixCore) CreateUser(ctx context.Context, req *CreateUserRequest) (*models.User, error) {
	if err := c.validateCreateUserRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	if _, err := c.storage.GetUserByUsername(ctx, req.Username); err == nil {
		return nil, fmt.Errorf("%s: username already exists", i18n.T("ErrorValidation", nil))
	} else if err != nil && !strings.Contains(err.Error(), i18n.T("ErrorUserNotFound", nil)) {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	existing, err := c.storage.GetUserByEmail(ctx, req.Email)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("%s: user with email already exists", i18n.T("ErrorValidation", nil))
	}
	if err != nil && !strings.Contains(err.Error(), i18n.T("ErrorUserNotFound", nil)) {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	now := c.now()
	active := true
	if req.IsActive != nil {
		active = *req.IsActive
	}
	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		DisplayName:  displayName,
		PasswordHash: string(hash),
		IsActive:     active,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	createdUser, err := c.storage.CreateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return createdUser, nil
}

// GetUser retrieves a user by ID.
func (c *KeyorixCore) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if id == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	user, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return user, nil
}

// UpdateUser updates an existing user.
func (c *KeyorixCore) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*models.User, error) {
	if err := c.validateUpdateUserRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	user, err := c.storage.GetUser(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if req.Username != "" && req.Username != user.Username {
		if _, err := c.storage.GetUserByUsername(ctx, req.Username); err == nil {
			return nil, fmt.Errorf("%s: username already exists", i18n.T("ErrorValidation", nil))
		} else if err != nil && !strings.Contains(err.Error(), i18n.T("ErrorUserNotFound", nil)) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		user.Username = req.Username
	}
	if req.Email != "" && req.Email != user.Email {
		existing, err := c.storage.GetUserByEmail(ctx, req.Email)
		if err == nil && existing != nil && existing.ID != user.ID {
			return nil, fmt.Errorf("%s: user with email already exists", i18n.T("ErrorValidation", nil))
		}
		if err != nil && !strings.Contains(err.Error(), i18n.T("ErrorUserNotFound", nil)) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		user.Email = req.Email
	}
	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	user.UpdatedAt = c.now()
	updated, err := c.storage.UpdateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return updated, nil
}

// DeleteUser soft-deletes a user by ID.
// The row is retained in the database with deleted_at set; active sessions
// for this user will fail authentication on next request. Soft-deleted users
// can be restored within the purge retention window (default 30 days).
func (c *KeyorixCore) DeleteUser(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if _, err := c.storage.GetUser(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if err := c.storage.DeleteUser(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RestoreUser clears the deleted_at timestamp on a soft-deleted user,
// making them active in all queries again. Returns an error if the user
// does not exist or was not soft-deleted.
func (c *KeyorixCore) RestoreUser(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if err := c.storage.RestoreUser(ctx, id); err != nil {
		if strings.Contains(err.Error(), i18n.T("ErrorUserNotFound", nil)) {
			return fmt.Errorf("%s: user not found or not deleted", i18n.T("ErrorUserNotFound", nil))
		}
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// ListUsers lists users with filtering and pagination.
func (c *KeyorixCore) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	if filter == nil {
		filter = &storage.UserFilter{}
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.PageSize > 100 {
		filter.PageSize = 100
	}
	users, total, err := c.storage.ListUsers(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return users, total, nil
}

// GetUserByEmail retrieves a user by email address.
func (c *KeyorixCore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	if email == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "email is required")
	}
	user, err := c.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return user, nil
}

// ── Groups ────────────────────────────────────────────────────────────────────

// CreateGroup creates a new group.
func (c *KeyorixCore) CreateGroup(ctx context.Context, req *CreateGroupRequest) (*models.Group, error) {
	if err := c.validateCreateGroupRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	group := &models.Group{Name: req.Name, Description: req.Description}
	created, err := c.storage.CreateGroup(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return created, nil
}

// GetGroup retrieves a group by ID.
func (c *KeyorixCore) GetGroup(ctx context.Context, id uint) (*models.Group, error) {
	if id == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	group, err := c.storage.GetGroup(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return group, nil
}

// UpdateGroup updates an existing group.
func (c *KeyorixCore) UpdateGroup(ctx context.Context, req *UpdateGroupRequest) (*models.Group, error) {
	if err := c.validateUpdateGroupRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	group, err := c.storage.GetGroup(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if req.Name != "" {
		group.Name = req.Name
	}
	if req.Description != "" {
		group.Description = req.Description
	}
	updated, err := c.storage.UpdateGroup(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return updated, nil
}

// DeleteGroup deletes a group by ID.
func (c *KeyorixCore) DeleteGroup(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	if _, err := c.storage.GetGroup(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if err := c.storage.DeleteGroup(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// ListGroups lists all groups.
func (c *KeyorixCore) ListGroups(ctx context.Context) ([]*models.Group, error) {
	groups, err := c.storage.ListGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return groups, nil
}

// AddUserToGroup adds a user to a group.
func (c *KeyorixCore) AddUserToGroup(ctx context.Context, userID, groupID uint) error {
	if userID == 0 || groupID == 0 {
		return fmt.Errorf("%s: user ID and group ID are required", i18n.T("ErrorValidation", nil))
	}
	if err := c.storage.AddUserToGroup(ctx, userID, groupID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RemoveUserFromGroup removes a user from a group.
func (c *KeyorixCore) RemoveUserFromGroup(ctx context.Context, userID, groupID uint) error {
	if userID == 0 || groupID == 0 {
		return fmt.Errorf("%s: user ID and group ID are required", i18n.T("ErrorValidation", nil))
	}
	if err := c.storage.RemoveUserFromGroup(ctx, userID, groupID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// GetGroupMembers returns all users that belong to a group.
func (c *KeyorixCore) GetGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error) {
	if groupID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	members, err := c.storage.ListGroupMembers(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return members, nil
}

// ── Validation ────────────────────────────────────────────────────────────────

func (c *KeyorixCore) validateCreateUserRequest(req *CreateUserRequest) error {
	if req.Username == "" {
		return fmt.Errorf("%s", i18n.T("LabelUsername", nil))
	}
	if req.Email == "" {
		return fmt.Errorf("%s", i18n.T("LabelEmail", nil))
	}
	if req.Password == "" {
		return fmt.Errorf("%s", i18n.T("LabelPassword", nil))
	}
	return nil
}

func (c *KeyorixCore) validateUpdateUserRequest(req *UpdateUserRequest) error {
	if req.ID == 0 {
		return fmt.Errorf("user ID is required")
	}
	return nil
}

func (c *KeyorixCore) validateCreateGroupRequest(req *CreateGroupRequest) error {
	if req.Name == "" {
		return fmt.Errorf("group name is required")
	}
	return nil
}

func (c *KeyorixCore) validateUpdateGroupRequest(req *UpdateGroupRequest) error {
	if req.ID == 0 {
		return fmt.Errorf("group ID is required")
	}
	return nil
}
