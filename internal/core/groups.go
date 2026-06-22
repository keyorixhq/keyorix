// groups.go — Group CRUD, membership, and validation.
//
// CreateGroup, GetGroup, UpdateGroup, DeleteGroup, ListGroups,
// AddUserToGroup, RemoveUserFromGroup, GetGroupMembers.
// For user operations see users.go. Types are in users_types.go.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Group lifecycle audit event types (API/CLI-driven; the SCIM provisioning path
// has its own scim.group_* events). Surfaced in the audit log like other mutations.
const (
	EventGroupCreated = "group.created"
	EventGroupUpdated = "group.updated"
	EventGroupDeleted = "group.deleted"
)

// CreateGroup creates a new group. actorID is the admin performing it (0 = no
// authenticated principal, e.g. a local CLI invocation).
func (c *KeyorixCore) CreateGroup(ctx context.Context, actorID uint, req *CreateGroupRequest) (*models.Group, error) {
	if err := c.validateCreateGroupRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	group := &models.Group{Name: req.Name, Description: req.Description}
	created, err := c.storage.CreateGroup(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventGroupCreated, actorPtr(actorID), nil,
		fmt.Sprintf("group %q (id %d) created", created.Name, created.ID))
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

// UpdateGroup updates an existing group. See CreateGroup for actorID semantics.
func (c *KeyorixCore) UpdateGroup(ctx context.Context, actorID uint, req *UpdateGroupRequest) (*models.Group, error) {
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
	c.writeAuditEvent(ctx, EventGroupUpdated, actorPtr(actorID), nil,
		fmt.Sprintf("group %q (id %d) updated", updated.Name, updated.ID))
	return updated, nil
}

// DeleteGroup deletes a group by ID. See CreateGroup for actorID semantics.
func (c *KeyorixCore) DeleteGroup(ctx context.Context, actorID, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	group, err := c.storage.GetGroup(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if err := c.storage.DeleteGroup(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventGroupDeleted, actorPtr(actorID), nil,
		fmt.Sprintf("group %q (id %d) deleted", group.Name, id))
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

func (c *KeyorixCore) validateCreateGroupRequest(req *CreateGroupRequest) error {
	if req.Name == "" {
		return fmt.Errorf("group name is required")
	}
	return validateDescription(req.Description)
}

func (c *KeyorixCore) validateUpdateGroupRequest(req *UpdateGroupRequest) error {
	if req.ID == 0 {
		return fmt.Errorf("group ID is required")
	}
	return validateDescription(req.Description)
}
