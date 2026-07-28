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
	EventGroupCreated  = "group.created"
	EventGroupUpdated  = "group.updated"
	EventGroupDeleted  = "group.deleted"
	EventGroupRestored = "group.restored"
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

// DeleteGroup deletes a group by ID. See CreateGroup for actorID semantics. It
// refuses to delete a group holding the install's last global-admin-conferring
// role grant (#107; see guardLastGlobalAdminGroupDelete) — deleting a group
// cascades to remove every role grant it holds.
func (c *KeyorixCore) DeleteGroup(ctx context.Context, actorID, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	group, err := c.storage.GetGroup(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if err := c.guardLastGlobalAdminGroupDelete(ctx, id); err != nil {
		return err
	}
	if err := c.storage.DeleteGroup(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventGroupDeleted, actorPtr(actorID), nil,
		fmt.Sprintf("group %q (id %d) deleted", group.Name, id))
	return nil
}

// RestoreGroup reverses a soft-delete, bringing the group back with the role grants
// and memberships it had at deletion. See CreateGroup for actorID semantics.
//
// #147: restoring reinstates EVERY role the group held atomically — potentially
// several at once, including admin-tier ones — so before restoring, this checks the
// group's whole role SET against the actor's own authority (requireGlobalAdmin
// ToReinstateAdminRoles), the same ceiling roles.assign/requireAuthorityForRole is
// meant to enforce on a direct grant. Without it, a principal holding only
// roles.assign (the router's permission gate) who is themselves a member of an
// admin-conferring group that was soft-deleted (e.g. an incident-response
// revocation) could restore it and get their admin access back.
func (c *KeyorixCore) RestoreGroup(ctx context.Context, actorID, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	roles, err := c.storage.GetGroupRoles(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	roleIDs := make([]uint, 0, len(roles))
	for _, r := range roles {
		roleIDs = append(roleIDs, r.ID)
	}
	if err := c.requireGlobalAdminToReinstateAdminRoles(ctx, actorID, roleIDs, "group"); err != nil {
		return err
	}
	if err := c.storage.RestoreGroup(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventGroupRestored, actorPtr(actorID), nil, fmt.Sprintf("group %d restored", id))
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

// AddUserToGroup adds a user to a group. actorID is the admin performing it (0 = no
// authenticated principal, e.g. a local CLI invocation). projectID scopes the
// membership: 0 = global (applies in every project), non-zero = this project only.
// Membership confers every role the group holds at the matching scope, so this is
// recorded in the RBAC audit trail (#233).
//
// Joining an admin-conferring group inherits that access just as directly as a
// role grant, so every global-scope admin role the group already holds is gated
// by the same escalation-by-proxy ceiling AssignRoleToGroup applies
// (requireAuthorityForRole): a non-admin roles.assign holder must not be able to
// self-escalate by joining a privileged group instead of being granted the role.
// The local CLI (actorID 0) is exempt — it is already fully trusted (it can grant
// any role directly via AssignRoleToUser, which bypasses this ceiling entirely) and
// the exemption avoids forcing an existing admin group deployment through this new
// check retroactively.
func (c *KeyorixCore) AddUserToGroup(ctx context.Context, actorID, userID, groupID, projectID uint) error {
	if userID == 0 || groupID == 0 {
		return fmt.Errorf("%s: user ID and group ID are required", i18n.T("ErrorValidation", nil))
	}
	if actorID != 0 {
		grants, err := c.storage.ListGroupRoleAssignments(ctx, groupID)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		for _, g := range grants {
			role, err := c.storage.GetRole(ctx, g.RoleID)
			if err != nil {
				continue
			}
			if err := c.requireAuthorityForRole(ctx, actorID, g.ProjectID, role.Name); err != nil {
				return err
			}
			// AUTHZ-007: joining a group confers its roles just as directly as a role grant,
			// so the same SoD preventive gate that guards AssignUserRole must run here too.
			if err := c.requireNoSoDViolation(ctx, userID, g.RoleID); err != nil {
				return err
			}
		}
	}
	if err := c.storage.AddUserToGroup(ctx, userID, groupID, projectID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogGroupMemberAdded(ctx, actorID, userID, groupID)
	return nil
}

// AddUserToGroupGlobal is a convenience wrapper that adds a global membership
// (projectID=0). Callers that do not need project-scoped membership (e.g. SSO
// JIT provisioning, SCIM) should call this rather than hard-coding 0.
func (c *KeyorixCore) AddUserToGroupGlobal(ctx context.Context, actorID, userID, groupID uint) error {
	return c.AddUserToGroup(ctx, actorID, userID, groupID, 0)
}

// RemoveUserFromGroup removes a user from a group at the given projectID scope.
// See AddUserToGroup for actorID semantics. It refuses to remove a user whose
// global admin-tier authority comes solely from this group's role grant when no
// other admin route remains (#107; see guardLastGlobalAdminMembership).
func (c *KeyorixCore) RemoveUserFromGroup(ctx context.Context, actorID, userID, groupID, projectID uint) error {
	if userID == 0 || groupID == 0 {
		return fmt.Errorf("%s: user ID and group ID are required", i18n.T("ErrorValidation", nil))
	}
	if err := c.guardLastGlobalAdminMembership(ctx, userID, groupID); err != nil {
		return err
	}
	if err := c.storage.RemoveUserFromGroup(ctx, userID, groupID, projectID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogGroupMemberRemoved(ctx, actorID, userID, groupID)
	return nil
}

// RemoveUserFromGroupGlobal is a convenience wrapper that removes the global
// membership (projectID=0). Callers that do not need project-scoped removal (e.g.
// SSO JIT de-provisioning, SCIM) should call this rather than hard-coding 0.
func (c *KeyorixCore) RemoveUserFromGroupGlobal(ctx context.Context, actorID, userID, groupID uint) error {
	return c.RemoveUserFromGroup(ctx, actorID, userID, groupID, 0)
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
	if err := validateNameLength("group name", req.Name); err != nil {
		return err
	}
	return validateDescription(req.Description)
}

func (c *KeyorixCore) validateUpdateGroupRequest(req *UpdateGroupRequest) error {
	if req.ID == 0 {
		return fmt.Errorf("group ID is required")
	}
	if err := validateNameLength("group name", req.Name); err != nil {
		return err
	}
	return validateDescription(req.Description)
}
