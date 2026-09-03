package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AssignRoleToUser assigns a role to a user by email and role name (global scope).
func (c *KeyorixCore) AssignRoleToUser(ctx context.Context, userEmail, roleName string) error {
	return c.AssignUserRoleScoped(ctx, userEmail, roleName, Scope{})
}

// AssignUserRoleScoped assigns a role to a user at an explicit scope (project/environment).
// Pass Scope{} for a global grant. actorID 0 = local CLI/system (no authenticated session).
func (c *KeyorixCore) AssignUserRoleScoped(ctx context.Context, userEmail, roleName string, scope Scope) error {
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	role, err := c.storage.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if err := c.AssignUserRole(ctx, 0, user.ID, role.ID, scope, false); err != nil {
		return err
	}
	return nil
}

// RemoveRoleFromUser removes a role from a user by email and role name (global scope).
func (c *KeyorixCore) RemoveRoleFromUser(ctx context.Context, userEmail, roleName string) error {
	return c.RemoveUserRoleScoped(ctx, userEmail, roleName, Scope{})
}

// RemoveUserRoleScoped removes a role from a user at an explicit scope (project/environment).
// Pass Scope{} for a global grant. actorID 0 = local CLI/system (no authenticated session).
func (c *KeyorixCore) RemoveUserRoleScoped(ctx context.Context, userEmail, roleName string, scope Scope) error {
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	role, err := c.storage.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if err := c.RemoveUserRole(ctx, 0, user.ID, role.ID, scope); err != nil {
		return err
	}
	return nil
}

// ListUserRolesByEmail lists roles for a user by email.
func (c *KeyorixCore) ListUserRolesByEmail(ctx context.Context, userEmail string) ([]*models.Role, error) {
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	roles, err := c.storage.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// HasPermissionByEmail checks if a user has a specific permission by email, at
// ANY scope the user holds a role — the CLI diagnostic used for offboarding and
// incident-response access checks (#376). It deliberately delegates to Authorize
// (mirroring scopedRoleIDs in authz.go) at every scope the user has a grant,
// rather than running its own parallel query, so it stays in lockstep with the
// live authorization path on all three axes that previously drifted: it honors
// group-inherited roles, it evaluates the permission per-scope (not a flat,
// scope-blind "any assignment anywhere" match), and it honors the admin-role
// bypass Authorize() applies. A role-less user (no grant at any scope) is still
// checked once at the global scope, matching Authorize's own "no roles, no
// permission" resolution.
func (c *KeyorixCore) HasPermissionByEmail(ctx context.Context, userEmail, resource, action string) (bool, error) {
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	permission := resource + "." + action
	scopes, err := c.storage.GetUserRoleScopes(ctx, user.ID)
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	if len(scopes) == 0 {
		scopes = []Scope{{}}
	}
	for _, scope := range scopes {
		ok, aerr := c.Authorize(ctx, user.ID, permission, scope)
		if aerr != nil {
			return false, fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), aerr)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// ListUserPermissionsByEmail lists a user's effective permission set (direct AND
// group-derived) for the CLI's `rbac list-permissions` — the same secondary
// symptom of the #219/#374 root cause called out for the HTTP dashboard endpoint
// (#375): union both sources rather than reporting direct roles only.
func (c *KeyorixCore) ListUserPermissionsByEmail(ctx context.Context, userEmail string) ([]*storage.Permission, error) {
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return c.GetUserPermissionsByID(ctx, user.ID)
}
