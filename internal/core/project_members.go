// project_members.go — project-scoped membership (ADR-021 two-tier model).
//
// A "project member" is a user holding a role at the project's scope
// (project_id = P, environment_id = 0). These helpers sit on top of the audited
// RBAC choke point (AssignUserRole/RemoveUserRole, see rbac_management.go) to give
// the Members tab a membership-shaped API — the same underlying grant as
// /user-roles, so it must be audited identically (#234).
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// ListProjectMembers returns the users with a role at the project's scope.
func (c *KeyorixCore) ListProjectMembers(ctx context.Context, projectID uint) ([]storage.ProjectMember, error) {
	return c.storage.ListProjectMembers(ctx, projectID)
}

// AddProjectMember assigns roleName to userID at the project scope. actorID is the
// acting principal (0 = no authenticated principal, e.g. a system-driven onboarding
// transition); see AssignUserRole for actorID semantics.
func (c *KeyorixCore) AddProjectMember(ctx context.Context, actorID, projectID, userID uint, roleName string) error {
	role, err := c.storage.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("unknown role %q: %w", roleName, err)
	}
	return c.AssignUserRole(ctx, actorID, userID, role.ID, Scope{ProjectID: projectID})
}

// SetProjectMemberRole replaces the user's role(s) at the project scope with
// roleName, adding the member if they had none. See AddProjectMember for actorID
// semantics.
func (c *KeyorixCore) SetProjectMemberRole(ctx context.Context, actorID, projectID, userID uint, roleName string) error {
	role, err := c.storage.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("unknown role %q: %w", roleName, err)
	}
	scope := Scope{ProjectID: projectID}
	existing, err := c.storage.GetUserRoleIDsExact(ctx, userID, scope)
	if err != nil {
		return err
	}
	hasTarget := false
	for _, rid := range existing {
		if rid == role.ID {
			hasTarget = true
			continue
		}
		if err := c.RemoveUserRole(ctx, actorID, userID, rid, scope); err != nil {
			return err
		}
	}
	if hasTarget {
		return nil
	}
	return c.AssignUserRole(ctx, actorID, userID, role.ID, scope)
}

// RemoveProjectMember removes all of the user's roles at the project scope. See
// AddProjectMember for actorID semantics.
func (c *KeyorixCore) RemoveProjectMember(ctx context.Context, actorID, projectID, userID uint) error {
	scope := Scope{ProjectID: projectID}
	existing, err := c.storage.GetUserRoleIDsExact(ctx, userID, scope)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return fmt.Errorf("user is not a member of this project")
	}
	for _, rid := range existing {
		if err := c.RemoveUserRole(ctx, actorID, userID, rid, scope); err != nil {
			return err
		}
	}
	return nil
}
