// project_members.go — project-scoped membership (ADR-021 two-tier model).
//
// A "project member" is a user holding a role at the project's scope
// (project_id = P, environment_id = 0). These helpers sit on top of the generic
// scoped role assignment (AssignRole/RemoveRole) to give the Members tab a
// membership-shaped API.
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

// AddProjectMember assigns roleName to userID at the project scope.
func (c *KeyorixCore) AddProjectMember(ctx context.Context, projectID, userID uint, roleName string) error {
	role, err := c.storage.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("unknown role %q: %w", roleName, err)
	}
	return c.storage.AssignRole(ctx, userID, role.ID, storage.Scope{ProjectID: projectID})
}

// SetProjectMemberRole replaces the user's role(s) at the project scope with
// roleName, adding the member if they had none.
func (c *KeyorixCore) SetProjectMemberRole(ctx context.Context, projectID, userID uint, roleName string) error {
	role, err := c.storage.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("unknown role %q: %w", roleName, err)
	}
	scope := storage.Scope{ProjectID: projectID}
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
		if err := c.storage.RemoveRole(ctx, userID, rid, scope); err != nil {
			return err
		}
	}
	if hasTarget {
		return nil
	}
	return c.storage.AssignRole(ctx, userID, role.ID, scope)
}

// RemoveProjectMember removes all of the user's roles at the project scope.
func (c *KeyorixCore) RemoveProjectMember(ctx context.Context, projectID, userID uint) error {
	scope := storage.Scope{ProjectID: projectID}
	existing, err := c.storage.GetUserRoleIDsExact(ctx, userID, scope)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return fmt.Errorf("user is not a member of this project")
	}
	for _, rid := range existing {
		if err := c.storage.RemoveRole(ctx, userID, rid, scope); err != nil {
			return err
		}
	}
	return nil
}
