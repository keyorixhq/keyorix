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
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// ListProjectMembers returns the users with a role at the project's scope.
func (c *KeyorixCore) ListProjectMembers(ctx context.Context, projectID uint) ([]storage.ProjectMember, error) {
	return c.storage.ListProjectMembers(ctx, projectID)
}

// AddProjectMember assigns roleName to userID at the project scope. actorID is the
// acting principal (0 = no authenticated principal, e.g. a system-driven onboarding
// transition); see AssignUserRole for actorID semantics — including the
// requireGranterHoldsRolePermissions escalation-by-proxy ceiling (#93/#107/#141)
// AssignUserRole applies to every grant, so a non-admin roles.assign holder cannot
// mint a project_admin (or any role bundling permissions they don't hold) through
// this direct entry point.
func (c *KeyorixCore) AddProjectMember(ctx context.Context, actorID, projectID, userID uint, roleName string) error {
	if err := c.domainAllowedForUser(ctx, userID); err != nil {
		return err
	}
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
	// Only re-run the domain check when this call is establishing NEW project
	// membership (the user holds no role at this scope yet) — an existing
	// member changing roles already passed the check when they joined.
	if len(existing) == 0 {
		if err := c.domainAllowedForUser(ctx, userID); err != nil {
			return err
		}
	}
	// Refuse a demotion that would leave the project with no roles.assign holder
	// (#236): after this call the user's only project-scope role is roleName, so
	// check whether THAT role still carries roles.assign before touching anything.
	// #G03: the guard's read and the role changes below are serialized under
	// projectAdminGuardMu, held for the whole check-then-act sequence — see its
	// doc comment in service.go for the race this closes.
	c.projectAdminGuardMu.Lock()
	defer c.projectAdminGuardMu.Unlock()
	if err := c.guardLastProjectAdmin(ctx, projectID, userID, existing, []uint{role.ID}); err != nil {
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

// RemoveProjectMember removes ALL of the user's role grants scoped to the
// project — not just the project-level (environment_id = 0) grant the Members
// UI shows, but any environment-scoped grant (e.g. "prod-only access") in the
// same project too. A prior version only deleted the exact-scope match, so an
// environment-scoped grant silently survived an offboarding admin's removal,
// invisible and uncorrectable by that admin (project-scoped roles.assign
// cannot see or edit /user-roles grants, which require global scope) (#232).
// See AddProjectMember for actorID semantics.
func (c *KeyorixCore) RemoveProjectMember(ctx context.Context, actorID, projectID, userID uint) error {
	scope := Scope{ProjectID: projectID}
	existing, err := c.storage.GetUserRoleIDsExact(ctx, userID, scope)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return fmt.Errorf("user is not a member of this project")
	}
	// Refuse to remove the project's last roles.assign holder (#236): the ordinary
	// member-management API has no other safeguard, so without this the sole
	// remaining project admin could remove themselves (or be removed by anyone
	// else holding roles.assign), leaving the project with zero project-scoped
	// admins. Not a permanent lockout — a GLOBAL admin can always re-add one via
	// GetUserRoleIDsAt's project_id = 0 OR project_id = ? matching — but still an
	// availability risk worth refusing outright rather than requiring recovery.
	// #G03: see SetProjectMemberRole's identical projectAdminGuardMu comment above.
	c.projectAdminGuardMu.Lock()
	defer c.projectAdminGuardMu.Unlock()
	if err := c.guardLastProjectAdmin(ctx, projectID, userID, existing, nil); err != nil {
		return err
	}
	// Capture every grant (any environment) this deletes so each can be recorded
	// in the RBAC audit trail (#234) — RemoveAllProjectRoleGrants is a single
	// bulk delete, not a per-role RemoveUserRole loop, so it doesn't audit itself.
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to list project role assignments: %w", err)
	}
	if err := c.storage.RemoveAllProjectRoleGrants(ctx, userID, projectID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// Clear owner_id on secrets this user owned in the project (RBAC-002): without
	// this the stale owner tag would grant them owner-level access via
	// CheckSecretPermission's owner short-circuit even after all role grants are gone.
	// Best-effort: a failure here is logged at the storage layer but does not roll back
	// the role removal, because the RBAC-001 membership check in CheckSecretPermission
	// already blocks access — this is defense-in-depth, not a hard gate.
	_ = c.storage.ClearProjectSecretOwnership(ctx, userID, projectID)
	// Revoke per-secret ACL grants in this project (CWE-284): without this a removed
	// member retains access to any secret they held a SecretACL grant for, because
	// AuthorizeSecret checks ACL grants before project-scope RBAC and short-circuits
	// on the first match — the role removal above provides no protection against stale ACLs.
	_ = c.storage.DeleteSecretACLsByUserAndProject(ctx, userID, projectID)
	for _, a := range assignments {
		if a.PrincipalType != "user" || a.PrincipalID != userID {
			continue
		}
		c.LogRoleRemoved(ctx, actorID, userID, a.RoleID, Scope{ProjectID: projectID, EnvironmentID: a.EnvironmentID})
	}
	return nil
}

// guardLastProjectAdmin refuses an operation that would strip targetID's
// roles.assign authority at projectID's PROJECT scope (environment_id = 0 — a
// member removal or role change) unless either (a) targetRoleIDsAfter still
// carries roles.assign, or (b) some OTHER project-level grant (user or group)
// already carries it, so governance of the project survives. Only environment_id
// = 0 grants count: RequireScopedPermission on /projects/{id}/members itself
// only matches project-level grants (GetUserRoleIDsAt's "environment_id = 0 OR
// environment_id = ?" against a target scope whose EnvironmentID is 0), so an
// environment-scoped roles.assign grant could not actually administer this
// project's membership either — it doesn't count as a survivor. Passing a
// nil/roles.assign-free targetRoleIDsBefore is a fast no-op (the target wasn't
// an admin to begin with).
func (c *KeyorixCore) guardLastProjectAdmin(ctx context.Context, projectID, targetID uint, targetRoleIDsBefore, targetRoleIDsAfter []uint) error { // NOSONAR -- cognitive complexity 18, suppress go:S3776
	hadAssign, err := c.storage.RoleSetHasPermission(ctx, targetRoleIDsBefore, permRolesAssign)
	if err != nil {
		return err
	}
	if !hadAssign {
		return nil // target wasn't a project admin — not the last-admin case
	}
	willHaveAssign, err := c.storage.RoleSetHasPermission(ctx, targetRoleIDsAfter, permRolesAssign)
	if err != nil {
		return err
	}
	if willHaveAssign {
		return nil // still an admin afterward — no governance gap
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to check project administrators: %w", err)
	}
	checked := make(map[uint]bool, len(assignments))
	for _, a := range assignments {
		if a.EnvironmentID != 0 {
			continue // not project-level; can't administer /projects/{id}/members
		}
		// A grant belonging to the target themselves doesn't count as "another"
		// admin — only groups and other users can pick up the slack.
		if a.PrincipalType == "user" && a.PrincipalID == targetID {
			continue
		}
		hasAssign, ok := checked[a.RoleID]
		if !ok {
			hasAssign, err = c.storage.RoleSetHasPermission(ctx, []uint{a.RoleID}, permRolesAssign)
			if err != nil {
				return err
			}
			checked[a.RoleID] = hasAssign
		}
		if hasAssign {
			return nil // another admin (user or group) survives the change
		}
	}
	return fmt.Errorf("cannot remove or demote the project's last administrator; assign another project admin first")
}
