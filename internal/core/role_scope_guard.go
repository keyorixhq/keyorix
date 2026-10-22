// role_scope_guard.go — GROUP-ROLE-SCOPE-1 (#3546): a role grant's scope must be
// one the role is meaningful at.
//
// ADR-021 splits the built-in roles into two tiers by WHERE they are assigned:
// system_* at the global scope (project 0), project_* at a project scope. The
// split had no enforcement: a grant of project_developer with no project_id
// landed at {0, 0}, and storage's authorization queries treat a global grant as
// applying in EVERY project — so "give alice project_developer" from a form that
// forgot the project silently made alice a developer of every project
// (DEMO-WALK-4). requireGranterHoldsRolePermissions cannot catch it: it bounds
// the GRANTER's authority, and an install admin passes it for any role.
//
// This file is that missing check. It runs in internal/core, not in a
// transport, so every grant path is covered — see
// TestEveryRoleGrantWriteChecksRoleScope (role_scope_guard_registry_test.go)
// for the AST-derived proof that every storage grant write in this package is
// either guarded or exempt for a stated reason.
//
// Phase 2: where a role may be granted is the role's own AssignableScope
// (models.Role, role_assignable_scope.go), not its name. Built-in roles carry
// their ADR-021 tier (system_* global, project_* project); a new custom role is
// project unless an admin widens it; custom roles that existed before were
// backfilled to any.
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrRoleScopeInvalid is the sentinel every role-scope refusal wraps
// (errors.Is). Transports map it to HTTP 400 / gRPC InvalidArgument.
var ErrRoleScopeInvalid = errors.New("invalid scope for role")

// RoleScopeError is a role-scope refusal. ClientMessage is a fixed,
// application-generated sentence (the role name and the fix) that is safe to
// send to a client verbatim. Role names are validated at create time (charset
// and length), so a name in the message cannot carry markup or control bytes.
type RoleScopeError struct {
	ClientMessage string
}

func (e *RoleScopeError) Error() string { return ErrRoleScopeInvalid.Error() + ": " + e.ClientMessage }

// Is makes errors.Is(err, ErrRoleScopeInvalid) true for a *RoleScopeError.
func (e *RoleScopeError) Is(target error) bool { return target == ErrRoleScopeInvalid }

// RoleScopeClientMessage returns the client-safe message of a role-scope
// refusal anywhere in err's chain, and false when err is not one.
func RoleScopeClientMessage(err error) (string, bool) {
	if rse, ok := errors.AsType[*RoleScopeError](err); ok {
		return rse.ClientMessage, true
	}
	return "", false
}

// roleAssignableScope is the scope the check enforces for role. A stored role
// always has one (the column is NOT NULL with a default); an empty value can
// only come from a hand-built models.Role, and resolves like an unset one on
// create (models.DefaultRoleAssignableScope): the built-in's fixed scope or,
// for anything else, project. Fail closed, never any.
func roleAssignableScope(role *models.Role) string { return models.EffectiveRoleAssignableScope(role) }

// RoleAssignableAtGlobalScope reports whether role may be granted with no
// project (project 0).
func RoleAssignableAtGlobalScope(role *models.Role) bool {
	return roleAssignableScope(role) != models.RoleAssignableProject
}

// validateRoleScope is the pure part of the check: an environment scope needs
// its project, a project-assignable role needs a project, and a
// global-assignable role must not have one.
func validateRoleScope(role *models.Role, scope Scope) error {
	if scope.ProjectID == 0 && scope.EnvironmentID != 0 {
		return &RoleScopeError{ClientMessage: "environment_id requires project_id: specify the project the environment belongs to"}
	}
	switch roleAssignableScope(role) {
	case models.RoleAssignableProject:
		if scope.ProjectID == 0 {
			return &RoleScopeError{ClientMessage: fmt.Sprintf(
				"role %s is project-scoped; specify a project_id (and optionally environment_id)", role.Name)}
		}
	case models.RoleAssignableGlobal:
		if scope.ProjectID != 0 {
			return &RoleScopeError{ClientMessage: fmt.Sprintf(
				"role %s is install-wide; grant it without project_id and environment_id", role.Name)}
		}
	}
	return nil
}

// seedBuiltinRoleAssignableScope sets a built-in role's fixed assignable scope
// (models.BuiltinRoleAssignableScopes) when it differs. Role seeding only
// (BootstrapSystem, seedAlertOperatorRole), in the seeding transaction: a role
// it does not know is left alone.
func seedBuiltinRoleAssignableScope(ctx context.Context, tx storage.Storage, role *models.Role) error {
	want, ok := models.BuiltinRoleAssignableScopes[role.Name]
	if !ok || role.AssignableScope == want {
		return nil
	}
	if err := tx.SetRoleAssignableScope(ctx, role.ID, want); err != nil {
		return fmt.Errorf("failed to seed the assignable scope of role %s: %w", role.Name, err)
	}
	role.AssignableScope = want
	return nil
}

// roleScopeRestoreKey marks a ctx that re-grants ONE exact (role, scope) row the
// same call removed moments before (SetUserRoles' compensating revert). The key
// type is unexported, so no transport can set it.
type roleScopeRestoreKey struct{}

type roleScopeRestore struct {
	roleID uint
	scope  Scope
}

// withRoleScopeRestore returns ctx marked as restoring roleID at scope. The
// scope check is skipped for exactly that (role, scope) and nothing else: a
// legacy grant the check would refuse today (a project role held globally
// before #3546) must come back when a partial SetUserRoles is undone, or the
// revert itself silently drops it (#3554 review follow-up 3).
func withRoleScopeRestore(ctx context.Context, roleID uint, scope Scope) context.Context {
	return context.WithValue(ctx, roleScopeRestoreKey{}, roleScopeRestore{roleID: roleID, scope: scope})
}

func isRoleScopeRestore(ctx context.Context, roleID uint, scope Scope) bool {
	r, ok := ctx.Value(roleScopeRestoreKey{}).(roleScopeRestore)
	return ok && r.roleID == roleID && r.scope == scope
}

// requireScopeValidForRole refuses a grant of roleID at scope when the scope is
// not valid for the role: an environment without its project, an environment
// of a different project, a project-assignable role at the global scope, or a
// global-assignable role at a project. Read-only; call it before any write.
func (c *KeyorixCore) requireScopeValidForRole(ctx context.Context, roleID uint, scope Scope) error {
	if isRoleScopeRestore(ctx, roleID, scope) {
		return nil
	}
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to resolve role %d for its scope check: %w", roleID, err)
	}
	return c.requireScopeValidForRoleModel(ctx, role, scope)
}

// requireScopeValidForRoleModel is requireScopeValidForRole for a caller that
// already resolved the role from storage.
func (c *KeyorixCore) requireScopeValidForRoleModel(ctx context.Context, role *models.Role, scope Scope) error {
	if err := validateRoleScope(role, scope); err != nil {
		return err
	}
	if scope.EnvironmentID == 0 {
		return nil
	}
	env, err := c.storage.GetEnvironment(ctx, scope.EnvironmentID)
	if err != nil {
		if !isEnvironmentNotFoundErr(err) {
			// Unknown, not refused: a failing read must not turn into a 400.
			return fmt.Errorf("failed to verify environment %d for the role scope check: %w", scope.EnvironmentID, err)
		}
		return &RoleScopeError{ClientMessage: "environment_id does not name an existing environment"}
	}
	if env.ProjectID != scope.ProjectID {
		return &RoleScopeError{ClientMessage: "environment_id must name an environment of project_id"}
	}
	return nil
}
