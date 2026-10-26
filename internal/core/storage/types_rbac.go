package storage

import (
	"time"

	"github.com/keyorixhq/keyorix/internal/core/rules"
)

// PrincipalPermission is ResolveUserPermissionAt's / ResolveMachinePermissionAt's
// result. RoleIDs is the de-duplicated role set that applies at the scope (the
// set core's scopedRoleIDs / GetMachineRoleIDsAt returned; order unspecified).
// BypassesPermissionChecks reports whether any of them carries the ADR-084
// flag (users only). HasPermission is RoleSetHasPermission(RoleIDs, permission),
// resolved only when RoleIDs is non-empty and does not bypass.
type PrincipalPermission struct {
	RoleIDs                  []uint
	BypassesPermissionChecks bool
	HasPermission            bool
}

// Scope is rules.Scope (internal/core/rules/scope.go): the project/environment
// a role assignment or an authorization check applies to, 0 = global.
type Scope = rules.Scope

// RoleGrant is a single role-to-scope grant applied atomically alongside a user
// creation (ADR-028 atomic provisioning).
type RoleGrant struct {
	RoleID uint
	Scope  Scope
}

// Permission represents a fine-grained permission
type Permission struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// RoleDeleteCascadeCounts reports how many live principal-assignment rows
// DeleteRole's cascade removed (SESSION-AT AT1 row 2, PR #2357 review) — the
// user/group/machine-identity grants that pointed at the deleted role.
// Deliberately excludes RolePermission/ConnectRefGrant: those are the role's
// OWN composition (its permission bundle, its connector grants), not another
// principal's assignment, so their removal isn't audit-worthy in the same
// way — it's an expected consequence of deleting the role's own definition,
// not something a user/group/machine "lost."
type RoleDeleteCascadeCounts struct {
	UserAssignments    int
	GroupAssignments   int
	MachineAssignments int
}

// RoleAssignment is one principal↔role grant at a scope — the raw rows behind an
// access review (ISO 27001 A.5.18). Unlike ProjectMember it does NOT collapse a
// principal to a single role: a user/group with several roles at a scope yields
// several RoleAssignments. PrincipalType is "user" or "group".
type RoleAssignment struct {
	PrincipalType string `json:"principal_type"`
	PrincipalID   uint   `json:"principal_id"`
	RoleID        uint   `json:"role_id"`
	ProjectID     uint   `json:"project_id"`
	EnvironmentID uint   `json:"environment_id"`
}

// GroupRoleGrant is a role assigned to a group together with the grant's optional
// time-bound expiry (nil = permanent). Mirrors a models.Role plus expires_at so the
// group-roles API can show remaining time on a just-in-time grant.
type GroupRoleGrant struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}
