package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RBACStore is the Storage slice for roles, permissions, role grants and permission resolution.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type RBACStore interface {
	// ListProjectRoleAssignments returns every direct (user) and group role grant
	// scoped to the project (project_id = projectID, any environment) — the raw
	// rows for a project access review. Global (project 0) grants are excluded:
	// those are install-level, reviewed separately. projectID 0 is the global
	// listing behind every core-side global-admin holder count: it returns only
	// grants at exactly {0, 0}, agreeing with ListGlobalAdminAssignmentsForUpdate
	// (#2857; a {0, X} grant does not apply at global scope).
	ListProjectRoleAssignments(ctx context.Context, projectID uint) ([]RoleAssignment, error)
	// ListProjectMachineRoleAssignments returns every machine-identity role grant
	// scoped to the project (project_id = projectID, any environment) — the machine
	// counterpart to ListProjectRoleAssignments's user/group rows, kept separate so
	// existing callers (compliance posture, RBAC/SCIM last-admin guards) are
	// unaffected; only the access review enumerates it (#91).
	ListProjectMachineRoleAssignments(ctx context.Context, projectID uint) ([]RoleAssignment, error)
	// ListGlobalAdminAssignmentsForUpdate returns every global-scope (project 0,
	// environment 0) direct user and group role grant whose role is in
	// adminRoleIDs, taking a row-level write lock on backends that support one
	// (Postgres: SELECT ... FOR UPDATE) so a concurrent racing removal serializes
	// against this read. This is the atomicity fix for #340: guardLastGlobalAdmin's
	// prior read-then-conditional-write let two admins racing to remove each
	// other's role assignment both observe "another admin still exists" before
	// either write landed, stranding the install. On SQLite this is a plain read;
	// the caller's own process-level mutex serializes same-process callers,
	// mirroring LockUserForUpdate/LockWebAuthnCredentialForUpdate.
	ListGlobalAdminAssignmentsForUpdate(ctx context.Context, adminRoleIDs []uint) ([]RoleAssignment, error)
	// RemoveGlobalAdminRoleGuarded atomically checks-then-removes a user's
	// global-scope (project 0, environment 0) role grant, refusing (without
	// removing anything) if doing so would leave the install with zero
	// admin-tier holders among adminRoleIDs — the exact guardLastGlobalAdmin
	// (#340) check and its RemoveRole write, folded into ONE storage call.
	//
	// Added for #525: RemoveUserRole previously ran this check (via
	// ListGlobalAdminAssignmentsForUpdate) and the removal (via RemoveRole) as TWO
	// separate calls inside a WithTransaction closure. That is correct against
	// LocalStorage (a real DB transaction + Postgres row lock spans both), but the
	// now-deleted RemoteStorage's WithTransaction was a no-op passthrough — two
	// separate HTTP round trips would have given a concurrent racing removal a
	// window to observe "another admin still exists" before either write landed,
	// reopening the exact cross-process last-admin lockout race #340 closed for HA
	// Postgres replicas. Folding the check and the write into one call means
	// whichever server actually owns the row is the only one that ever needs to
	// enforce it atomically, exactly like CreateSecretDependencyExclusive (#260) and
	// TransitionMachineIdentityState (#388/#518) did for their own TOCTOU classes.
	//
	// Returns ErrWouldStrandLastAdmin if the removal is refused, or
	// ErrRoleNotAssigned (wrapped) if the (userID, roleID) grant does not exist at
	// the global scope.
	RemoveGlobalAdminRoleGuarded(ctx context.Context, userID, roleID uint, adminRoleIDs []uint) error

	// Permission Management
	CreatePermission(ctx context.Context, permission *models.Permission) (*models.Permission, error)
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uint) error

	// Role Management
	//
	// CreateRole takes a typed identity.FoldedName, not a raw string or a
	// pre-built *models.Role, deliberately (#1642): both server/http and
	// server/grpc's role-creation handlers call this directly, bypassing
	// internal/core entirely (no length cap, no charset check, no
	// normalization of any kind existed before this). Patching each of those
	// two known call sites to construct a FoldedName themselves would still
	// let a third, future caller bypass it again by passing a raw string —
	// putting the typed parameter in the signature makes every caller,
	// present and future, go through identity.NewFoldedName's validation
	// (which also rejects control characters and bidi-override characters as
	// part of the PRECIS profile) or fail to compile.
	CreateRole(ctx context.Context, name identity.FoldedName, description string) (*models.Role, error)
	GetRole(ctx context.Context, id uint) (*models.Role, error)
	GetRoleByName(ctx context.Context, name string) (*models.Role, error)
	UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error)
	// DeleteRole hard-deletes a role and cascades the delete to every
	// UserRole/GroupRole/MachineIdentityRole/RolePermission/ConnectRefGrant row
	// referencing it (SESSION-AT AT1 row 2). The returned RoleDeleteCascadeCounts
	// reports how many live assignments the cascade actually removed, strictly
	// for the audit trail (PR #2357 review) -- not a correctness mechanism, so a
	// caller that ignores it loses nothing but the audit detail.
	DeleteRole(ctx context.Context, id uint) (RoleDeleteCascadeCounts, error)
	ListRoles(ctx context.Context) ([]*models.Role, error)
	// SetRoleBypassesPermissionChecks sets models.Role.BypassesPermissionChecks
	// (ADR-084) for roleID. Deliberately NOT reachable from CreateRole/UpdateRole
	// or any request DTO -- called only by role seeding
	// (defaultRoles/BootstrapSystem, internal/core/auth_bootstrap.go) for the
	// four reserved admin-tier role names, immediately after creating them. No
	// other production caller should exist; this is the one narrow, storage-
	// internal write path the ADR names, not a general role-mutation primitive.
	SetRoleBypassesPermissionChecks(ctx context.Context, roleID uint, value bool) error
	// SetRoleAssignableScope writes models.Role.AssignableScope (#3546 Phase 2)
	// for roleID, that column only (no full-row write). Callers: role seeding
	// (built-in scopes) and internal/core's CreateRoleWithScope.
	SetRoleAssignableScope(ctx context.Context, roleID uint, scope string) error

	// RBAC Operations.
	// AssignRole/RemoveRole bind a role to a user at the given Scope
	// (zero Scope = global). GetUserRoleIDsAt / GetUserGroupRoleIDsAt return the
	// role IDs that apply at a target scope (directly, or via group membership),
	// and RoleSetHasPermission reports whether any of those roles grants a
	// permission. Together they back core.Authorize.
	AssignRole(ctx context.Context, userID, roleID uint, scope Scope) error
	// AssignRoleWithExpiry binds a time-bound role to a user (just-in-time access):
	// the grant stops authorizing the moment expiresAt passes (the auth queries
	// filter on it) and is later swept by DeleteExpiredRoleGrants.
	AssignRoleWithExpiry(ctx context.Context, userID, roleID uint, scope Scope, expiresAt time.Time) error
	RemoveRole(ctx context.Context, userID, roleID uint, scope Scope) error
	// RemoveAllProjectRoleGrants deletes every user_roles row for (userID, projectID),
	// across ALL environments — not just the project-level (environment_id = 0) grant
	// RemoveRole's exact-scope match would touch. RemoveProjectMember uses it so that
	// offboarding a project member also revokes any environment-scoped grant (e.g.
	// "prod-only access", created via POST /user-roles) they separately hold in the
	// same project; otherwise it silently survives project-level removal, invisible to
	// the project admin who performed the offboarding (#232).
	RemoveAllProjectRoleGrants(ctx context.Context, userID, projectID uint) error
	// ClearProjectSecretOwnership clears the owner_id field (sets to 0) for every
	// live secret in projectID that is owned by userID. Called by RemoveProjectMember
	// so that an offboarded user's stale owner_id tag cannot grant them post-offboarding
	// owner-level access to those secrets via CheckSecretPermission's owner short-circuit
	// (RBAC-002).
	ClearProjectSecretOwnership(ctx context.Context, userID, projectID uint) error
	GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error)
	// ListAllUserRoleGrants returns every user→role grant row in the deployment,
	// including scoped (project/environment) and global (project_id=0) grants.
	// Includes time-bound (JIT) grants; callers filter by ExpiresAt if needed.
	ListAllUserRoleGrants(ctx context.Context) ([]*models.UserRole, error)
	// ListExpiringUserRoles returns every UserRole whose ExpiresAt is non-nil and
	// before the given cutoff (i.e. expiring or already expired). Used by
	// CheckRoleExpiry to find grants approaching their deadline.
	ListExpiringUserRoles(ctx context.Context, before time.Time) ([]models.UserRole, error)
	GetUserRoleIDsAt(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	GetUserRoleIDsExact(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	// IsProjectMember reports whether the user holds a LIVE role grant scoped to the
	// project itself (project_id = projectID), directly or via a group — i.e. real
	// membership. A global/install-wide role (project_id = 0) does NOT count.
	IsProjectMember(ctx context.Context, userID, projectID uint) (bool, error)
	// ProjectMembershipsAmong is IsProjectMember for many projects at once
	// (SHARES-BATCH-AUTHZ-1): the subset of projectIDs the user is a live member of,
	// by exactly IsProjectMember's rules (project 0 is never a membership; a global
	// role does not count; expired grants and soft-deleted groups do not count).
	ProjectMembershipsAmong(ctx context.Context, userID uint, projectIDs []uint) (map[uint]bool, error)
	// ListUserRoleGrants returns every live role grant of userID, direct and via a live
	// group, each with its own scope, so a caller can derive the role set at any number
	// of scopes in memory (SHARES-BATCH-AUTHZ-1). Applying UserRoleGrant.AppliesAt to
	// the rows yields exactly the role set ResolveUserPermissionAt reads at that scope.
	ListUserRoleGrants(ctx context.Context, userID uint) ([]UserRoleGrant, error)
	// ListUserLiveGroupMemberships returns userID's memberships in non-deleted groups
	// with the project each membership is scoped to (0 = global): the rows
	// GetUserGroupsAt filters by scope, for every scope at once.
	ListUserLiveGroupMemberships(ctx context.Context, userID uint) ([]UserGroupMembershipAt, error)
	// IsGroupProjectScoped reports whether groupID itself holds a LIVE role grant
	// scoped to the project (group_roles.project_id = projectID) — the group-share
	// counterpart to IsProjectMember, used to reject group shares whose recipient
	// group has no legitimate tie to the secret's project. A global/install-wide
	// group role grant (project_id = 0) does NOT count, matching IsProjectMember's
	// own global exclusion.
	IsGroupProjectScoped(ctx context.Context, groupID, projectID uint) (bool, error)
	GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	// GetUserGroupsAt is GetUserGroups scoped: only groups where userID's own
	// UserGroup row is global (project_id=0) OR matches scope.ProjectID (#G01).
	// GetUserGroups returns every group the user has ANY membership row in,
	// regardless of that membership's own project scope — callers resolving
	// "does this group membership grant authority within THIS project/secret"
	// must use this instead, or a membership scoped to project X is silently
	// treated as if it applied everywhere.
	GetUserGroupsAt(ctx context.Context, userID uint, scope Scope) ([]*models.Group, error)
	// GetUserRoleScopes returns the distinct (project, environment) scopes at which
	// userID holds ANY role, directly or via a live (non-deleted) group. It is the
	// scope-DISCOVERY step behind a scope-aware admin-rank-ceiling comparison
	// (impersonation's #165 check): the caller doesn't know in advance which
	// project a target might hold a project-scoped admin role in, so it must
	// enumerate every scope the target actually has a grant at, then evaluate
	// GetUserRoleIDsAt/GetUserGroupRoleIDsAt (via scopedRoleIDs) per scope.
	GetUserRoleScopes(ctx context.Context, userID uint) ([]Scope, error)
	// GetUserRoleScopesByUserIDs is the batch form of GetUserRoleScopes (LIST-ENDPOINTS-1):
	// the same distinct live scopes per user, keyed by user id; a user with no live role is absent.
	GetUserRoleScopesByUserIDs(ctx context.Context, userIDs []uint) (map[uint][]Scope, error)
	RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error)
	// RoleSetBypassesPermissionChecks reports whether any role in roleIDs has
	// BypassesPermissionChecks = true (ADR-084) -- the structural,
	// resolve-by-ID replacement for roleSetContainsAdmin's old fixed-name-list
	// lookup (internal/core/authz.go). Mirrors RoleSetHasPermission's shape.
	RoleSetBypassesPermissionChecks(ctx context.Context, roleIDs []uint) (bool, error)
	// ResolveUserPermissionAt is one user-principal role decision's reads
	// (PERF-FIX-6, collapse C4): GetUserRoleIDsAt ∪ GetUserGroupRoleIDsAt,
	// RoleSetBypassesPermissionChecks over that set and the role->permission
	// cache generation come from ONE statement (one snapshot); RoleSetHasPermission
	// is then answered from the cache under that generation, or by the live join
	// on a miss. The permission is not resolved (HasPermission false) when the
	// set is empty or bypasses, exactly as core.Authorize never asked then.
	ResolveUserPermissionAt(ctx context.Context, userID uint, scope Scope, permission string) (*PrincipalPermission, error)
	// ListAdminBypassRoleIDs enumerates every role ID carrying
	// BypassesPermissionChecks = true (ADR-084) -- the ENUMERATION counterpart to
	// RoleSetBypassesPermissionChecks' membership test, and the single source of
	// truth for "which roles confer administrative authority" (#2496,
	// INV-CORE-20). The last-install-admin guards need the set, not a yes/no on a
	// candidate set: they ask "which assignment rows count as an admin grant" and
	// "who else holds one", neither of which a membership predicate can answer.
	// Before this existed, those guards resolved the set by NAME
	// (installAdminRoleIDSet over a fixed super_admin/admin/system_admin list),
	// a second definition of "admin" that disagreed with the flag in both
	// directions -- see internal/core/admin_roles.go.
	//
	// Returns an error on any genuine resolution failure; callers must fail
	// closed (refuse the mutation) rather than treat it as an empty set, for
	// roleSetContainsAdmin's documented reason: an inability to verify must not
	// be indistinguishable from "there is no admin role here".
	ListAdminBypassRoleIDs(ctx context.Context) ([]uint, error)
	GetUserPermissions(ctx context.Context, userID uint) ([]*Permission, error)
	// GetUserGroupPermissions returns the permissions a user holds via GROUP
	// membership (group → group_roles → role_permissions), scope-agnostically and
	// across all of the user's groups — the counterpart to GetUserPermissions, which
	// covers only direct user_roles. Callers that need a user's full effective
	// permission set (e.g. SoD conflict detection, GetUserPermissionsByID) must
	// union both, mirroring how Authorize unions direct and group-inherited roles.
	GetUserGroupPermissions(ctx context.Context, userID uint) ([]*Permission, error)

	// Permission queries
	ListPermissions(ctx context.Context) ([]*models.Permission, error)
	GetPermission(ctx context.Context, id uint) (*models.Permission, error)
	GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error)
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID uint) error

	// Group-Role assignments. Assign/Remove bind a role to a group at the given
	// Scope (zero Scope = global).
	GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error)
	// GetGroupRoleGrants is GetGroupRoles plus each grant's time-bound expiry
	// (nil = permanent), so callers can surface remaining time on a JIT grant.
	GetGroupRoleGrants(ctx context.Context, groupID uint) ([]*GroupRoleGrant, error)
	// ListGroupRoleAssignments returns every role grant held by a group across ALL
	// scopes (unlike ListProjectRoleAssignments, which is scoped to one project) —
	// used to evaluate the admin-rank ceiling before adding a member to the group,
	// and the last-install-administrator invariant before removing one or deleting
	// the group outright.
	ListGroupRoleAssignments(ctx context.Context, groupID uint) ([]RoleAssignment, error)
	// ListAllGroupRoleGrants returns every group→role grant row in the deployment,
	// including scoped (project/environment) and global (project_id=0) grants, and
	// including already-expired time-bound grants — the group-grant counterpart to
	// ListAllUserRoleGrants. Unlike GetGroupRoles (role only, no scope),
	// GetGroupRoleGrants (role, scope and expiry, but for one group) or
	// ListGroupRoleAssignments (scope, but silently drops expired rows), this is the
	// one call that carries every group grant's role, scope, AND expiry
	// together, unfiltered — what GetPermissionBaseline needs to report a
	// group-inherited grant's real scope and flag (not hide) an expired one (#G25).
	ListAllGroupRoleGrants(ctx context.Context) ([]*models.GroupRole, error)
	AssignRoleToGroup(ctx context.Context, groupID, roleID uint, scope Scope) error
	// AssignRoleToGroupWithExpiry binds a time-bound role to a group; see
	// AssignRoleWithExpiry.
	AssignRoleToGroupWithExpiry(ctx context.Context, groupID, roleID uint, scope Scope, expiresAt time.Time) error
	// RemoveRoleFromGroup returns ErrRoleNotAssigned (wrapped) if the group
	// holds no such grant at scope.
	RemoveRoleFromGroup(ctx context.Context, groupID, roleID uint, scope Scope) error
	// DeleteExpiredRoleGrants removes user/group role grants whose ExpiresAt is at
	// or before `before`, returning the removed grants so the caller can audit each
	// expiry. Backs the JIT access-expiry scheduler.
	DeleteExpiredRoleGrants(ctx context.Context, before time.Time) ([]RoleAssignment, error)
}
