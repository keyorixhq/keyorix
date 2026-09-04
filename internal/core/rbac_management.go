package core

import (
	"context"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RoleWithPermissions embeds a Role and includes its assigned permissions.
type RoleWithPermissions struct {
	models.Role
	Permissions []*models.Permission `json:"permissions"`
}

// UserRoleAssignment holds a user's identity alongside their assigned roles.
type UserRoleAssignment struct {
	UserID   uint           `json:"user_id"`
	Username string         `json:"username"`
	Email    string         `json:"email"`
	Roles    []*models.Role `json:"roles"`
}

// ListPermissions returns all permissions.
func (c *KeyorixCore) ListPermissions(ctx context.Context) ([]*models.Permission, error) {
	permissions, err := c.storage.ListPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}

// GetRoleWithPermissions returns a role and its assigned permissions.
func (c *KeyorixCore) GetRoleWithPermissions(ctx context.Context, roleID uint) (*models.Role, []*models.Permission, error) {
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return nil, nil, err
	}
	perms, err := c.storage.GetRolePermissions(ctx, roleID)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return role, perms, nil
}

// AssignPermissionToRole verifies both exist, requires the actor already hold the
// permission being bundled, assigns it, and records an RBAC audit event. actorID is
// the acting principal (0 = none).
//
// #169: CreateRole/UpdateRole are gated only by the narrower "roles.write" — without
// this check, a roles.write holder could bundle an arbitrary admin-tier permission
// (system.write, roles.assign, users.impersonate, ...) into a role's DEFINITION with
// zero check that they hold it themselves, then have that role granted to them
// through any ordinary (non-admin) grant path — bypassing every admin-rank-ceiling
// check on the GRANT step (#93/#107/#141/#147/#161/#165 and friends), since none of
// those fixes touch role-definition time. Roles are global catalog objects (not
// project/environment-scoped), so the actor must hold the permission at GLOBAL scope
// — matching how roles.write itself is gated (RequirePermission always resolves to
// ScopeGlobal). c.Authorize already includes the admin-role bypass, so a genuine
// global admin is unaffected.
//
// #1500: mutating a built-in role's permission set stays PERMITTED here, on
// purpose. ADR-044's "Alternatives considered" already rejected making RBAC
// permission changes converge/refuse against operator intent — the same
// reasoning applies to bundling a permission into a built-in role directly:
// operators must retain authority to widen (or narrow, see
// RemovePermissionFromRole below) a built-in role's grants. Do NOT add an
// IsBuiltinRole guard here — that would be exactly the "fix" ADR-044 already
// considered and declined. What changes is visibility: the audit event and
// log warning below let an operator/reviewer SEE that a built-in role's
// authorization baseline moved, without blocking the move.
//
// #1545: actorIsMachine distinguishes a machine-credential-authenticated caller
// (UserID==0 by construction, ADR-030) from the true "no authenticated principal"
// case the actorID==0 exemption below was written for (system/background callers
// like ReconcileRBACPermissions). Both present as actorID==0; only the latter is
// exempt. A machine identity holding nothing but roles.write reached this
// unguarded — server/http/handlers/rbac.go's AssignPermissionToRole handler
// passes userCtx.UserID directly, unlike CreateRole/UpdateRole which already
// pre-authorize every permission via Authorize(ctx, userCtx.UserID, ...) before
// ever reaching here (and so already denied a machine actor there — Authorize
// has no user ID 0 to find roles for). actorID==0 with actorIsMachine==true now
// falls into the check below, which correctly fails closed the same way.
func (c *KeyorixCore) AssignPermissionToRole(ctx context.Context, actorID, roleID, permissionID uint, actorIsMachine bool) error {
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	perm, err := c.storage.GetPermission(ctx, permissionID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	// actorID 0 is the established "system" pseudo-actor used by startup/background
	// processes that are never attacker-reachable (e.g. ReconcileRBACPermissions's
	// additive, non-clobbering, once-per-boot top-up of newly-added canonical
	// permissions — #293). Those callers have no role of their own to hold the
	// permission being bundled, so the #169 self-permission check only applies to a
	// real (non-zero) actor OR a machine-credential-authenticated one (#1545).
	if actorID != 0 || actorIsMachine {
		// #1545 sibling gap (Part 2 regression audit, 2026-09-04): c.Authorize
		// is the USER-only lookup (GetUserRoleIDsAt); for a machine caller
		// actorID is always 0 (ADR-030, no UserID), so this call could never
		// succeed for ANY machine actor -- even one that genuinely holds the
		// permission via its own machine role. Use AuthorizePrincipal (the
		// actor-aware primitive every other machine-auth path in this
		// codebase uses) instead, resolving the machine's real principal ID
		// from WithSelfMachineGranter the same way requireGranterHoldsRolePermissions
		// does -- fail closed if the caller (a /system proxy relay, or any
		// direct caller that forgot to tag ctx) never tagged itself as the
		// self-acting machine granter.
		if actorIsMachine {
			granterID, tagged := selfMachineGranterFromContext(ctx)
			if !tagged {
				return fmt.Errorf("cannot assign permission %q to a role: you do not hold it yourself", perm.Name)
			}
			if ok, aerr := c.AuthorizePrincipal(ctx, ActorTypeMachine, granterID, perm.Name, Scope{}); aerr != nil {
				return fmt.Errorf("failed to resolve actor authority: %w", aerr)
			} else if !ok {
				return fmt.Errorf("cannot assign permission %q to a role: you do not hold it yourself", perm.Name)
			}
		} else if ok, aerr := c.Authorize(ctx, actorID, perm.Name, Scope{}); aerr != nil {
			return fmt.Errorf("failed to resolve actor authority: %w", aerr)
		} else if !ok {
			return fmt.Errorf("cannot assign permission %q to a role: you do not hold it yourself", perm.Name)
		}
	}
	if err := c.storage.AssignPermissionToRole(ctx, roleID, permissionID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	builtinTarget := IsBuiltinRole(role.Name)
	if builtinTarget {
		log.Printf("SECURITY: permission %q (id %d) added to built-in role %q (id %d) by actor %d — permitted by design (ADR-044); operator authority over a built-in role's permission set is deliberate, not a bug",
			perm.Name, permissionID, role.Name, roleID, actorID)
	}
	c.LogPermissionAssigned(ctx, actorID, roleID, permissionID, builtinTarget)
	return nil
}

// RemovePermissionFromRole verifies the role exists, removes the permission, and
// records an RBAC audit event. actorID is the acting principal (0 = none).
//
// #1500: mutating a built-in role's permission set stays PERMITTED here, on
// purpose — see the identical note on AssignPermissionToRole above. Removing a
// permission from a built-in role must not be refused; only made visible.
func (c *KeyorixCore) RemovePermissionFromRole(ctx context.Context, actorID, roleID, permissionID uint) error {
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if err := c.storage.RemovePermissionFromRole(ctx, roleID, permissionID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	builtinTarget := IsBuiltinRole(role.Name)
	if builtinTarget {
		// A best-effort name lookup purely for the log line's readability — unlike
		// AssignPermissionToRole, the permission is never otherwise fetched on this
		// path, so this query only runs in the (rare) built-in-target case rather
		// than on every call.
		permName := fmt.Sprintf("id %d", permissionID)
		if perm, perr := c.storage.GetPermission(ctx, permissionID); perr == nil {
			permName = fmt.Sprintf("%q (id %d)", perm.Name, permissionID)
		}
		log.Printf("SECURITY: permission %s removed from built-in role %q (id %d) by actor %d — permitted by design (ADR-044); operator authority over a built-in role's permission set is deliberate, not a bug",
			permName, role.Name, roleID, actorID)
	}
	c.LogPermissionRemoved(ctx, actorID, roleID, permissionID, builtinTarget)
	return nil
}

// GetGroupRoles returns all roles assigned to a group.
func (c *KeyorixCore) GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error) {
	roles, err := c.storage.GetGroupRoles(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// GetGroupRoleGrants returns a group's roles each with its time-bound expiry
// (nil = permanent), so the API can surface remaining time on a just-in-time grant.
func (c *KeyorixCore) GetGroupRoleGrants(ctx context.Context, groupID uint) ([]*storage.GroupRoleGrant, error) {
	grants, err := c.storage.GetGroupRoleGrants(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return grants, nil
}

// AssignRoleToGroup verifies both exist, applies the escalation-by-proxy ceiling
// (requireGranterHoldsRolePermissions — granting a group a role inherits to every
// member, so it is gated exactly like a direct user grant, and by the role's real
// bundled permissions rather than only its name), then assigns the role at scope
// and records an RBAC audit event. actorID is the acting principal (0 = none, the
// trusted system pseudo-actor); actorIsMachine distinguishes a machine-credential
// caller (also actorID==0) from that true unauthenticated case.
func (c *KeyorixCore) AssignRoleToGroup(ctx context.Context, actorID, groupID, roleID uint, scope Scope, actorIsMachine bool) error {
	if _, err := c.storage.GetGroup(ctx, groupID); err != nil {
		return fmt.Errorf("group not found: %w", err)
	}
	if _, err := c.storage.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if err := c.requireGranterHoldsRolePermissions(ctx, actorID, roleID, scope, actorIsMachine); err != nil {
		return err
	}
	// #1646: see AssignUserRole's identical WithNamedLock use.
	return c.storage.WithNamedLock(ctx, sodGrantLockKey("group", groupID), func(ctx context.Context) error {
		if err := c.requireGroupGrantNoSoDViolation(ctx, groupID, roleID); err != nil {
			return err
		}
		if err := c.storage.AssignRoleToGroup(ctx, groupID, roleID, scope); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		c.LogGroupRoleAssigned(ctx, actorID, groupID, roleID, scope)
		return nil
	})
}

// RemoveRoleFromGroup verifies the group exists then removes the role at scope
// and records an RBAC audit event. actorID is the acting principal (0 = none). It
// refuses to remove the install's last global-admin-conferring group grant (#107;
// see guardLastGlobalAdminGroupRole), OR a project's last roles.assign-conferring
// group grant (FIX-2; see guardLastProjectAdminGroupRole) — a group losing its
// project-admin-conferring role is the third way (alongside group deletion and
// membership removal, both already guarded — guardLastProjectAdminGroupDelete/
// guardLastProjectAdminGroupMembership) a group can stop conferring project-admin
// authority, and had no guard at all.
func (c *KeyorixCore) RemoveRoleFromGroup(ctx context.Context, actorID, groupID, roleID uint, scope Scope) error {
	if _, err := c.storage.GetGroup(ctx, groupID); err != nil {
		return fmt.Errorf("group not found: %w", err)
	}
	if err := c.guardLastGlobalAdminGroupRole(ctx, groupID, roleID, scope); err != nil {
		return err
	}
	if scope.ProjectID != 0 && scope.EnvironmentID == 0 {
		// #1646: serialize the guard's read against every HA replica via the same
		// per-project named lock SetProjectMemberRole/RemoveProjectMember/
		// RemoveUserRole use, so a concurrent removal racing this one can't each
		// observe "another admin survives" before either write commits.
		if err := c.storage.WithNamedLock(ctx, projectAdminGuardLockKey(scope.ProjectID), func(ctx context.Context) error {
			return c.guardLastProjectAdminGroupRole(ctx, groupID, roleID, scope.ProjectID)
		}); err != nil {
			return err
		}
	}
	if err := c.storage.RemoveRoleFromGroup(ctx, groupID, roleID, scope); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogGroupRoleRemoved(ctx, actorID, groupID, roleID, scope)
	return nil
}

// ListRolesWithPermissions returns all roles with their permission sets.
func (c *KeyorixCore) ListRolesWithPermissions(ctx context.Context) ([]*RoleWithPermissions, error) {
	roles, err := c.storage.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	result := make([]*RoleWithPermissions, 0, len(roles))
	for _, role := range roles {
		perms, err := c.storage.GetRolePermissions(ctx, role.ID)
		if err != nil {
			perms = []*models.Permission{}
		}
		result = append(result, &RoleWithPermissions{
			Role:        *role,
			Permissions: perms,
		})
	}
	return result, nil
}

// GetUserRoleAssignment returns a user's identity and assigned roles.
func (c *KeyorixCore) GetUserRoleAssignment(ctx context.Context, userID uint) (*UserRoleAssignment, error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	roles, err := c.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &UserRoleAssignment{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Roles:    roles,
	}, nil
}

// GetUserRolesByID returns the roles assigned to the given user ID.
func (c *KeyorixCore) GetUserRolesByID(ctx context.Context, userID uint) ([]*models.Role, error) {
	roles, err := c.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// GetUserPermissionsByID returns a user's effective permission set — the
// de-duplicated union of permissions across every DIRECT role assigned to the
// user AND every role inherited via group membership, mirroring how Authorize
// resolves scopedRoleIDs (authz.go) before any live permission check. This is
// the "what can this user do" view for dashboards and access reviews (#375); a
// permission held only via a group role must be visible here — omitting it let
// a malicious insider "hide" real, group-derived access from a recertification
// reviewer even though Authorize() would grant it on every live request. Empty
// for an unknown user.
func (c *KeyorixCore) GetUserPermissionsByID(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	direct, err := c.storage.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	viaGroups, err := c.storage.GetUserGroupPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	seen := make(map[uint]struct{}, len(direct)+len(viaGroups))
	perms := make([]*storage.Permission, 0, len(direct)+len(viaGroups))
	for _, list := range [][]*storage.Permission{direct, viaGroups} {
		for _, p := range list {
			if _, ok := seen[p.ID]; ok {
				continue
			}
			seen[p.ID] = struct{}{}
			perms = append(perms, p)
		}
	}
	return perms, nil
}

// SetUserRoles does a full replacement of the roles assigned to a user at the
// given scope. Only assignments at exactly that scope are considered: roles
// present there but not in roleIDs are removed; roles in roleIDs not already
// assigned there are added. Assignments at other scopes are left untouched.
// actorIsMachine distinguishes a machine-credential-authenticated caller (also
// actorID==0) from the true actorID==0 system pseudo-actor.
func (c *KeyorixCore) SetUserRoles(ctx context.Context, actorID, userID uint, roleIDs []uint, scope Scope, actorIsMachine bool) error {
	current, err := c.storage.GetUserRoleIDsExact(ctx, userID, scope)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	currentSet := make(map[uint]bool, len(current))
	for _, id := range current {
		currentSet[id] = true
	}
	newSet := make(map[uint]bool, len(roleIDs))
	for _, id := range roleIDs {
		newSet[id] = true
	}
	for _, id := range current {
		if !newSet[id] {
			if err := c.RemoveUserRole(ctx, actorID, userID, id, scope); err != nil {
				return err
			}
		}
	}
	for _, id := range roleIDs {
		if !currentSet[id] {
			if err := c.AssignUserRole(ctx, actorID, userID, id, scope, actorIsMachine); err != nil {
				return err
			}
		}
	}
	return nil
}

// sodGrantLockKey is the WithNamedLock key for every role-grant path guarded by the
// #419 separation-of-duties preventive check (#1646): scoped per (principalType,
// principalID) so two concurrent grants to the SAME principal serialize against
// each other -- the shape a toxic-combination SoD violation requires -- without
// unrelated principals' grants contending on the same lock.
func sodGrantLockKey(principalType string, principalID uint) string {
	return fmt.Sprintf("sod-grant:%s:%d", principalType, principalID)
}

// AssignUserRole assigns a role to a user at the given scope and records an RBAC
// audit event. actorID is the acting principal (0 when unauthenticated, e.g. a
// local CLI invocation). This is the audited choke point all role-assignment
// paths funnel through. See requireGranterHoldsRolePermissions for the
// admin-rank-ceiling check on the grant (#93/#107/#141), and requireNoSoDViolation
// (sod.go) for the separation-of-duties preventive gate (#419).
//
// actorIsMachine distinguishes a machine-credential-authenticated caller
// (also actorID==0, per server/middleware/auth.go) from the true actorID==0
// "system" pseudo-actor -- see requireGranterHoldsRolePermissions's doc
// comment. Every caller of this permanent-grant path is reachable by a
// general machine identity the same way #1545 found for AssignPermissionToRole
// (AddProjectMember/SetProjectMemberRole, the AssignRole gRPC/HTTP endpoints);
// this closes that sibling instance by threading the real value through
// instead of hardcoding false.
func (c *KeyorixCore) AssignUserRole(ctx context.Context, actorID, userID, roleID uint, scope Scope, actorIsMachine bool) error {
	if err := c.requireGranterHoldsRolePermissions(ctx, actorID, roleID, scope, actorIsMachine); err != nil {
		return err
	}
	// #1646: the check-then-write below must be serialized across every replica of
	// an HA deployment, not just within this process — sodGrantMu (an in-process
	// sync.Mutex) alone let two independent replicas each pass a stale pre-grant
	// SoD check and both write, live-reproduced. WithNamedLock's Postgres advisory
	// lock, keyed per target principal, closes that; see its doc comment in
	// internal/core/storage/interface.go.
	return c.storage.WithNamedLock(ctx, sodGrantLockKey("user", userID), func(ctx context.Context) error {
		if err := c.requireNoSoDViolation(ctx, userID, roleID); err != nil {
			return err
		}
		if err := c.storage.AssignRole(ctx, userID, roleID, scope); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		c.LogRoleAssigned(ctx, actorID, userID, roleID, scope)
		return nil
	})
}

// assignUserRoleSystemGrant performs the same audited grant as AssignUserRole but
// deliberately SKIPS the #93/#107/#141 grant-ceiling check. Use it ONLY where the
// authorization root for the grant is not the acting principal's own
// roles.assign-derived authority, but an independently validated, admin-
// configured trust mapping — today that is exactly one caller: SSO group-role
// reconciliation (sso.go), where an install admin (not the logging-in user)
// decided which IdP groups map to which roles ahead of time, and the login itself
// was verified against the IdP's signed id_token. Requiring the logging-in user to
// already hold the very role they're being auto-provisioned would defeat the
// feature's whole purpose — this mirrors the actorID-0 "system pseudo-actor"
// bypass AssignPermissionToRole uses for #169, but keyed on the call site instead
// of the actor ID, since SSO reconciliation attributes the grant to the real
// logging-in user (actorID = userID) for audit purposes, not to actor 0.
// actorID is still recorded as the audit actor. Never call this from a path
// reachable by an ordinary authenticated request exercising roles.assign — that
// path must go through AssignUserRole so the ceiling check applies.
//
// #419: the separation-of-duties preventive gate (requireNoSoDViolation) IS
// still applied here, unlike the ceiling check above — this is a distinct
// concern (whether the grant creates a toxic-permission overlap, not whether the
// granter's own authority covers it) and its only caller, reconcileSSOGroups
// (sso.go), already treats any error from this call as "role not added, sync the
// rest, retry next login" rather than failing the login — so blocking here is
// safe and closes an SSO-group-mapping-driven instance of the same #419 gap
// (IdP group membership can change on every login, which is at least as fast a
// grant/revoke cycle as an explicit JIT grant).
func (c *KeyorixCore) assignUserRoleSystemGrant(ctx context.Context, actorID, userID, roleID uint, scope Scope) error {
	// #1646: see AssignUserRole's identical WithNamedLock use.
	return c.storage.WithNamedLock(ctx, sodGrantLockKey("user", userID), func(ctx context.Context) error {
		if err := c.requireNoSoDViolation(ctx, userID, roleID); err != nil {
			return err
		}
		if err := c.storage.AssignRole(ctx, userID, roleID, scope); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		c.LogRoleAssigned(ctx, actorID, userID, roleID, scope)
		return nil
	})
}

// RemoveUserRole removes a role from a user at the given scope and records an
// RBAC audit event. See AssignUserRole for actorID semantics. It refuses to remove
// the last install administrator (see RemoveGlobalAdminRoleGuarded). This is the
// choke point SetUserRoles and the HTTP/gRPC role-removal handlers funnel through.
//
// #340/#525: for a global-scope (project 0, environment 0) admin-conferring role,
// the last-admin check and the removal itself must be ATOMIC — otherwise two
// concurrent removals of two different admins' role assignments could each
// observe "another admin still exists" before either write commits, stranding
// the install with zero admins. Prior to #525 this ran as
// ListGlobalAdminAssignmentsForUpdate + RemoveRole inside a single
// storage.WithTransaction closure: correct against LocalStorage (a real DB
// transaction + Postgres row lock spans both calls), but
// RemoteStorage.WithTransaction is a no-op passthrough — under storage.type:
// remote those were two independent HTTP round trips with nothing serializing
// them beyond globalAdminGuardMu, which only covers same-process callers (not a
// second spoke, or the hub's own direct callers, racing the same admin set).
// RemoveGlobalAdminRoleGuarded folds the check and the write into ONE storage
// call, so whichever server actually owns the row — the hub, for a remote spoke —
// is the only one that ever needs to enforce it atomically; globalAdminGuardMu is
// kept as a cheap same-process fast-path serializer (mirroring
// login_lockout.go's recordFailedLogin two-layer pattern), not as the sole
// correctness mechanism.
//
// FIX-2: RemoveUserRole was scope-blind past the global check — a project-scoped
// removal (scope.ProjectID != 0) fell straight through to storage.RemoveRole with
// no last-admin protection at all, even though this is THE shared primitive
// SetProjectMemberRole/RemoveProjectMember funnel through for their OWN
// project-scope guard (guardLastProjectAdmin, itself WithNamedLock-wrapped by
// those two callers per #1646). Any OTHER caller reaching this primitive
// directly at project scope — and there are several: the plain /user-roles HTTP
// route (RemoveRole, server/http/handlers/rbac.go), the gRPC RemoveRole RPC, and
// the /system RemoveRoleGrantProxy — bypassed project-admin protection entirely,
// letting a project's last roles.assign holder remove their own (or anyone's)
// project-admin grant with no refusal. Guard the primitive itself, scope-aware,
// so no entry point can bypass it going forward — the same "move the check to
// where it cannot be skipped" fix SetProjectMemberRole/RemoveProjectMember
// already apply one layer up, generalized to the actual choke point.
func (c *KeyorixCore) RemoveUserRole(ctx context.Context, actorID, userID, roleID uint, scope Scope) error {
	if scope.ProjectID == 0 && scope.EnvironmentID == 0 {
		handled, err := c.removeGlobalAdminRoleIfApplicable(ctx, userID, roleID)
		if err != nil {
			return err
		}
		if handled {
			c.LogRoleRemoved(ctx, actorID, userID, roleID, scope)
			// Evict the auth cache so a just-revoked role stops authorizing on the
			// very next request instead of the up-to-30s positive-cache window every
			// other credential-lifecycle event in this package already closes
			// (password change, suspend/deactivate/delete, PAT revoke,
			// machine-identity suspend/revoke).
			c.evictUserSessionCache(ctx, userID)
			return nil
		}
	}
	if scope.ProjectID != 0 && scope.EnvironmentID == 0 {
		// #1646: the guard's read (existing roles) and the removal below must be
		// serialized across every replica of an HA deployment, matching
		// SetProjectMemberRole/RemoveProjectMember's identical use of the same
		// per-project named lock — two concurrent removals of two different
		// project admins' grants could otherwise each observe "another admin
		// survives" before either write commits.
		if err := c.storage.WithNamedLock(ctx, projectAdminGuardLockKey(scope.ProjectID), func(ctx context.Context) error {
			existing, err := c.storage.GetUserRoleIDsExact(ctx, userID, scope)
			if err != nil {
				return err
			}
			after := make([]uint, 0, len(existing))
			for _, id := range existing {
				if id != roleID {
					after = append(after, id)
				}
			}
			return c.guardLastProjectAdmin(ctx, scope.ProjectID, userID, existing, after)
		}); err != nil {
			return err
		}
	}
	return c.removeUserRoleUnguarded(ctx, actorID, userID, roleID, scope)
}

// removeUserRoleUnguarded performs the actual role removal, audit log, and
// cache eviction WITHOUT re-running guardLastProjectAdmin -- the tail
// RemoveUserRole itself uses after its own guard above passes.
//
// Part 2 regression audit (adversarial review run 2): SetProjectMemberRole
// swapping a project's SOLE administrator directly from one admin-tier role
// to ANOTHER (both carrying roles.assign) already validates that full
// transition safely, atomically, under its own WithNamedLock, via its own
// guardLastProjectAdmin(existing, []uint{newRole.ID}) call BEFORE touching
// anything (see SetProjectMemberRole). But its removal loop used to call the
// public, guarded RemoveUserRole for the outgoing role -- whose OWN
// project-scope guard (added by this same FIX-2, above) re-derives "after"
// as "existing minus roleID", blind to the compensating AssignUserRole
// SetProjectMemberRole is about to make. For a sole admin with exactly one
// existing role, that blind re-check saw an empty "after" and refused the
// swap outright ("cannot remove or demote the project's last administrator")
// even though the operation, viewed as a whole -- which is exactly what
// SetProjectMemberRole's own upfront guard already confirmed -- never
// actually left the project without an administrator. SetProjectMemberRole
// now calls this unguarded primitive directly for its removal-loop steps,
// relying on its own already-correct, whole-operation guard instead of
// RemoveUserRole's necessarily narrower, single-call one.
func (c *KeyorixCore) removeUserRoleUnguarded(ctx context.Context, actorID, userID, roleID uint, scope Scope) error {
	if err := c.storage.RemoveRole(ctx, userID, roleID, scope); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogRoleRemoved(ctx, actorID, userID, roleID, scope)
	c.evictUserSessionCache(ctx, userID)
	return nil
}

// removeGlobalAdminRoleIfApplicable performs RemoveUserRole's global-scope
// admin-conferring-role removal (the #340/#525 atomic path) when roleID is one
// of installAdminRoleNames, returning handled=true (removal performed or
// refused) in that case. handled=false means roleID is not a global-admin role
// and the caller should fall through to the ordinary removal path. Split out of
// RemoveUserRole so globalAdminGuardMu's critical section stays scoped to
// exactly this branch — it must never be held while the function's OTHER branch
// (the project-scope guard below) acquires storage.WithNamedLock, or a
// project-scope RemoveUserRole call racing a SetProjectMemberRole/
// RemoveProjectMember call (which acquires WithNamedLock BEFORE calling back
// into RemoveUserRole, per #1646) would lock-order-invert: the former acquires
// globalAdminGuardMu then waits on WithNamedLock, the latter holds WithNamedLock
// and waits on globalAdminGuardMu.
func (c *KeyorixCore) removeGlobalAdminRoleIfApplicable(ctx context.Context, userID, roleID uint) (handled bool, err error) {
	c.globalAdminGuardMu.Lock()
	defer c.globalAdminGuardMu.Unlock()
	adminIDs := c.installAdminRoleIDSet(ctx)
	if !adminIDs[roleID] {
		return false, nil
	}
	ids := make([]uint, 0, len(adminIDs))
	for id := range adminIDs {
		ids = append(ids, id)
	}
	if err := c.storage.RemoveGlobalAdminRoleGuarded(ctx, userID, roleID, ids); err != nil {
		return true, err
	}
	return true, nil
}

// installAdminRoleNames are the roles that confer install-wide administration when
// held at the global scope (project 0). Removing the last such assignment leaves the
// install with no one able to manage users, roles, or settings.
var installAdminRoleNames = []string{"super_admin", "admin", "system_admin"}

// installAdminRoleIDSet resolves installAdminRoleNames to their role IDs (skipping
// any that a given install did not seed). Used by RemoveUserRole's global-admin
// guard (RemoveGlobalAdminRoleGuarded, #340/#525) and by the group-level admin
// guards in authz.go (guardLastGlobalAdminGroupRole/GroupDelete/Membership).
func (c *KeyorixCore) installAdminRoleIDSet(ctx context.Context) map[uint]bool {
	set := make(map[uint]bool, len(installAdminRoleNames))
	for _, name := range installAdminRoleNames {
		if role, err := c.storage.GetRoleByName(ctx, name); err == nil && role != nil {
			set[role.ID] = true
		}
	}
	return set
}
