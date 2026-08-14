// authz.go — Scope-aware permission enforcement (RBAC Phase 2).
//
// Authorize is the single entrypoint the HTTP middleware uses to decide whether
// a user may perform an action against a particular project/environment. It
// resolves the roles that apply at the target scope — both directly assigned and
// inherited via group membership — then checks whether any of them grants the
// permission. A user holding the admin (or super_admin) role at, or above, the
// target scope bypasses the specific-permission check: the super-user escape
// hatch. All resolution errors fail closed (deny).
package core

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// PATRestriction bounds what a request authenticated by a personal access token
// (ADR-042) may do, independent of — and intersected with — the owning user's own
// permissions. It is a least-privilege FILTER: it can only narrow a token below
// its owner, never grant the owner anything extra. The owner's live role
// resolution still runs after this check, so a restriction listing a permission
// the owner has since lost grants nothing.
type PATRestriction struct {
	// Permissions, when non-empty, is the exhaustive allowlist of permission
	// strings the token may exercise. Empty = inherit the owner's full set. An
	// entry may be an exact permission ("secrets.read"), the catch-all "*", or a
	// prefix wildcard ("secrets.*").
	Permissions []string
	// ProjectID, when non-zero, restricts the token to that project's scope;
	// any check at a different project — or at global/system scope (project 0) —
	// is denied. Zero = any scope the owner can reach.
	ProjectID uint
	// EnvironmentID, when non-zero, further restricts the token to that one
	// environment: any check whose resolved scope is a different environment — or a
	// project-level/global scope (environment 0) — is denied. Environment ids are
	// globally unique, so this confines the token to that env's project too. Zero =
	// any environment. (Secret-level checks carry the secret's environment; broader
	// project-level operations resolve environment 0 and so are denied for an
	// environment-scoped token — correct least privilege for, e.g., a staging-only
	// CI credential.)
	EnvironmentID uint
	// AllowedCIDRs, when non-empty, restricts the token to requests whose source IP falls
	// within one of the listed CIDR blocks. Enforced at the auth boundary (fail-closed: an
	// undeterminable/unparseable source IP is denied). Empty = no network restriction.
	AllowedCIDRs []string
}

// MachineTokenRestriction carries the network-level constraints a machine
// identity credential may impose. When AllowedCIDRs is non-empty, the
// request source IP must fall within one of the listed blocks; a stolen
// machine token is therefore useless from outside the allowed network.
type MachineTokenRestriction struct {
	AllowedCIDRs []string
}

// IPInCIDRs reports whether ip (a bare host like "203.0.113.7") falls within any of the
// given CIDR blocks. It is the network gate for IP-allowlisted tokens and fails CLOSED:
// an unparseable ip, an empty cidr list passed as a gate, or a malformed CIDR yields false
// (callers only invoke it when the token actually carries an allowlist).
func IPInCIDRs(ip string, cidrs []string) bool {
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return false
	}
	for _, c := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		if network.Contains(addr) {
			return true
		}
	}
	return false
}

// Allows reports whether this restriction permits exercising permission at scope.
// A nil restriction (no PAT, or an unrestricted PAT) is handled by the caller.
func (r *PATRestriction) Allows(permission string, scope Scope) bool {
	if r == nil {
		return true
	}
	// A project-scoped token may act ONLY within its project. A check at global
	// scope (ProjectID 0 — system-wide actions like users.read) is therefore
	// denied for a project-scoped token: it is not a system credential.
	if r.ProjectID != 0 && scope.ProjectID != r.ProjectID {
		return false
	}
	// An environment-scoped token may act ONLY within its environment; a check at a
	// different (or project-level/global) environment is denied.
	if r.EnvironmentID != 0 && scope.EnvironmentID != r.EnvironmentID {
		return false
	}
	if len(r.Permissions) == 0 {
		return true
	}
	for _, p := range r.Permissions {
		if p == "*" || p == permission {
			return true
		}
		if strings.HasSuffix(p, ".*") && strings.HasPrefix(permission, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}

// patRestrictionCtxKey is the unexported context key carrying a *PATRestriction.
type patRestrictionCtxKey struct{}

// WithPATRestriction tags ctx with the restriction a personal access token
// imposes on the request. The auth middleware sets it for PAT-authenticated
// requests only; session, machine and OIDC requests never carry one. Authorize
// and AuthorizePrincipal read it back so the restriction is enforced uniformly at
// the single authorization chokepoint — every present and future authz path.
func WithPATRestriction(ctx context.Context, r *PATRestriction) context.Context {
	return context.WithValue(ctx, patRestrictionCtxKey{}, r)
}

// patRestrictionFromContext returns the PAT restriction on ctx, or nil if none.
func patRestrictionFromContext(ctx context.Context) *PATRestriction {
	r, _ := ctx.Value(patRestrictionCtxKey{}).(*PATRestriction)
	return r
}

// Scope identifies the project/environment an authorization check or a role
// assignment applies to. It aliases storage.Scope so the same 0 = global
// sentinel flows from the HTTP layer through to the queries unchanged.
type Scope = storage.Scope

// adminRoleNames are roles that bypass the per-permission check at the scope
// they are assigned. A global (project 0) admin therefore bypasses everywhere;
// a project-scoped admin bypasses only within that project.
//
// "admin"/"super_admin" are the legacy single-tier super-users; "system_admin"
// and "project_admin" are the ADR-021 two-tier equivalents. A system_admin is
// expected to be assigned globally (bypasses install-wide); a project_admin is
// expected to be assigned at a project scope (bypasses within that project).
var adminRoleNames = []string{"super_admin", "admin", "system_admin", "project_admin"}

// isAdminRoleName reports whether roleName is one of the admin (permission-bypass)
// roles — a pure-string check requiring no storage lookup, for guards that already
// hold the role name.
func isAdminRoleName(roleName string) bool {
	return slices.Contains(adminRoleNames, roleName)
}

// AuthorizePrincipal reports whether a principal — a human user or a machine
// identity (ADR-030) — may exercise permission against the target scope. It is
// the actor-aware entrypoint the auth gates use; Authorize is the user-only
// wrapper kept for source compatibility. Machine principals resolve their
// permissions from machine_identity_roles and receive NO admin-role bypass: a
// machine is never a global super-user, so a leaked machine token is bounded to
// the permissions of its explicit grants. Fails closed.
func (c *KeyorixCore) AuthorizePrincipal(ctx context.Context, actorType string, principalID uint, permission string, scope Scope) (bool, error) {
	// A personal access token may carry a least-privilege restriction (ADR-042)
	// that narrows it below its owner. Enforce it first, before any role
	// resolution or admin bypass, so even a global-admin's token is bounded. Only
	// PAT-authenticated (user-actored) requests ever carry one, but the check is
	// safe on every path. Fails closed (deny) when the restriction disallows.
	if !patRestrictionFromContext(ctx).Allows(permission, scope) {
		return false, nil
	}
	if actorType == ActorTypeMachine {
		roleIDs, err := c.storage.GetMachineRoleIDsAt(ctx, principalID, scope)
		if err != nil {
			return false, err
		}
		if len(roleIDs) == 0 {
			return false, nil
		}
		return c.storage.RoleSetHasPermission(ctx, roleIDs, permission)
	}
	return c.Authorize(ctx, principalID, permission, scope)
}

// Authorize reports whether userID may exercise permission (e.g. "secrets.read")
// against the target scope. Fails closed: any resolution error returns
// (false, err).
func (c *KeyorixCore) Authorize(ctx context.Context, userID uint, permission string, scope Scope) (bool, error) {
	// PAT least-privilege filter (ADR-042) — narrows even an admin owner. Applied
	// here too (not only in AuthorizePrincipal) so direct Authorize callers and the
	// admin bypass below are equally bounded. Idempotent on the AuthorizePrincipal
	// path, which already checked it.
	if !patRestrictionFromContext(ctx).Allows(permission, scope) {
		return false, nil
	}
	roleIDs, err := c.scopedRoleIDs(ctx, userID, scope)
	if err != nil {
		return false, err
	}
	if len(roleIDs) == 0 {
		return false, nil
	}
	if c.roleSetContainsAdmin(ctx, roleIDs) {
		return true, nil
	}
	return c.storage.RoleSetHasPermission(ctx, roleIDs, permission)
}

// principalHasScopedPermission reports whether userID's OWN roles grant permission at
// scope, independent of any PAT restriction on the context (which belongs to the
// requesting actor, not this user). Use it to vet a THIRD party — e.g. a prospective
// secret owner — without the caller's token narrowing the result. Fails closed.
func (c *KeyorixCore) principalHasScopedPermission(ctx context.Context, userID uint, permission string, scope Scope) (bool, error) {
	roleIDs, err := c.scopedRoleIDs(ctx, userID, scope)
	if err != nil {
		return false, err
	}
	if len(roleIDs) == 0 {
		return false, nil
	}
	if c.roleSetContainsAdmin(ctx, roleIDs) {
		return true, nil
	}
	return c.storage.RoleSetHasPermission(ctx, roleIDs, permission)
}

// AuthorizeSecret checks whether userID may perform perm on the given secretID.
// It first checks any explicit SecretACL grant (RBAC Phase 3); if found and it covers
// perm, returns true immediately — the user need not hold a project role. Otherwise
// falls back to project-scope RBAC (Authorize at the secret's own project/environment
// scope). Fails closed: any resolution error returns (false, err).
func (c *KeyorixCore) AuthorizeSecret(ctx context.Context, userID, secretID uint, perm string) (bool, error) {
	// Resolve the secret first so we know its scope for the PAT check below.
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return false, err
	}
	scope := Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
	// PAT-SCOPE-002: a per-secret ACL grant must not let a project-scoped PAT read
	// secrets outside the token's own project/environment — check the restriction
	// against the secret's actual scope before honouring an ACL grant.
	if !patRestrictionFromContext(ctx).Allows(perm, scope) {
		return false, nil
	}
	// Check per-secret ACL (additive grant).
	hasACL, err := c.HasSecretACL(ctx, userID, secretID, perm)
	if err != nil {
		return false, err
	}
	if hasACL {
		return true, nil
	}
	// Fall back to project-scope RBAC.
	return c.Authorize(ctx, userID, perm, scope)
}

// AuthorizeSecretPrincipal is the actor-aware counterpart to AuthorizeSecret,
// mirroring AuthorizePrincipal's split between human users and machine
// identities (ADR-030). It is the entrypoint the per-secret HTTP routes use
// (RequireScopedSecretPermission) so a per-secret SecretACL grant (RBAC Phase 3)
// is honored for the ~15 GET/PUT/DELETE routes gated on a specific secret ID,
// not just the ListSecrets surface.
//
// SecretACL rows are inherently user-scoped (models.SecretACL.UserID; see
// secret_acl.go's GrantSecretACL, which requires the grantee to be a project
// member — a concept that doesn't apply to machine identities). A machine
// identity's principal ID lives in an entirely separate ID space/table from
// User, so treating it as a userID for the ACL lookup would risk an accidental
// match against an unrelated human's grant purely by numeric coincidence.
// Machine/OIDC-federated principals therefore always take the existing
// role-based AuthorizePrincipal path unchanged — byte-for-byte the behavior
// before this function existed. Fails closed.
func (c *KeyorixCore) AuthorizeSecretPrincipal(ctx context.Context, actorType string, principalID, secretID uint, permission string) (bool, error) {
	if actorType != ActorTypeMachine {
		return c.AuthorizeSecret(ctx, principalID, secretID, permission)
	}
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return false, err
	}
	scope := Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
	return c.AuthorizePrincipal(ctx, actorType, principalID, permission, scope)
}

// IsGlobalAdmin reports whether userID holds an admin role assigned globally
// (project 0, environment 0). Used to short-circuit scope-filtered listing.
//
// A request carrying a PAT least-privilege restriction (ADR-042) is never treated
// as an unrestricted global admin: the token was deliberately scoped below its
// owner, so a caller that uses this to return unfiltered data must instead fall
// back to the scope-filtered path. Returning false here is fail-closed — the
// filtered path can only ever return a subset — and keeps the restriction honoured
// on this otherwise un-funnelled authz path (it does not flow through Authorize).
func (c *KeyorixCore) IsGlobalAdmin(ctx context.Context, userID uint) (bool, error) {
	if patRestrictionFromContext(ctx) != nil {
		return false, nil
	}
	roleIDs, err := c.scopedRoleIDs(ctx, userID, Scope{})
	if err != nil {
		return false, err
	}
	return c.roleSetContainsAdmin(ctx, roleIDs), nil
}

// scopedRoleIDs returns the de-duplicated set of role IDs that apply to userID
// at the target scope, unioning direct assignments and group-inherited roles.
func (c *KeyorixCore) scopedRoleIDs(ctx context.Context, userID uint, scope Scope) ([]uint, error) {
	direct, err := c.storage.GetUserRoleIDsAt(ctx, userID, scope)
	if err != nil {
		return nil, err
	}
	viaGroups, err := c.storage.GetUserGroupRoleIDsAt(ctx, userID, scope)
	if err != nil {
		return nil, err
	}
	return dedupeUints(append(direct, viaGroups...)), nil
}

// roleSetContainsAdmin reports whether any role ID in the set is an admin role.
func (c *KeyorixCore) roleSetContainsAdmin(ctx context.Context, roleIDs []uint) bool { // nosemgrep: keyorix-unbounded-bulk-slice-param -- roleIDs is a principal's resolved current role set (scopedRoleIDs/GetUserRoleIDsAt), not a raw client-supplied array; every call site passes an internally-computed list
	if len(roleIDs) == 0 {
		return false
	}
	idSet := make(map[uint]struct{}, len(roleIDs))
	for _, id := range roleIDs {
		idSet[id] = struct{}{}
	}
	for _, name := range adminRoleNames {
		role, err := c.storage.GetRoleByName(ctx, name)
		if err != nil {
			continue // role not seeded in this deployment
		}
		if _, ok := idSet[role.ID]; ok {
			return true
		}
	}
	return false
}

// requireGlobalAdminToReinstateAdminRoles refuses to reinstate roleIDs unless
// actorID is themselves a global admin, but ONLY when roleIDs actually contains an
// admin-tier role — a non-admin role set passes untouched. Restoring a soft-deleted
// principal (a group, a project, an environment) brings back EVERY role grant it
// held atomically, in one step, with no per-role choice — unlike a single direct
// grant (requireAuthorityForRole, invitations.go), the restore may reinstate
// several roles at once, so the whole SET needs an aggregate ceiling check. Used
// by group/project/environment restore (#147/#161): a principal holding only the
// gating permission (roles.assign) — not admin authority itself — must not be able
// to resurrect an admin-conferring grant that was soft-deleted out from under them
// (e.g. an incident-response revocation), the same escalation-by-proxy shape
// requireAuthorityForRole closes for direct grants.
func (c *KeyorixCore) requireGlobalAdminToReinstateAdminRoles(ctx context.Context, actorID uint, roleIDs []uint, objectDesc string) error {
	if !c.roleSetContainsAdmin(ctx, roleIDs) {
		return nil
	}
	isAdmin, err := c.IsGlobalAdmin(ctx, actorID)
	if err != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	if !isAdmin {
		return fmt.Errorf("only an administrator can restore a %s holding an administrative role grant", objectDesc)
	}
	return nil
}

// ceilingCacheEntry is a single cached result of requireEqualOrGreaterAdminAuthority.
type ceilingCacheEntry struct {
	err       error
	expiresAt time.Time
}

const ceilingCacheTTL = 60 * time.Second

// cachedImpersonationCeiling wraps requireEqualOrGreaterAdminAuthority with a
// short-lived cache (ceilingCacheTTL) so the expensive DB reads it issues are
// not repeated on every ValidateSessionToken call (IMP-001). The cache TTL is
// intentionally 2× the auth-cache window so a cache miss here never triggers
// two consecutive uncached ceiling checks within the same outer auth-cache miss.
func (c *KeyorixCore) cachedImpersonationCeiling(ctx context.Context, actorID, targetID uint) error {
	key := fmt.Sprintf("%d:%d", actorID, targetID)
	if v, ok := c.impersonationCeilingCache.Load(key); ok {
		if entry := v.(ceilingCacheEntry); c.now().Before(entry.expiresAt) {
			return entry.err
		}
	}
	err := c.requireEqualOrGreaterAdminAuthority(ctx, actorID, targetID, "impersonate")
	c.impersonationCeilingCache.Store(key, ceilingCacheEntry{err: err, expiresAt: c.now().Add(ceilingCacheTTL)})
	return err
}

// requireMachinePrivilegeCeiling refuses to issue a token for machineID when the
// machine holds any admin-tier role and the actor is not a global admin (MACH-001).
// A token inherits the machine's roles, so issuing one is equivalent to granting
// the actor those roles — the same privilege-ceiling contract enforced for user
// impersonation and role grants.
func (c *KeyorixCore) requireMachinePrivilegeCeiling(ctx context.Context, actorID, machineID uint) error {
	roles, err := c.storage.GetMachineRoles(ctx, machineID)
	if err != nil {
		return fmt.Errorf("failed to check machine privilege ceiling: %w", err)
	}
	roleIDs := make([]uint, len(roles))
	for i, r := range roles {
		roleIDs[i] = r.ID
	}
	if !c.roleSetContainsAdmin(ctx, roleIDs) {
		return nil
	}
	isAdmin, err := c.IsGlobalAdmin(ctx, actorID)
	if err != nil {
		return fmt.Errorf("failed to verify actor authority: %w", err)
	}
	if !isAdmin {
		return fmt.Errorf("issuing a token for a machine identity that holds administrative roles requires administrative authority")
	}
	return nil
}

// requireEqualOrGreaterAdminAuthority refuses when targetID holds an admin-tier
// role — global OR project-scoped, direct OR group-inherited — at any scope where
// actorID does not ALSO hold admin-tier authority. Unlike the single-scope
// IsGlobalAdmin check, this discovers and checks EVERY scope the target actually
// holds a grant at (via GetUserRoleScopes), so a target who is a project-scoped
// project_admin — never itself flagged "global admin" — is still compared
// correctly. Used by impersonation's admin-rank-ceiling check (#165): the action
// string only customizes the error message (e.g. "impersonate").
func (c *KeyorixCore) requireEqualOrGreaterAdminAuthority(ctx context.Context, actorID, targetID uint, action string) error {
	scopes, err := c.storage.GetUserRoleScopes(ctx, targetID)
	if err != nil {
		return fmt.Errorf("failed to resolve target authority: %w", err)
	}
	for _, scope := range scopes {
		targetRoleIDs, err := c.scopedRoleIDs(ctx, targetID, scope)
		if err != nil {
			return fmt.Errorf("failed to resolve target authority: %w", err)
		}
		if !c.roleSetContainsAdmin(ctx, targetRoleIDs) {
			continue
		}
		actorRoleIDs, err := c.scopedRoleIDs(ctx, actorID, scope)
		if err != nil {
			return fmt.Errorf("failed to resolve actor authority: %w", err)
		}
		if !c.roleSetContainsAdmin(ctx, actorRoleIDs) {
			return fmt.Errorf("cannot %s a user holding administrative authority you do not also hold", action)
		}
	}
	return nil
}

// requireGranterHoldsRolePermissions refuses to GRANT roleID at scope unless the
// actor already holds, at that scope or broader, EVERY permission bundled into the
// role — the admin-rank-ceiling check on the GRANT step (#93/#107/#141), distinct
// from and complementary to #169's check on role DEFINITION. #169 only stops a
// roles.write holder from bundling a permission they don't hold into a role's
// definition; it does nothing to stop a roles.assign holder from GRANTING an
// already-defined, already-permission-rich role — including a pre-existing/seeded
// builtin like "editor" — to a third party (or to themselves) without holding any
// of its bundled permissions. c.Authorize already includes the admin-role bypass
// and resolves a broader (e.g. global) grant the actor holds at a narrower target
// scope, so a genuine admin, or an actor who already holds every bundled
// permission at an equal-or-broader scope, is unaffected.
//
// actorID 0 is the established "system" pseudo-actor for genuinely non-attacker-
// reachable callers (the local CLI's AssignRoleToUser); skipped exactly like
// #169's analogous check on AssignPermissionToRole.
func (c *KeyorixCore) requireGranterHoldsRolePermissions(ctx context.Context, actorID, roleID uint, scope Scope) error {
	if actorID == 0 {
		return nil
	}
	perms, err := c.storage.GetRolePermissions(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to resolve role permissions: %w", err)
	}
	for _, p := range perms {
		ok, aerr := c.Authorize(ctx, actorID, p.Name, scope)
		if aerr != nil {
			return fmt.Errorf("failed to resolve actor authority: %w", aerr)
		}
		if !ok {
			return fmt.Errorf("cannot grant this role: you do not hold permission %q yourself", p.Name)
		}
	}
	return nil
}

// groupHoldsGlobalAdminRole reports whether groupID carries a LIVE global-scope
// (project 0, environment 0) grant of any role in adminIDs, per the pre-fetched
// assignments — the cheap relevance check every group-path last-admin guard (#107)
// runs first: a mutation touching a group with no admin-tier grant at all can
// never strand the install, so there is nothing to compute or refuse.
func groupHoldsGlobalAdminRole(assignments []storage.RoleAssignment, adminIDs map[uint]bool, groupID uint) bool {
	for _, a := range assignments {
		if a.PrincipalType == "group" && a.PrincipalID == groupID && adminIDs[a.RoleID] {
			return true
		}
	}
	return false
}

// resolveGlobalAdminHolders expands the given global-scope assignments (both
// direct user grants and group grants, the latter to their live members) into the
// set of user IDs who hold admin-tier authority, after applying the optional
// exclusions. Backs the group-path last-admin guards (#107): unlike
// guardLastGlobalAdmin's simpler "does another assignment ROW exist" check
// (sufficient when the removal itself deletes the admin-conferring row), removing
// a single user from a group leaves the group's own role grant row intact — only
// that one member's DERIVED authority disappears — so the check must expand group
// grants to their actual live members, not just count rows.
//
//   - excludeAssignment, when non-nil, drops every assignment row it matches:
//     the one (group, role) grant being removed (RemoveRoleFromGroup), or every
//     row belonging to a group being deleted (DeleteGroup).
//   - excludeMember, when non-nil, drops one specific (groupID, userID) member
//     expansion while leaving the group's grant — and its OTHER members' derived
//     authority — intact (RemoveUserFromGroup).
//
// Any storage error is returned, never swallowed: silently under-counting here
// only makes the guard MORE likely to refuse (fail closed), but silently mis-
// resolving a group's membership on a real error could do the opposite.
//
// #G03: a role/group ASSIGNMENT row surviving is not the same as the holder
// actually being usable as a fallback admin — deactivating (SCIM/DeleteUser/
// SuspendUser) never removes the UserRole/GroupRole grant, only the user's
// IsActive flag or deleted_at. Without filtering by current active status, this
// function could report a just-deactivated (or already-deleted) user as "another
// admin survives" purely because their stale grant row is still there —
// letting the LAST two admins each be deactivated one after another (or
// concurrently), not just the intended "one may go, one must remain."
func (c *KeyorixCore) resolveGlobalAdminHolders(ctx context.Context, adminIDs map[uint]bool, assignments []storage.RoleAssignment, excludeAssignment func(storage.RoleAssignment) bool, excludeMember func(groupID, userID uint) bool) (map[uint]bool, error) {
	holders := make(map[uint]bool)
	for _, a := range assignments {
		if !adminIDs[a.RoleID] {
			continue
		}
		if excludeAssignment != nil && excludeAssignment(a) {
			continue
		}
		switch a.PrincipalType {
		case "user":
			holders[a.PrincipalID] = true
		case "group":
			if err := c.resolveGroupAdminMembers(ctx, a.PrincipalID, excludeMember, holders); err != nil {
				return nil, err
			}
		}
	}
	return c.filterActiveHolders(ctx, holders)
}

// filterActiveHolders drops every holder whose account is no longer usable as a
// fallback admin (soft-deleted, or IsActive=false) — see resolveGlobalAdminHolders'
// #G03 doc comment above for why a surviving grant ROW is not sufficient on its own.
func (c *KeyorixCore) filterActiveHolders(ctx context.Context, holders map[uint]bool) (map[uint]bool, error) {
	for id := range holders {
		user, err := c.storage.GetUser(ctx, id)
		if err != nil {
			if isNotFound(err) {
				// Soft-deleted: GetUser's default scope excludes it — this holder no
				// longer counts, but is not itself an error.
				delete(holders, id)
				continue
			}
			return nil, err
		}
		if !user.IsActive {
			delete(holders, id)
		}
	}
	return holders, nil
}

func (c *KeyorixCore) resolveGroupAdminMembers(ctx context.Context, groupID uint, excludeMember func(groupID, userID uint) bool, holders map[uint]bool) error {
	members, merr := c.storage.ListGroupMembers(ctx, groupID)
	if merr != nil {
		return fmt.Errorf("failed to resolve group %d membership: %w", groupID, merr)
	}
	for _, m := range members {
		if excludeMember != nil && excludeMember(groupID, m.ID) {
			continue
		}
		holders[m.ID] = true
	}
	return nil
}

// guardLastGlobalAdminGroupRole is guardLastGlobalAdmin's group-role-removal
// counterpart (#107): refuses to remove roleID from groupID at the global scope
// when doing so would leave the install with zero global admin-tier holders.
func (c *KeyorixCore) guardLastGlobalAdminGroupRole(ctx context.Context, groupID, roleID uint, scope Scope) error {
	if scope.ProjectID != 0 || scope.EnvironmentID != 0 {
		return nil // not the global scope — project admins are recoverable
	}
	adminIDs := c.installAdminRoleIDSet(ctx)
	if !adminIDs[roleID] {
		return nil // not removing an install-admin role
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to resolve global role assignments: %w", err)
	}
	holders, err := c.resolveGlobalAdminHolders(ctx, adminIDs, assignments, func(a storage.RoleAssignment) bool {
		return a.PrincipalType == "group" && a.PrincipalID == groupID && a.RoleID == roleID
	}, nil)
	if err != nil {
		return err
	}
	if len(holders) == 0 {
		return fmt.Errorf("refusing to remove role %d from group %d: the install would be left with no super_admin/admin/system_admin at the global scope and no one able to manage users, roles, or settings", roleID, groupID)
	}
	return nil
}

// guardLastGlobalAdminGroupDelete is guardLastGlobalAdmin's group-deletion
// counterpart (#107): refuses to delete groupID when it holds a global admin-tier
// role and doing so would leave the install with zero admin-tier holders —
// deleting a group cascades to remove EVERY role grant it holds, not just one. A
// group with no admin-tier grant at all is never blocked, regardless of the
// install's overall admin count.
func (c *KeyorixCore) guardLastGlobalAdminGroupDelete(ctx context.Context, groupID uint) error {
	adminIDs := c.installAdminRoleIDSet(ctx)
	if len(adminIDs) == 0 {
		return nil // no install-admin role seeded — nothing to guard
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to resolve global role assignments: %w", err)
	}
	if !groupHoldsGlobalAdminRole(assignments, adminIDs, groupID) {
		return nil // this group carries no admin-tier grant — irrelevant to the guard
	}
	holders, err := c.resolveGlobalAdminHolders(ctx, adminIDs, assignments, func(a storage.RoleAssignment) bool {
		return a.PrincipalType == "group" && a.PrincipalID == groupID
	}, nil)
	if err != nil {
		return err
	}
	if len(holders) == 0 {
		return fmt.Errorf("refusing to delete group %d: it holds the install's last administrative role grant, and deleting it would leave no super_admin/admin/system_admin at the global scope", groupID)
	}
	return nil
}

// guardLastGlobalAdminMembership is guardLastGlobalAdmin's group-membership-
// removal counterpart (#107): refuses to remove userID from groupID when the
// group's admin-tier grant is userID's only remaining route to global admin-tier
// authority and no other user holds one either. The group's grant row survives
// this removal, so — unlike the other two guards — this can't be answered by
// excluding an assignment row; it must exclude just this one member's derived
// authority via this one group. A group with no admin-tier grant at all is never
// blocked, regardless of the install's overall admin count.
func (c *KeyorixCore) guardLastGlobalAdminMembership(ctx context.Context, userID, groupID uint) error {
	adminIDs := c.installAdminRoleIDSet(ctx)
	if len(adminIDs) == 0 {
		return nil // no install-admin role seeded — nothing to guard
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to resolve global role assignments: %w", err)
	}
	if !groupHoldsGlobalAdminRole(assignments, adminIDs, groupID) {
		return nil // this group carries no admin-tier grant — irrelevant to the guard
	}
	holders, err := c.resolveGlobalAdminHolders(ctx, adminIDs, assignments, nil, func(gID, uID uint) bool {
		return gID == groupID && uID == userID
	})
	if err != nil {
		return err
	}
	if len(holders) == 0 {
		return fmt.Errorf("refusing to remove user %d from group %d: they may be the install's last administrator via this group's role grant, and removing them would leave no super_admin/admin/system_admin at the global scope", userID, groupID)
	}
	return nil
}

// GetReadableScopes returns every (project, environment) scope at which userID
// holds the given permission, directly or via group membership. It is used by
// ListSecrets to enumerate the scopes a project-scoped reader can access when
// no explicit project_id/environment_id filter is provided and the user lacks a
// global grant. The global scope ({0,0}) is deliberately excluded — callers
// check that first and fall back here only when the global check fails.
//
// PAT restrictions are honoured: a PAT that is itself narrowed to one project
// will receive at most that project's scopes from this function.
//
// Any storage error is returned unchanged; the caller fails closed (returns an
// empty list to the user rather than a 500).
func (c *KeyorixCore) GetReadableScopes(ctx context.Context, userID uint, permission string) ([]Scope, error) {
	allScopes, err := c.storage.GetUserRoleScopes(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate user scopes: %w", err)
	}

	var result []Scope
	for _, scope := range allScopes {
		if scope.ProjectID == 0 {
			// Global scope handled by caller; skip.
			continue
		}
		ok, aerr := c.Authorize(ctx, userID, permission, scope)
		if aerr != nil {
			// Fail closed: skip scopes we cannot evaluate.
			continue
		}
		if ok {
			result = append(result, scope)
		}
	}
	return result, nil
}

// dedupeUints returns ids with duplicates removed, preserving first-seen order.
func dedupeUints(ids []uint) []uint {
	if len(ids) <= 1 {
		return ids
	}
	seen := make(map[uint]struct{}, len(ids))
	out := ids[:0:0]
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
