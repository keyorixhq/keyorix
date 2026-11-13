package authzdiff

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
)

// The reference model (Oracle 2). It reads the grant tables of the iteration's
// database directly — never through core or storage code — and answers "does
// this principal hold these permissions at this scope", the same question
// core.Authorize answers, from the role's ACTUAL permissions:
//
//   - a grant applies to a target project P if its project is 0 (global) or P;
//     a target of 0 (global) is satisfied only by global grants;
//   - an expired grant, or a grant on a soft-deleted project, does not apply;
//   - a user's grants are direct (user_roles) plus via live groups
//     (user_groups -> group_roles); a machine's are machine_identity_roles;
//   - a role with bypasses_permission_checks satisfies any permission for a
//     USER; a machine never gets that override (ADR-030);
//   - a role grant (ceiling) additionally needs every permission the granted
//     role bundles, at the target scope (the FIX-1 rule: derived from the
//     role's permissions, never its name).
//
// Environment-scoped grants are not modelled: the harness never creates one.
// PAT restrictions (ADR-042: the PAT principal's restriction narrows each
// permission check, plus core's restricted-PAT ungated-write table) and
// account state (a suspended principal may do nothing) ARE modelled.
// What it does NOT model: ownership/share/ACL-based secret access beyond the
// documented owner rules (secret op args 1-3 are recorded as model n/a), and
// MFA (no fixture project requires it). The machine-token target check
// (machineCovers) treats only the bypass flag as admin-tier: the fixture's
// target machines hold project_auditor, which is admin-tier by none of core's
// tests, so the name- and bundle-based variants are not exercised.

type grant struct {
	roleID    uint
	projectID uint
	expires   *time.Time
	// viaMemberAt: the grant comes from a group membership scoped to this
	// project (user_groups.project_id); 0 = a direct grant or a global membership.
	// A project-scoped membership confers the group's roles only in that project
	// (models.UserGroup), so a grant with viaMemberAt != 0 does not apply elsewhere.
	viaMemberAt uint
}

// appliesAt reports whether the grant can apply when the target is project proj.
func (g grant) appliesAt(proj uint) bool { return g.viaMemberAt == 0 || g.viaMemberAt == proj }

type model struct{ db *gorm.DB }

func (m model) grants(p *principal) []grant {
	var out []grant
	if p.machineID != 0 {
		rows, err := m.db.Raw(`SELECT role_id, project_id FROM machine_identity_roles WHERE machine_identity_id = ? AND environment_id = 0`, p.machineID).Rows()
		if err == nil {
			for rows.Next() {
				var g grant
				_ = rows.Scan(&g.roleID, &g.projectID)
				out = append(out, g)
			}
			_ = rows.Close()
		}
		return out
	}
	if p.userID == 0 {
		return nil
	}
	rows, err := m.db.Raw(`SELECT role_id, project_id, expires_at, 0 AS via FROM user_roles WHERE user_id = ? AND environment_id = 0
		UNION ALL
		SELECT gr.role_id, gr.project_id, gr.expires_at, ug.project_id AS via FROM group_roles gr
		  JOIN user_groups ug ON ug.group_id = gr.group_id
		  JOIN groups g ON g.id = gr.group_id AND g.deleted_at IS NULL
		 WHERE ug.user_id = ? AND gr.environment_id = 0`, p.userID, p.userID).Rows()
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var g grant
		_ = rows.Scan(&g.roleID, &g.projectID, &g.expires, &g.viaMemberAt)
		out = append(out, g)
	}
	return out
}

func (m model) projectLive(id uint) bool {
	if id == 0 {
		return true
	}
	var n int64
	m.db.Raw(`SELECT COUNT(*) FROM projects WHERE id = ? AND deleted_at IS NULL`, id).Scan(&n)
	return n > 0
}

func (m model) rolePerms(roleID uint) (perms []string, adminRole bool) {
	m.db.Raw(`SELECT p.name FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = ?`, roleID).Scan(&perms)
	m.db.Raw(`SELECT bypasses_permission_checks FROM roles WHERE id = ?`, roleID).Scan(&adminRole)
	return perms, adminRole
}

// holds reports whether p holds perm at target project proj (0 = global).
func (m model) holds(p *principal, perm string, proj uint) bool {
	now := time.Now().UTC()
	for _, g := range m.grants(p) {
		if g.projectID != 0 && g.projectID != proj {
			continue
		}
		if !g.appliesAt(proj) {
			continue
		}
		if g.expires != nil && !g.expires.After(now) {
			continue
		}
		if !m.projectLive(g.projectID) {
			continue
		}
		perms, adminRole := m.rolePerms(g.roleID)
		if (adminRole && p.machineID == 0) || slices.Contains(perms, perm) {
			return true
		}
	}
	return false
}

// allowed is the model's decision for (principal, requirement).
func (m model) allowed(p *principal, req requirement) bool {
	if p.unauthenticated {
		return false
	}
	if p.systemActor {
		return true // actor id 0: core's trusted internal caller (intended difference ID-1)
	}
	if p.suspended {
		return false // a suspended account may do nothing (account_state.go)
	}
	for _, perm := range req.perms {
		if !m.holds(p, perm, req.scope) {
			return false
		}
		// A PAT narrows its owner (ADR-042, rules.PATRestriction.Allows) on the
		// permission check; the grant ceiling reads the principal's OWN roles,
		// independent of the PAT (authz.go principalHasScopedPermission).
		if p.pat != nil && !p.pat.Allows(perm, core.Scope{ProjectID: req.scope}) {
			return false
		}
	}
	for _, perm := range req.globalPerms {
		if !m.holds(p, perm, 0) || (p.pat != nil && !p.pat.Allows(perm, core.Scope{})) {
			return false
		}
	}
	if req.memberOnly && (p.machineID != 0 || p.userID == 0 || !m.memberOf(p, req.scope)) {
		// break-glass activate: only a USER who is a member of the project NOW.
		return false
	}
	if req.requesterUserID != 0 && p.userID != req.requesterUserID {
		// documented requester-only rule (WithdrawAccessRequest: "not your" → refused)
		return false
	}
	if req.recipientUserIDs != nil && (p.userID == 0 || !slices.Contains(req.recipientUserIDs, p.userID)) {
		// documented recipient-only rule (RemoveSelfFromShare deletes only a direct
		// share whose recipient is the caller; no permission is involved)
		return false
	}
	if req.globalAdminRole && !m.holdsAdminRoleAt(p, 0) {
		// documented: binding an OIDC subject "requires install-wide admin
		// authority" (CreateOIDCBinding → requireAdminAuthorityAt(actor, 0))
		return false
	}
	if req.ownerUserID != 0 {
		// documented owner rules (ErrShareNotOwner / ErrShareOwnerNotMember,
		// internal/core/share_authz.go): only the owner, and only while holding
		// a live PROJECT-scoped grant there — a global role makes nobody a member.
		// a machine caller reaches core as actor 0, which the manager path
		// refuses (revokerMayManageSecret), so only a user can take it.
		manager := req.ownerOrPerm != "" && p.machineID == 0 && p.userID != req.ownerUserID && m.holds(p, req.ownerOrPerm, req.scope) &&
			(p.pat == nil || p.pat.Allows(req.ownerOrPerm, core.Scope{ProjectID: req.scope}))
		if !manager && (p.userID != req.ownerUserID || !m.memberOf(p, req.scope)) {
			return false
		}
	}
	if req.tokenForMachineID != 0 && p.machineID != 0 && !m.machineCovers(p, req.tokenForMachineID) {
		return false
	}
	for _, r := range req.ceiling {
		perms, _ := m.rolePerms(r.roleID)
		for _, perm := range perms {
			if !m.holds(p, perm, r.scope) {
				return false
			}
		}
	}
	return true
}

// machineCovers: machine caller p may control target's credential (see
// requirement.tokenForMachineID). The target's grants are read from the
// grant tables like any principal's.
func (m model) machineCovers(p *principal, target uint) bool {
	if p.machineID == target {
		return false
	}
	for _, g := range m.grants(&principal{machineID: target}) {
		perms, adminRole := m.rolePerms(g.roleID)
		if adminRole {
			return false
		}
		for _, perm := range perms {
			if !m.holds(p, perm, g.projectID) {
				return false
			}
		}
	}
	return true
}

// memberOf: p holds a live, unexpired grant scoped to project proj itself.
func (m model) memberOf(p *principal, proj uint) bool {
	now := time.Now().UTC()
	for _, g := range m.grants(p) {
		if g.projectID == proj && proj != 0 && g.appliesAt(proj) && (g.expires == nil || g.expires.After(now)) && m.projectLive(proj) {
			return true
		}
	}
	return false
}

// roleAt is one role an op grants, at the scope it will be held.
type roleAt struct{ roleID, scope uint }

// requirement is what an op needs for one concrete (target) call.
type requirement struct {
	perms   []string
	scope   uint     // project id the perms are checked at, 0 = global
	ceiling []roleAt // roles the op grants (a group join grants all the group's roles); nil = not a grant
	// ownerUserID != 0: a documented owner-only rule applies (see allowed).
	ownerUserID uint
	// ownerOrPerm, with ownerUserID: a NON-owner USER holding this permission
	// at scope satisfies the owner rule instead (RevokeShare: secrets.manage,
	// revokerMayManageSecret). The owner itself still needs live membership.
	ownerOrPerm string
	// globalPerms are additionally required at GLOBAL scope (a route gated at
	// two scopes, e.g. migrate-from-user: roles.assign@project + users.write@global).
	globalPerms []string
	// requesterUserID != 0: only that user may act (access-request withdraw).
	requesterUserID uint
	// globalAdminRole: the actor must hold an admin role (bypasses_permission_checks) at global scope.
	globalAdminRole bool
	// recipientUserIDs non-nil: only these users may act (self-share removal).
	recipientUserIDs []uint
	// memberOnly: the op has NO permission gate — eligibility is project
	// membership alone (break-glass activate: core.ActivateBreakGlass →
	// IsProjectMember, a role scoped to THIS project, direct or via a live group;
	// a global/install-wide role is NOT membership — the #284-era fix). A machine
	// actor reaches core as userID==0 and is refused with a validation error, not
	// a permission denial, so the model denies it here and the untyped-core
	// refusal is absorbed by known-09 at the partition.
	memberOnly bool
	// tokenForMachineID != 0: the op mints a credential for that machine. A
	// MACHINE caller must then cover the target (#3993): it is not the target
	// itself, the target holds no role that bypasses permission checks, and the
	// caller holds every permission of every role the target holds, at the
	// scope the target holds it. A user caller is not checked against it.
	tokenForMachineID uint
}

// holdsAdminRoleAt: p holds a live, unexpired admin role granted exactly at proj.
// Machines never hold the override.
func (m model) holdsAdminRoleAt(p *principal, proj uint) bool {
	if p.machineID != 0 {
		return false
	}
	now := time.Now().UTC()
	for _, g := range m.grants(p) {
		if g.projectID != proj || !g.appliesAt(proj) || (g.expires != nil && !g.expires.After(now)) {
			continue
		}
		if _, adminRole := m.rolePerms(g.roleID); adminRole {
			return true
		}
	}
	return false
}

// patRefusesUngatedWrite applies the documented restricted-PAT rule for writes
// no permission gate covers (ADR-042, PAT-GUARD-3): core's own table
// (core.RestrictedPATWriteRefusal), keyed by the op's matrix route — the same
// key the REST middleware looks up. Model-only: this file never decides which
// layer enforces it.
func patRefusesUngatedWrite(tb testing.TB, fx *fixtures, spec opSpec, p *principal) bool {
	if p.pat == nil {
		return false
	}
	route := opRouteKey(tb, fx, spec)
	return route != "" && core.RestrictedPATWriteRefusal(route) != nil
}

var (
	routeKeyMu    sync.Mutex
	routeKeyCache = map[string]string{}
	allRESTRoutes []string
)

// opRouteKey is the matrix route ("POST /api/v1/...") the op's REST request matches.
func opRouteKey(tb testing.TB, fx *fixtures, spec opSpec) string {
	routeKeyMu.Lock()
	defer routeKeyMu.Unlock()
	if r, ok := routeKeyCache[spec.name]; ok {
		return r
	}
	if allRESTRoutes == nil {
		b, err := os.ReadFile("matrix.json")
		if err != nil {
			tb.Fatalf("matrix.json: %v", err)
		}
		var m struct {
			Ops []matrixOp `json:"ops"`
		}
		_ = json.Unmarshal(b, &m)
		for _, op := range m.Ops {
			if op.Layer == "rest" {
				allRESTRoutes = append(allRESTRoutes, strings.TrimPrefix(op.Key, "REST "))
			}
		}
	}
	r := opRoute(fx, spec, allRESTRoutes)
	routeKeyCache[spec.name] = r
	return r
}
