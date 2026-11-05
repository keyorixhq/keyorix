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
//     USER; a machine never bypasses (ADR-030);
//   - a role grant (ceiling) additionally needs every permission the granted
//     role bundles, at the target scope (the FIX-1 rule: derived from the
//     role's permissions, never its name).
//
// Environment-scoped grants are not modelled: the harness never creates one.
// What it does NOT model: ownership/share/ACL-based secret access (fixture
// secrets are owned by the admin and carry no shares/ACLs for the probed
// principal), MFA (no fixture project requires it), PAT restrictions (no PATs),
// and account state (every fixture principal is active). An op whose outcome
// depends on one of those is out of the model's domain and says so in its spec.

type grant struct {
	roleID    uint
	projectID uint
	expires   *time.Time
}

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
	rows, err := m.db.Raw(`SELECT role_id, project_id, expires_at FROM user_roles WHERE user_id = ? AND environment_id = 0
		UNION ALL
		SELECT gr.role_id, gr.project_id, gr.expires_at FROM group_roles gr
		  JOIN user_groups ug ON ug.group_id = gr.group_id
		  JOIN groups g ON g.id = gr.group_id AND g.deleted_at IS NULL
		 WHERE ug.user_id = ? AND gr.environment_id = 0`, p.userID, p.userID).Rows()
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var g grant
		_ = rows.Scan(&g.roleID, &g.projectID, &g.expires)
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

func (m model) rolePerms(roleID uint) (perms []string, bypass bool) {
	m.db.Raw(`SELECT p.name FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = ?`, roleID).Scan(&perms)
	m.db.Raw(`SELECT bypasses_permission_checks FROM roles WHERE id = ?`, roleID).Scan(&bypass)
	return perms, bypass
}

// holds reports whether p holds perm at target project proj (0 = global).
func (m model) holds(p *principal, perm string, proj uint) bool {
	now := time.Now().UTC()
	for _, g := range m.grants(p) {
		if g.projectID != 0 && g.projectID != proj {
			continue
		}
		if g.expires != nil && !g.expires.After(now) {
			continue
		}
		if !m.projectLive(g.projectID) {
			continue
		}
		perms, bypass := m.rolePerms(g.roleID)
		if (bypass && p.machineID == 0) || slices.Contains(perms, perm) {
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
	if req.requesterUserID != 0 && p.userID != req.requesterUserID {
		// documented requester-only rule (WithdrawAccessRequest: "not your" → refused)
		return false
	}
	if req.globalAdminRole && !m.holdsBypassAt(p, 0) {
		// documented: binding an OIDC subject "requires install-wide admin
		// authority" (CreateOIDCBinding → requireAdminAuthorityAt(actor, 0))
		return false
	}
	if req.ownerUserID != 0 {
		// documented owner rules (ErrShareNotOwner / ErrShareOwnerNotMember,
		// internal/core/share_authz.go): only the owner, and only while holding
		// a live PROJECT-scoped grant there — a global role makes nobody a member.
		if p.userID != req.ownerUserID || !m.memberOf(p, req.scope) {
			return false
		}
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

// memberOf: p holds a live, unexpired grant scoped to project proj itself.
func (m model) memberOf(p *principal, proj uint) bool {
	now := time.Now().UTC()
	for _, g := range m.grants(p) {
		if g.projectID == proj && proj != 0 && (g.expires == nil || g.expires.After(now)) && m.projectLive(proj) {
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
	// globalPerms are additionally required at GLOBAL scope (a route gated at
	// two scopes, e.g. migrate-from-user: roles.assign@project + users.write@global).
	globalPerms []string
	// requesterUserID != 0: only that user may act (access-request withdraw).
	requesterUserID uint
	// globalAdminRole: the actor must hold an admin (bypass) role at global scope.
	globalAdminRole bool
}

// withoutPerm is req with perm dropped from its gate permissions (both
// scopes). The ceiling is unchanged: it is derived from the granted roles.
func withoutPerm(req requirement, perm string) requirement {
	drop := func(ps []string) []string {
		return slices.DeleteFunc(slices.Clone(ps), func(p string) bool { return p == perm })
	}
	req.perms = drop(req.perms)
	req.globalPerms = drop(req.globalPerms)
	return req
}

// holdsBypassAt: p holds a live, unexpired bypass role granted exactly at proj.
// Machines never bypass.
func (m model) holdsBypassAt(p *principal, proj uint) bool {
	if p.machineID != 0 {
		return false
	}
	now := time.Now().UTC()
	for _, g := range m.grants(p) {
		if g.projectID != proj || (g.expires != nil && !g.expires.After(now)) {
			continue
		}
		if _, bypass := m.rolePerms(g.roleID); bypass {
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
