// secret_access_list.go — the effective access list for a secret: every USER who can
// read it and at what level, resolved across ownership, project roles, per-secret ACLs,
// direct user shares and group shares (group membership expanded). For a project
// member that level is max(role permission, active share permission) (#2941), so a
// share that elevates a role is visible as such. A least-privilege / access-review aid
// ("who can read secret X?"). Read-only; the caller must be able to read the secret.
// Expired shares, and shares to users who are not project members, grant nothing and
// are not listed, matching enforcement. Holders of a global (install-wide) role have
// implicit access and are not enumerated.
package core

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SecretAccessor is one user with effective access to a secret.
type SecretAccessor struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	// Permission is the EFFECTIVE level: the highest of everything below (#2941:
	// max(role permission, active share permission), plus ownership and ACLs).
	Permission string `json:"permission"` // read | write | owner
	// Source is the grant that gives Permission: owner | role | acl | direct_share |
	// group_share:<group>. When several give the same level, the first in that order.
	Source string `json:"source"`
	// Grants lists every grant the user holds on the secret with its level, e.g.
	// ["role:read", "direct_share:write"], so a share that elevates a role is visible.
	Grants []string `json:"grants"`
}

// SecretAccessorsResult is the effective access list for a secret plus a signal for
// whether it is complete. #417: on storage.type: remote, ListGroupMembers is
// unconditionally unimplemented, so every group-share accessor was silently
// omitted from this incident-response-critical "who can access secret X" report
// with no indication anything was missing. Degraded + DegradedReasons make that
// detectable instead of the result silently looking like a complete accessor
// list — mirroring CompliancePosture.Degraded (compliance_posture.go) and
// DashboardStats.Degraded (dashboard.go, #394).
type SecretAccessorsResult struct {
	Accessors []SecretAccessor `json:"accessors"`
	// Degraded is true when at least one group's membership could not be
	// resolved — Accessors is then an UNDER-count (missing group members), never
	// verified-complete.
	Degraded bool `json:"degraded"`
	// DegradedReasons names each group whose membership failed to resolve, with
	// the underlying error.
	DegradedReasons []string `json:"degraded_reasons,omitempty"`
}

// degrade records that a group's membership could not be resolved: it flips
// Degraded and appends a human-readable reason, mirroring
// CompliancePosture.degrade (compliance_posture.go).
func (r *SecretAccessorsResult) degrade(area string, err error) {
	r.Degraded = true
	r.DegradedReasons = append(r.DegradedReasons, fmt.Sprintf("%s: %v", area, err))
}

var permissionRank = map[string]int{"read": 1, "write": 2, "owner": 3}

// ListSecretAccessors returns the distinct users with effective access to secretID,
// sorted by username, plus whether the list is known-complete. The actor must be able
// to read the secret.
//
// Candidates are the owner, the share recipients (group shares expanded), the
// project's members (direct or group role grants) and the per-secret ACL holders.
// Each candidate's level is computed from the same terms AuthorizeSecret decides with
// — role at the secret's scope, per-secret ACL, and the share term with its
// membership rule (sharePermissionFor) — so a share to a non-member, or an expired
// one, is not listed, and a share that elevates a role shows as the higher level.
// It evaluates other users, so the caller's PAT restriction does not apply
// (principalHasScopedPermission), and nothing is audited: this is a report, not an
// access. Not listed: holders of a GLOBAL role (global admins have implicit access)
// and ACLs inherited from a parent folder.
func (c *KeyorixCore) ListSecretAccessors(ctx context.Context, secretID, actorID uint) (*SecretAccessorsResult, error) { // NOSONAR -- cognitive complexity, suppress go:S3776
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	result := &SecretAccessorsResult{}

	userNames := map[uint]string{}
	var candidates []uint
	addCandidate := func(id uint) {
		if id == 0 {
			return
		}
		if _, seen := userNames[id]; !seen {
			userNames[id] = ""
			candidates = append(candidates, id)
		}
	}
	addCandidate(secret.OwnerID)

	shares, err := c.storage.ListSharesBySecret(ctx, secretID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	groupNameByShare := map[uint]string{}
	for _, sh := range activeShares(shares, c.shareEffectiveNow()) {
		if !sh.IsGroup {
			addCandidate(sh.RecipientID)
			continue
		}
		gname := fmt.Sprintf("group %d", sh.RecipientID)
		if g, err := c.storage.GetGroup(ctx, sh.RecipientID); err == nil && g != nil && g.Name != "" {
			gname = g.Name
		}
		groupNameByShare[sh.ID] = gname
		members, err := c.storage.ListGroupMembers(ctx, sh.RecipientID)
		if err != nil {
			// #417: a group whose membership can't be resolved (deterministically
			// every group on storage.type: remote, where ListGroupMembers is
			// unimplemented) must not silently vanish from this report — record
			// it as an explicit gap instead of continuing unflagged.
			result.degrade(fmt.Sprintf("group_members:group=%d(%s)", sh.RecipientID, gname), err)
			continue
		}
		for _, m := range members {
			addCandidate(m.ID)
			userNames[m.ID] = m.Username // already loaded; prime the cache
		}
	}
	// The project's role-holders are its member roster. Only a caller who may already
	// read the project's members (users.read at the project, the gate of
	// GET /projects/{id}/members) gets it here; a secrets.read-only caller keeps the
	// owner, share and ACL listing and sees the gap flagged, never a roster they could
	// not otherwise read.
	if canRoster, err := c.Authorize(ctx, actorID, "users.read", Scope{ProjectID: secret.ProjectID}); err != nil {
		result.degrade("project_members", err)
	} else if !canRoster {
		result.degrade("project_members", errors.New("project members are not listed: the caller lacks users.read in the project"))
	} else if members, err := c.shareRecipientCandidates(ctx, secret.ProjectID); err != nil {
		result.degrade("project_members", err)
	} else {
		for _, id := range members {
			addCandidate(id)
		}
	}
	if acls, err := c.storage.ListSecretACLs(ctx, secretID); err != nil {
		result.degrade("secret_acls", err)
	} else {
		for _, a := range acls {
			addCandidate(a.UserID)
		}
	}

	out := make([]SecretAccessor, 0, len(candidates))
	for _, uid := range candidates {
		acc, ok := c.effectiveSecretAccess(ctx, secret, uid, groupNameByShare, result)
		if !ok {
			continue
		}
		acc.Username = userNames[uid]
		if acc.Username == "" {
			acc.Username = fmt.Sprintf("user %d", uid)
			if u, err := c.storage.GetUser(ctx, uid); err == nil && u != nil && u.Username != "" {
				acc.Username = u.Username
			}
		}
		out = append(out, acc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	result.Accessors = out
	return result, nil
}

// effectiveSecretAccess computes one user's grants on secret. ok is false when the
// user has none. A resolution error degrades the report (the user may be missing or
// under-counted) instead of failing it.
func (c *KeyorixCore) effectiveSecretAccess(ctx context.Context, secret *models.SecretNode, uid uint, groupNameByShare map[uint]string, result *SecretAccessorsResult) (SecretAccessor, bool) {
	acc := SecretAccessor{UserID: uid, Grants: []string{}}
	grant := func(level, source string) {
		acc.Grants = append(acc.Grants, source+":"+level)
		if permissionRank[level] > permissionRank[acc.Permission] {
			acc.Permission, acc.Source = level, source
		}
	}
	if secret.OwnerID == uid {
		acc.Permission, acc.Source = "owner", "owner"
		acc.Grants = append(acc.Grants, "owner")
	}
	scope := Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
	for _, lvl := range []struct{ perm, level string }{{permSecretsWrite, "write"}, {permSecretsRead, "read"}} {
		ok, err := c.principalHasScopedPermission(ctx, uid, lvl.perm, scope)
		if err != nil {
			result.degrade(fmt.Sprintf("role:user=%d", uid), err)
			break
		}
		if ok {
			grant(lvl.level, "role")
			break
		}
	}
	for _, lvl := range []struct{ perm, level string }{{permSecretsWrite, "write"}, {permSecretsRead, "read"}} {
		ok, err := c.HasSecretACL(ctx, uid, secret.ID, lvl.perm)
		if err != nil {
			result.degrade(fmt.Sprintf("acl:user=%d", uid), err)
			break
		}
		if ok {
			grant(lvl.level, "acl")
			break
		}
	}
	for _, need := range []PermissionLevel{PermissionWrite, PermissionRead} {
		g, err := c.sharePermissionFor(ctx, uid, secret.ID, secret.ProjectID, need)
		if err != nil {
			result.degrade(fmt.Sprintf("share:user=%d", uid), err)
			break
		}
		if g.Level == PermissionNone {
			continue
		}
		source := g.Source
		if g.Source == "group_share" && g.ShareID != nil {
			if name, ok := groupNameByShare[*g.ShareID]; ok {
				source = "group_share:" + name
			}
		}
		grant(string(g.Level), source)
		break
	}
	return acc, acc.Permission != ""
}
