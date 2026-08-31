// secret_access_list.go — the effective access list for a secret: every USER who can
// read it, resolved across the owner, direct user shares, and group shares (with group
// membership expanded). A least-privilege / access-review aid ("who can read secret
// X?"). Read-only; the caller must be able to read the secret. Expired (time-bound)
// shares are excluded, matching enforcement. Note: holders of an admin role have
// implicit access and are not enumerated here — this lists the per-secret grants.
package core

import (
	"context"
	"fmt"
	"sort"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// SecretAccessor is one user with effective access to a secret.
type SecretAccessor struct {
	UserID     uint   `json:"user_id"`
	Username   string `json:"username"`
	Permission string `json:"permission"` // read | write | owner
	Source     string `json:"source"`     // owner | direct_share | group_share:<group>
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

// ListSecretAccessors returns the distinct users who can access secretID, strongest
// grant per user, sorted by username, plus whether the list is known-complete. The
// actor must be able to read the secret.
func (c *KeyorixCore) ListSecretAccessors(ctx context.Context, secretID, actorID uint) (*SecretAccessorsResult, error) { // NOSONAR -- cognitive complexity 29, suppress go:S3776
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	userNames := map[uint]string{}
	resolveUser := func(id uint) string {
		if n, ok := userNames[id]; ok {
			return n
		}
		name := fmt.Sprintf("user %d", id)
		if u, err := c.storage.GetUser(ctx, id); err == nil && u != nil && u.Username != "" {
			name = u.Username
		}
		userNames[id] = name
		return name
	}

	byUser := map[uint]SecretAccessor{}
	add := func(uid uint, perm, source string) {
		if uid == 0 {
			return
		}
		if ex, ok := byUser[uid]; ok && permissionRank[ex.Permission] >= permissionRank[perm] {
			return // keep the stronger grant
		}
		byUser[uid] = SecretAccessor{UserID: uid, Username: resolveUser(uid), Permission: perm, Source: source}
	}

	if secret.OwnerID != 0 {
		add(secret.OwnerID, "owner", "owner")
	}

	result := &SecretAccessorsResult{}

	shares, err := c.storage.ListSharesBySecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, sh := range activeShares(shares, c.shareEffectiveNow()) {
		if sh.IsGroup {
			gname := fmt.Sprintf("group %d", sh.RecipientID)
			if g, err := c.storage.GetGroup(ctx, sh.RecipientID); err == nil && g != nil && g.Name != "" {
				gname = g.Name
			}
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
				userNames[m.ID] = m.Username // already loaded; prime the cache
				add(m.ID, sh.Permission, "group_share:"+gname)
			}
		} else {
			add(sh.RecipientID, sh.Permission, "direct_share")
		}
	}

	out := make([]SecretAccessor, 0, len(byUser))
	for _, a := range byUser {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	result.Accessors = out
	return result, nil
}
