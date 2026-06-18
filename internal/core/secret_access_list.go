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

var permissionRank = map[string]int{"read": 1, "write": 2, "owner": 3}

// ListSecretAccessors returns the distinct users who can access secretID, strongest
// grant per user, sorted by username. The actor must be able to read the secret.
func (c *KeyorixCore) ListSecretAccessors(ctx context.Context, secretID, actorID uint) ([]SecretAccessor, error) {
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

	shares, err := c.storage.ListSharesBySecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, sh := range activeShares(shares, c.now()) {
		if sh.IsGroup {
			gname := fmt.Sprintf("group %d", sh.RecipientID)
			if g, err := c.storage.GetGroup(ctx, sh.RecipientID); err == nil && g != nil && g.Name != "" {
				gname = g.Name
			}
			members, err := c.storage.ListGroupMembers(ctx, sh.RecipientID)
			if err != nil {
				continue // skip an unresolvable group rather than fail the whole list
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
	return out, nil
}
