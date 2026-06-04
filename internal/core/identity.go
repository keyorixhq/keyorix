package core

import "context"

// UserIdentity summarises a user's roles and permissions for the login and
// profile responses, so the web UI can do coarse, server-truthful gating (e.g.
// show/hide admin nav). The backend still enforces real, scope-aware checks on
// every request via Authorize — this summary is for UI convenience, not a
// security boundary.
type UserIdentity struct {
	Role        string   `json:"role"`        // highest-privilege role, for single-role consumers
	Roles       []string `json:"roles"`       // all assigned role names
	Permissions []string `json:"permissions"` // distinct permission names across the user's roles
}

// rolePrecedence ranks role names from most to least privileged (lower = higher
// privilege). Used to pick one "primary" role for clients that want a single
// value. Roles not listed (unknown/custom) rank below all known roles.
var rolePrecedence = map[string]int{
	"super_admin":       0,
	"system_admin":      1,
	"admin":             2,
	"system_auditor":    3,
	"auditor":           4,
	"editor":            5,
	"project_admin":     6,
	"project_developer": 7,
	"project_auditor":   8,
	"project_viewer":    9,
	"system_viewer":     10,
	"viewer":            11,
}

// primaryRole returns the highest-privilege role name from names, or "" if empty.
func primaryRole(names []string) string {
	const unknownRank = 1000
	best, bestRank := "", int(^uint(0)>>1)
	for _, n := range names {
		rank, ok := rolePrecedence[n]
		if !ok {
			rank = unknownRank
		}
		if rank < bestRank {
			best, bestRank = n, rank
		}
	}
	return best
}

// GetUserIdentity assembles the role/permission summary for a user. Roles are
// every role the user holds (any scope); permissions are the distinct union
// across those roles. Both slices are non-nil (empty, not null) so JSON clients
// get [] rather than null.
func (c *KeyorixCore) GetUserIdentity(ctx context.Context, userID uint) (UserIdentity, error) {
	roles, err := c.GetUserRolesByID(ctx, userID)
	if err != nil {
		return UserIdentity{}, err
	}
	roleNames := make([]string, 0, len(roles))
	for _, r := range roles {
		roleNames = append(roleNames, r.Name)
	}

	perms, err := c.storage.GetUserPermissions(ctx, userID)
	if err != nil {
		return UserIdentity{}, err
	}
	permNames := make([]string, 0, len(perms))
	for _, p := range perms {
		permNames = append(permNames, p.Name)
	}

	return UserIdentity{
		Role:        primaryRole(roleNames),
		Roles:       roleNames,
		Permissions: permNames,
	}, nil
}
