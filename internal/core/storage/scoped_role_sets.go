package storage

import "context"

// UserScopedRoleReads is the subset of Storage that ComposeUserScopedRoleSets reads.
type UserScopedRoleReads interface {
	GetUserRoleScopes(ctx context.Context, userID uint) ([]Scope, error)
	GetUserRoleIDsAt(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope Scope) ([]uint, error)
}

// ComposeUserScopedRoleSets answers GetUserScopedRoleSets with the per-statement
// reads: GetUserRoleScopes, then GetUserRoleIDsAt and GetUserGroupRoleIDsAt at
// each scope. Each read sees its own moment, so the result is not a snapshot;
// that is why GetUserScopedRoleSets exists (#4025). This is the reference the
// one-statement implementation is tested against, and what a Storage wrapper
// that overrides one of these reads (a test injecting a fault) forwards
// GetUserScopedRoleSets to, so the override still reaches the decision. Any
// read's error is returned.
func ComposeUserScopedRoleSets(ctx context.Context, s UserScopedRoleReads, userID uint) (map[Scope][]uint, error) {
	scopes, err := s.GetUserRoleScopes(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make(map[Scope][]uint, len(scopes))
	for _, scope := range scopes {
		direct, err := s.GetUserRoleIDsAt(ctx, userID, scope)
		if err != nil {
			return nil, err
		}
		viaGroups, err := s.GetUserGroupRoleIDsAt(ctx, userID, scope)
		if err != nil {
			return nil, err
		}
		seen := make(map[uint]struct{}, len(direct)+len(viaGroups))
		ids := []uint{}
		for _, id := range append(append([]uint(nil), direct...), viaGroups...) {
			if _, dup := seen[id]; !dup {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
		out[scope] = ids
	}
	return out, nil
}
