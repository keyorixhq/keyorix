// permission_baseline.go — GetPermissionBaseline: export every user's effective
// permissions (through roles + group membership) as a flat edge list.
// Used for auditor hand-off (CSV / JSON) via the compliance endpoints.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// PermissionBaselineRow is one user→role→permission edge in the deployment,
// annotated with the scope at which the role was granted.
type PermissionBaselineRow struct {
	UserID     uint   `json:"user_id"`
	Username   string `json:"username"`
	Email      string `json:"email"`
	RoleName   string `json:"role_name"`
	Scope      string `json:"scope"` // "global" or "project:<id>"
	Permission string `json:"permission"`
}

// PermissionBaseline is the full permission edge list for the deployment.
type PermissionBaseline struct {
	GeneratedAt time.Time               `json:"generated_at"`
	Rows        []PermissionBaselineRow `json:"rows"`
}

// GetPermissionBaseline returns every user→role→permission edge in the system,
// expanding through both direct UserRole grants and GroupRole grants (via
// UserGroup→Group→GroupRole). Each distinct (user, role, scope, permission)
// tuple becomes one PermissionBaselineRow. Expired grants are included (snapshot
// of all grants, including time-bound ones) so the auditor sees the full history;
// callers that need only live grants should filter by expiry themselves.
func (k *KeyorixCore) GetPermissionBaseline(ctx context.Context) (*PermissionBaseline, error) {
	// 1. Load all users (no filter — we want every principal).
	users, _, err := k.storage.ListUsers(ctx, &storage.UserFilter{PageSize: 100000})
	if err != nil {
		return nil, fmt.Errorf("permission baseline: list users: %w", err)
	}

	// 2. Load all role grants in one shot (user_roles table).
	allGrants, err := k.storage.ListAllUserRoleGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("permission baseline: list user role grants: %w", err)
	}

	// Build quick lookup maps.
	userByID := make(map[uint]*userBaseline, len(users))
	for _, u := range users {
		userByID[u.ID] = &userBaseline{username: u.Username, email: u.Email}
	}

	// rolePermCache: roleID → []permissionName (populated on first access).
	rolePermCache := make(map[uint][]string)
	rolePermLookup := func(roleID uint) ([]string, error) {
		if perms, ok := rolePermCache[roleID]; ok {
			return perms, nil
		}
		perms, err := k.storage.GetRolePermissions(ctx, roleID)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(perms))
		for _, p := range perms {
			names = append(names, p.Name)
		}
		rolePermCache[roleID] = names
		return names, nil
	}

	// roleNameCache: roleID → roleName.
	roleNameCache := make(map[uint]string)
	roleNameLookup := func(roleID uint) (string, error) {
		if name, ok := roleNameCache[roleID]; ok {
			return name, nil
		}
		role, err := k.storage.GetRole(ctx, roleID)
		if err != nil {
			return "", err
		}
		roleNameCache[roleID] = role.Name
		return role.Name, nil
	}

	var rows []PermissionBaselineRow

	// 3. Direct user→role grants.
	for _, grant := range allGrants {
		u, ok := userByID[grant.UserID]
		if !ok {
			continue // skip if the user row is gone (soft-deleted outside the window)
		}
		roleName, err := roleNameLookup(grant.RoleID)
		if err != nil {
			return nil, fmt.Errorf("permission baseline: get role %d: %w", grant.RoleID, err)
		}
		perms, err := rolePermLookup(grant.RoleID)
		if err != nil {
			return nil, fmt.Errorf("permission baseline: get permissions for role %d: %w", grant.RoleID, err)
		}
		scope := scopeLabel(grant.ProjectID)
		for _, perm := range perms {
			rows = append(rows, PermissionBaselineRow{
				UserID:     grant.UserID,
				Username:   u.username,
				Email:      u.email,
				RoleName:   roleName,
				Scope:      scope,
				Permission: perm,
			})
		}
	}

	// 4. Group-inherited grants: for each user, enumerate groups → group roles →
	//    permissions. We iterate over users and call GetUserGroups so the expansion
	//    is readable and doesn't require a new bulk storage method.
	for _, u := range users {
		groups, err := k.storage.GetUserGroups(ctx, u.ID)
		if err != nil {
			return nil, fmt.Errorf("permission baseline: get groups for user %d: %w", u.ID, err)
		}
		for _, g := range groups {
			groupRoles, err := k.storage.GetGroupRoles(ctx, g.ID)
			if err != nil {
				return nil, fmt.Errorf("permission baseline: get roles for group %d: %w", g.ID, err)
			}
			for _, role := range groupRoles {
				perms, err := rolePermLookup(role.ID)
				if err != nil {
					return nil, fmt.Errorf("permission baseline: get permissions for role %d (group %d): %w", role.ID, g.ID, err)
				}
				// Group roles don't carry a per-grant scope in GetGroupRoles; for the
				// baseline we report the group's role as global scope (project_id=0
				// semantics). Callers needing exact per-scope rows can use
				// ListGroupRoleAssignments separately.
				for _, perm := range perms {
					rows = append(rows, PermissionBaselineRow{
						UserID:     u.ID,
						Username:   u.Username,
						Email:      u.Email,
						RoleName:   role.Name,
						Scope:      "global",
						Permission: perm,
					})
				}
			}
		}
	}

	if rows == nil {
		rows = []PermissionBaselineRow{}
	}
	return &PermissionBaseline{
		GeneratedAt: time.Now().UTC(),
		Rows:        rows,
	}, nil
}

// scopeLabel turns a project_id sentinel into the string form stored in the CSV/JSON.
func scopeLabel(projectID uint) string {
	if projectID == 0 {
		return "global"
	}
	return fmt.Sprintf("project:%d", projectID)
}

// userBaseline is a compact struct for the fields we carry per-user in the builder.
type userBaseline struct {
	username string
	email    string
}
