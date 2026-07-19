package core

import (
	"context"
	"fmt"
	"time"
)

// PermissionMatrixRow is one row in the audit permission matrix:
// one user × one permission × one scope (global, project, or environment).
type PermissionMatrixRow struct {
	UserID          uint       `json:"user_id"`
	Username        string     `json:"username"`
	Email           string     `json:"email"`
	RoleID          uint       `json:"role_id"`
	RoleName        string     `json:"role_name"`
	PermissionName  string     `json:"permission_name"`
	Resource        string     `json:"resource"`
	Action          string     `json:"action"`
	Scope           string     `json:"scope"`            // "global" | "project" | "environment"
	ProjectID       uint       `json:"project_id"`
	ProjectName     string     `json:"project_name"`
	EnvironmentID   uint       `json:"environment_id"`
	EnvironmentName string     `json:"environment_name"`
	ExpiresAt       *time.Time `json:"expires_at"` // nil = permanent
}

// GetPermissionMatrix returns every (user, role, permission, scope) tuple in the
// deployment. If projectID > 0, only grants scoped to that project are included
// (plus global grants with project_id = 0).
func (c *KeyorixCore) GetPermissionMatrix(ctx context.Context, projectID uint) ([]*PermissionMatrixRow, error) {
	// 1. Fetch all user→role grant rows.
	grants, err := c.storage.ListAllUserRoleGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("permission matrix: list grants: %w", err)
	}

	// 2. Build user lookup map (user_id → User).
	type userInfo struct {
		Username string
		Email    string
	}
	userCache := map[uint]userInfo{}
	getUserInfo := func(userID uint) (userInfo, error) {
		if u, ok := userCache[userID]; ok {
			return u, nil
		}
		u, err := c.storage.GetUser(ctx, userID)
		if err != nil {
			return userInfo{}, fmt.Errorf("get user %d: %w", userID, err)
		}
		info := userInfo{Username: u.Username, Email: u.Email}
		userCache[userID] = info
		return info, nil
	}

	// 3. Build role permissions cache (role_id → []Permission).
	type permInfo struct {
		Name     string
		Resource string
		Action   string
	}
	rolePermsCache := map[uint][]permInfo{}
	getRolePerms := func(roleID uint) ([]permInfo, error) {
		if perms, ok := rolePermsCache[roleID]; ok {
			return perms, nil
		}
		perms, err := c.storage.GetRolePermissions(ctx, roleID)
		if err != nil {
			return nil, fmt.Errorf("get permissions for role %d: %w", roleID, err)
		}
		var result []permInfo
		for _, p := range perms {
			result = append(result, permInfo{Name: p.Name, Resource: p.Resource, Action: p.Action})
		}
		rolePermsCache[roleID] = result
		return result, nil
	}

	// 4. Build role name cache.
	roleNameCache := map[uint]string{}
	getRoleName := func(roleID uint) (string, error) {
		if name, ok := roleNameCache[roleID]; ok {
			return name, nil
		}
		role, err := c.storage.GetRole(ctx, roleID)
		if err != nil {
			return "", fmt.Errorf("get role %d: %w", roleID, err)
		}
		roleNameCache[roleID] = role.Name
		return role.Name, nil
	}

	// 5. Build project name cache.
	projectNameCache := map[uint]string{}
	getProjectName := func(projID uint) (string, error) {
		if projID == 0 {
			return "", nil
		}
		if name, ok := projectNameCache[projID]; ok {
			return name, nil
		}
		proj, err := c.storage.GetProject(ctx, projID)
		if err != nil {
			// Soft-deleted projects may still have grants; return ID-as-name rather than failing.
			name := fmt.Sprintf("project-%d", projID)
			projectNameCache[projID] = name
			return name, nil
		}
		projectNameCache[projID] = proj.Name
		return proj.Name, nil
	}

	// 6. Build environment name cache.
	envNameCache := map[uint]string{}
	getEnvName := func(envID uint) (string, error) {
		if envID == 0 {
			return "", nil
		}
		if name, ok := envNameCache[envID]; ok {
			return name, nil
		}
		env, err := c.storage.GetEnvironment(ctx, envID)
		if err != nil {
			name := fmt.Sprintf("env-%d", envID)
			envNameCache[envID] = name
			return name, nil
		}
		envNameCache[envID] = env.Name
		return env.Name, nil
	}

	// 7. Cross-join: for each grant × each permission → one row.
	var rows []*PermissionMatrixRow
	for _, grant := range grants {
		// Apply project filter: include global (project_id=0) and same-project grants.
		if projectID > 0 && grant.ProjectID != 0 && grant.ProjectID != projectID {
			continue
		}

		uInfo, err := getUserInfo(grant.UserID)
		if err != nil {
			// Unknown/deleted user — skip silently; the row may be a stale JIT grant.
			continue
		}

		roleName, err := getRoleName(grant.RoleID)
		if err != nil {
			continue
		}

		perms, err := getRolePerms(grant.RoleID)
		if err != nil {
			continue
		}

		projName, _ := getProjectName(grant.ProjectID)
		envName, _ := getEnvName(grant.EnvironmentID)

		scope := "global"
		if grant.ProjectID != 0 && grant.EnvironmentID != 0 {
			scope = "environment"
		} else if grant.ProjectID != 0 {
			scope = "project"
		}

		for _, perm := range perms {
			rows = append(rows, &PermissionMatrixRow{
				UserID:          grant.UserID,
				Username:        uInfo.Username,
				Email:           uInfo.Email,
				RoleID:          grant.RoleID,
				RoleName:        roleName,
				PermissionName:  perm.Name,
				Resource:        perm.Resource,
				Action:          perm.Action,
				Scope:           scope,
				ProjectID:       grant.ProjectID,
				ProjectName:     projName,
				EnvironmentID:   grant.EnvironmentID,
				EnvironmentName: envName,
				ExpiresAt:       grant.ExpiresAt,
			})
		}
	}

	return rows, nil
}
