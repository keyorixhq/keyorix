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

// permMatrixCache holds lazy-populated lookup caches used while building the
// permission matrix. Extracting the five closures into methods keeps
// GetPermissionMatrix's cognitive complexity within bounds.
type permMatrixCache struct {
	core           *KeyorixCore
	ctx            context.Context
	userCache      map[uint]pmUserInfo
	rolePermsCache map[uint][]pmPermInfo
	roleNameCache  map[uint]string
	projectCache   map[uint]string
	envCache       map[uint]string
}

type pmUserInfo struct {
	Username string
	Email    string
}

type pmPermInfo struct {
	Name     string
	Resource string
	Action   string
}

func newPermMatrixCache(c *KeyorixCore, ctx context.Context) *permMatrixCache {
	return &permMatrixCache{
		core:           c,
		ctx:            ctx,
		userCache:      make(map[uint]pmUserInfo),
		rolePermsCache: make(map[uint][]pmPermInfo),
		roleNameCache:  make(map[uint]string),
		projectCache:   make(map[uint]string),
		envCache:       make(map[uint]string),
	}
}

func (h *permMatrixCache) getUser(userID uint) (pmUserInfo, error) {
	if u, ok := h.userCache[userID]; ok {
		return u, nil
	}
	u, err := h.core.storage.GetUser(h.ctx, userID)
	if err != nil {
		return pmUserInfo{}, fmt.Errorf("get user %d: %w", userID, err)
	}
	info := pmUserInfo{Username: u.Username, Email: u.Email}
	h.userCache[userID] = info
	return info, nil
}

func (h *permMatrixCache) getRolePerms(roleID uint) ([]pmPermInfo, error) {
	if perms, ok := h.rolePermsCache[roleID]; ok {
		return perms, nil
	}
	perms, err := h.core.storage.GetRolePermissions(h.ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("get permissions for role %d: %w", roleID, err)
	}
	var result []pmPermInfo
	for _, p := range perms {
		result = append(result, pmPermInfo{Name: p.Name, Resource: p.Resource, Action: p.Action})
	}
	h.rolePermsCache[roleID] = result
	return result, nil
}

func (h *permMatrixCache) getRoleName(roleID uint) (string, error) {
	if name, ok := h.roleNameCache[roleID]; ok {
		return name, nil
	}
	role, err := h.core.storage.GetRole(h.ctx, roleID)
	if err != nil {
		return "", fmt.Errorf("get role %d: %w", roleID, err)
	}
	h.roleNameCache[roleID] = role.Name
	return role.Name, nil
}

func (h *permMatrixCache) getProjectName(projID uint) string {
	if projID == 0 {
		return ""
	}
	if name, ok := h.projectCache[projID]; ok {
		return name
	}
	proj, err := h.core.storage.GetProject(h.ctx, projID)
	if err != nil {
		// Soft-deleted projects may still have grants; return ID-as-name rather than failing.
		name := fmt.Sprintf("project-%d", projID)
		h.projectCache[projID] = name
		return name
	}
	h.projectCache[projID] = proj.Name
	return proj.Name
}

func (h *permMatrixCache) getEnvName(envID uint) string {
	if envID == 0 {
		return ""
	}
	if name, ok := h.envCache[envID]; ok {
		return name
	}
	env, err := h.core.storage.GetEnvironment(h.ctx, envID)
	if err != nil {
		name := fmt.Sprintf("env-%d", envID)
		h.envCache[envID] = name
		return name
	}
	h.envCache[envID] = env.Name
	return env.Name
}

func grantScope(projectID, envID uint) string {
	if projectID != 0 && envID != 0 {
		return "environment"
	}
	if projectID != 0 {
		return "project"
	}
	return "global"
}

// GetPermissionMatrix returns every (user, role, permission, scope) tuple in the
// deployment. If projectID > 0, only grants scoped to that project are included
// (plus global grants with project_id = 0).
func (c *KeyorixCore) GetPermissionMatrix(ctx context.Context, projectID uint) ([]*PermissionMatrixRow, error) {
	grants, err := c.storage.ListAllUserRoleGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("permission matrix: list grants: %w", err)
	}

	cache := newPermMatrixCache(c, ctx)

	var rows []*PermissionMatrixRow
	for _, grant := range grants {
		if projectID > 0 && grant.ProjectID != 0 && grant.ProjectID != projectID {
			continue
		}

		uInfo, err := cache.getUser(grant.UserID)
		if err != nil {
			// Unknown/deleted user — skip silently; the row may be a stale JIT grant.
			continue
		}

		roleName, err := cache.getRoleName(grant.RoleID)
		if err != nil {
			continue
		}

		perms, err := cache.getRolePerms(grant.RoleID)
		if err != nil {
			continue
		}

		projName := cache.getProjectName(grant.ProjectID)
		envName := cache.getEnvName(grant.EnvironmentID)
		scope := grantScope(grant.ProjectID, grant.EnvironmentID)

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
