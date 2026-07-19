// remote.go — server-backed (remote mode) implementations of the rbac commands.
//
// Every rbac subcommand is dual-mode (mirroring `keyorix secret`): when the CLI
// is configured to talk to a server (env vars or ~/.keyorix/cli.yaml written by
// `keyorix connect` / `keyorix auth login --server`), the command goes through
// the HTTP API so it operates on the SAME data the server and web UI show.
// Without remote configuration it falls back to the embedded direct-DB path.
//
// Before this, every rbac command opened a local SQLite file directly, so against
// a server-backed (e.g. Postgres) deployment `list-roles` reported "No roles
// found" and `assign-role` wrote to the wrong store — silently diverging from the
// dashboard. See fix/rbac-cli-remote-mode.
package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
)

// ── shared resolution helpers ───────────────────────────────────────────────

// resolveProjectIDByName finds a project's ID by name via GET /api/v1/projects.
func resolveProjectIDByName(ctx context.Context, rc *common.RemoteClient, name string) (uint, error) {
	var resp struct {
		Projects []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := rc.Get(ctx, "/api/v1/projects", &resp); err != nil {
		return 0, fmt.Errorf("failed to list projects: %w", err)
	}
	for _, p := range resp.Projects {
		if strings.EqualFold(p.Name, name) {
			return p.ID, nil
		}
	}
	return 0, fmt.Errorf("project %q not found — run 'keyorix project list' to see available projects", name)
}

// resolveEnvironmentIDByName finds an environment's ID by name via GET /api/v1/environments.
func resolveEnvironmentIDByName(ctx context.Context, rc *common.RemoteClient, name string) (uint, error) {
	var resp struct {
		Environments []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"environments"`
	}
	if err := rc.Get(ctx, "/api/v1/environments", &resp); err != nil {
		return 0, fmt.Errorf("failed to list environments: %w", err)
	}
	for _, e := range resp.Environments {
		if strings.EqualFold(e.Name, name) {
			return e.ID, nil
		}
	}
	return 0, fmt.Errorf("environment %q not found", name)
}

// resolveUserIDByEmail finds a user's ID by email via GET /api/v1/users.
func resolveUserIDByEmail(ctx context.Context, rc *common.RemoteClient, email string) (uint, error) {
	var resp struct {
		Users []struct {
			ID    uint   `json:"id"`
			Email string `json:"email"`
		} `json:"users"`
	}
	if err := rc.Get(ctx, "/api/v1/users?page_size=1000", &resp); err != nil {
		return 0, fmt.Errorf("failed to list users: %w", err)
	}
	for _, u := range resp.Users {
		if strings.EqualFold(u.Email, email) {
			return u.ID, nil
		}
	}
	return 0, fmt.Errorf("user %q not found", email)
}

type remoteRole struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// fetchRoles returns all roles via GET /api/v1/roles.
func fetchRoles(ctx context.Context, rc *common.RemoteClient) ([]remoteRole, error) {
	var resp struct {
		Roles []remoteRole `json:"roles"`
	}
	if err := rc.Get(ctx, "/api/v1/roles", &resp); err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	return resp.Roles, nil
}

// resolveRoleIDByName finds a role's ID by name via GET /api/v1/roles.
func resolveRoleIDByName(ctx context.Context, rc *common.RemoteClient, name string) (uint, error) {
	roles, err := fetchRoles(ctx, rc)
	if err != nil {
		return 0, err
	}
	for _, r := range roles {
		if strings.EqualFold(r.Name, name) {
			return r.ID, nil
		}
	}
	return 0, fmt.Errorf("role %q not found — run 'keyorix rbac list-roles' to see available roles", name)
}

// fetchUserRoles returns the roles assigned to a user via GET /api/v1/users/{id}/roles.
func fetchUserRoles(ctx context.Context, rc *common.RemoteClient, userID uint) ([]remoteRole, error) {
	var resp struct {
		Roles []remoteRole `json:"roles"`
	}
	if err := rc.Get(ctx, fmt.Sprintf("/api/v1/users/%d/roles", userID), &resp); err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	return resp.Roles, nil
}

// userEffectivePermissions returns the de-duplicated set of permission names a
// user holds, composed from each assigned role's permissions
// (GET /api/v1/roles/{id}/permissions). There is no single by-email permission
// endpoint, so the union is assembled client-side.
func userEffectivePermissions(ctx context.Context, rc *common.RemoteClient, userID uint) ([]string, error) {
	roles, err := fetchUserRoles(ctx, rc, userID)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var names []string
	for _, role := range roles {
		var resp struct {
			Permissions []struct {
				Name string `json:"name"`
			} `json:"permissions"`
		}
		if err := rc.Get(ctx, fmt.Sprintf("/api/v1/roles/%d/permissions", role.ID), &resp); err != nil {
			return nil, fmt.Errorf("failed to get permissions for role %q: %w", role.Name, err)
		}
		for _, p := range resp.Permissions {
			if _, ok := seen[p.Name]; ok {
				continue
			}
			seen[p.Name] = struct{}{}
			names = append(names, p.Name)
		}
	}
	return names, nil
}

// ── remote command implementations ──────────────────────────────────────────

func runListRolesRemote(ctx context.Context, rc *common.RemoteClient) error {
	roles, err := fetchRoles(ctx, rc)
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		fmt.Println("No roles found")
		return nil
	}
	fmt.Println("Available roles:")
	for _, role := range roles {
		fmt.Printf("  - %s: %s\n", role.Name, role.Description)
	}
	return nil
}

func runListUserRolesRemote(ctx context.Context, rc *common.RemoteClient, email string) error {
	userID, err := resolveUserIDByEmail(ctx, rc, email)
	if err != nil {
		return err
	}
	roles, err := fetchUserRoles(ctx, rc, userID)
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		fmt.Printf("No roles assigned to user '%s'\n", email)
		return nil
	}
	fmt.Printf("Roles assigned to user '%s':\n", email)
	for _, role := range roles {
		fmt.Printf("  - %s: %s\n", role.Name, role.Description)
	}
	return nil
}

func runListPermissionsRemote(ctx context.Context, rc *common.RemoteClient, email string) error {
	userID, err := resolveUserIDByEmail(ctx, rc, email)
	if err != nil {
		return err
	}
	perms, err := userEffectivePermissions(ctx, rc, userID)
	if err != nil {
		return err
	}
	if len(perms) == 0 {
		fmt.Printf("No permissions found for user '%s'\n", email)
		return nil
	}
	fmt.Printf("Permissions for user '%s':\n", email)
	for _, p := range perms {
		fmt.Printf("  - %s\n", p)
	}
	return nil
}

func runCheckPermissionRemote(ctx context.Context, rc *common.RemoteClient, email, permission string) error {
	// Validate the name shape up front for a clear error (matches embedded mode).
	if _, _, err := splitPermissionName(permission); err != nil {
		return err
	}
	userID, err := resolveUserIDByEmail(ctx, rc, email)
	if err != nil {
		return err
	}
	perms, err := userEffectivePermissions(ctx, rc, userID)
	if err != nil {
		return err
	}
	for _, p := range perms {
		if strings.EqualFold(p, permission) {
			fmt.Printf("✅ User '%s' has permission '%s'\n", email, permission)
			return nil
		}
	}
	fmt.Printf("❌ User '%s' does NOT have permission '%s'\n", email, permission)
	return nil
}

func runAssignRoleRemote(ctx context.Context, rc *common.RemoteClient, email, role string, ttl time.Duration, project, env string) error {
	userID, err := resolveUserIDByEmail(ctx, rc, email)
	if err != nil {
		return err
	}
	roleID, err := resolveRoleIDByName(ctx, rc, role)
	if err != nil {
		return err
	}
	body := map[string]interface{}{"user_id": userID, "role_id": roleID}
	if ttl > 0 {
		body["expires_at"] = time.Now().Add(ttl).UTC().Format(time.RFC3339)
	}
	if project != "" {
		projectID, err := resolveProjectIDByName(ctx, rc, project)
		if err != nil {
			return err
		}
		body["project_id"] = projectID
		if env != "" {
			envID, err := resolveEnvironmentIDByName(ctx, rc, env)
			if err != nil {
				return err
			}
			body["environment_id"] = envID
		}
	}
	var out map[string]interface{}
	if err := rc.Post(ctx, "/api/v1/user-roles", body, &out); err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}
	suffix := scopeSuffix(project, env)
	if ttl > 0 {
		fmt.Printf("Assigned role '%s' to user '%s'%s for %s (time-bound)\n", role, email, suffix, ttl)
	} else {
		fmt.Printf("Successfully assigned role '%s' to user '%s'%s\n", role, email, suffix)
	}
	return nil
}

func runRemoveRoleRemote(ctx context.Context, rc *common.RemoteClient, email, role string, project, env string) error {
	userID, err := resolveUserIDByEmail(ctx, rc, email)
	if err != nil {
		return err
	}
	roleID, err := resolveRoleIDByName(ctx, rc, role)
	if err != nil {
		return err
	}
	body := map[string]interface{}{"user_id": userID, "role_id": roleID}
	if project != "" {
		projectID, err := resolveProjectIDByName(ctx, rc, project)
		if err != nil {
			return err
		}
		body["project_id"] = projectID
		if env != "" {
			envID, err := resolveEnvironmentIDByName(ctx, rc, env)
			if err != nil {
				return err
			}
			body["environment_id"] = envID
		}
	}
	if err := rc.DeleteWithBody(ctx, "/api/v1/user-roles", body); err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}
	suffix := scopeSuffix(project, env)
	fmt.Printf("Successfully removed role '%s' from user '%s'%s\n", role, email, suffix)
	return nil
}
