// group_role.go — RBAC subcommands for managing group role assignments.
//
// These are the group-side counterparts to assign-role / remove-role /
// list-user-roles. They are dual-mode (remote API when a server is configured,
// embedded SQLite otherwise), exactly mirroring the user-role commands.
package rbac

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/spf13/cobra"
)

// ── flag variables (prefixed to avoid collision with user-role flags) ──────────

var (
	groupRoleGroupFlag string
	groupRoleName      string
	groupRoleProjectFlag string
	groupRoleEnvFlag   string
	groupRoleTTL       time.Duration

	listGroupRoleGroupFlag string
	removeGroupRoleGroupFlag string
	removeGroupRoleName    string
	removeGroupRoleProjectFlag string
	removeGroupRoleEnvFlag string
)

// ── assign-role-to-group ──────────────────────────────────────────────────────

var assignRoleToGroupCmd = &cobra.Command{
	Use:   "assign-role-to-group",
	Short: "Assign a role to a group",
	Long: `Assign a role to a group.

With --project, the grant is scoped to that project only.
With --environment, the grant is further narrowed to a single environment within
that project (--project must also be supplied).

With --ttl, the grant is time-bound (just-in-time access). Requires a server
connection (run 'keyorix connect <server>').`,
	RunE: runAssignRoleToGroup,
}

func init() {
	assignRoleToGroupCmd.Flags().StringVar(&groupRoleGroupFlag, "group", "", "Group name or numeric ID (required)")
	assignRoleToGroupCmd.Flags().StringVar(&groupRoleName, "role", "", "Role name to assign (required)")
	assignRoleToGroupCmd.Flags().StringVar(&groupRoleProjectFlag, "project", "", "Scope the grant to this project (optional)")
	assignRoleToGroupCmd.Flags().StringVar(&groupRoleEnvFlag, "environment", "", "Scope the grant to this environment within --project (optional; requires --project)")
	assignRoleToGroupCmd.Flags().DurationVar(&groupRoleTTL, "ttl", 0, "Time-bound grant lifetime (e.g. 4h, 30m); omit for a permanent grant")

	_ = assignRoleToGroupCmd.MarkFlagRequired("group")
	_ = assignRoleToGroupCmd.MarkFlagRequired("role")
}

func runAssignRoleToGroup(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if groupRoleTTL < 0 {
		return fmt.Errorf("--ttl must be positive")
	}
	if groupRoleEnvFlag != "" && groupRoleProjectFlag == "" {
		return fmt.Errorf("--environment requires --project")
	}

	if rc, ok := common.NewRemoteClient(); ok {
		return runAssignRoleToGroupRemote(ctx, rc, groupRoleGroupFlag, groupRoleName, groupRoleTTL, groupRoleProjectFlag, groupRoleEnvFlag)
	}

	// Embedded (direct-DB) mode has no JIT sweep — time-bound grants require a server.
	if groupRoleTTL > 0 {
		return fmt.Errorf("--ttl requires a server connection; run 'keyorix connect <server>'")
	}

	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}

	groupID, err := resolveGroupID(ctx, st, groupRoleGroupFlag)
	if err != nil {
		return err
	}

	roleID, err := resolveRoleIDEmbedded(ctx, st, groupRoleName)
	if err != nil {
		return err
	}

	scope, err := resolveScope(ctx, st, groupRoleProjectFlag, groupRoleEnvFlag)
	if err != nil {
		return err
	}

	if err := st.AssignRoleToGroup(ctx, groupID, roleID, scope); err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	suffix := scopeSuffix(groupRoleProjectFlag, groupRoleEnvFlag)
	fmt.Printf("Successfully assigned role '%s' to group '%s'%s\n", groupRoleName, groupRoleGroupFlag, suffix)
	return nil
}

// ── remove-role-from-group ────────────────────────────────────────────────────

var removeRoleFromGroupCmd = &cobra.Command{
	Use:   "remove-role-from-group",
	Short: "Remove a role from a group",
	Long: `Remove a role assignment from a group.

With --project, removes only the grant scoped to that project.
With --environment, removes only the grant scoped to that environment within
the project (--project must also be supplied).`,
	RunE: runRemoveRoleFromGroup,
}

func init() {
	removeRoleFromGroupCmd.Flags().StringVar(&removeGroupRoleGroupFlag, "group", "", "Group name or numeric ID (required)")
	removeRoleFromGroupCmd.Flags().StringVar(&removeGroupRoleName, "role", "", "Role name to remove (required)")
	removeRoleFromGroupCmd.Flags().StringVar(&removeGroupRoleProjectFlag, "project", "", "Remove the grant scoped to this project (optional)")
	removeRoleFromGroupCmd.Flags().StringVar(&removeGroupRoleEnvFlag, "environment", "", "Remove the grant scoped to this environment within --project (optional; requires --project)")

	_ = removeRoleFromGroupCmd.MarkFlagRequired("group")
	_ = removeRoleFromGroupCmd.MarkFlagRequired("role")
}

func runRemoveRoleFromGroup(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if removeGroupRoleEnvFlag != "" && removeGroupRoleProjectFlag == "" {
		return fmt.Errorf("--environment requires --project")
	}

	if rc, ok := common.NewRemoteClient(); ok {
		return runRemoveRoleFromGroupRemote(ctx, rc, removeGroupRoleGroupFlag, removeGroupRoleName, removeGroupRoleProjectFlag, removeGroupRoleEnvFlag)
	}

	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}

	groupID, err := resolveGroupID(ctx, st, removeGroupRoleGroupFlag)
	if err != nil {
		return err
	}

	roleID, err := resolveRoleIDEmbedded(ctx, st, removeGroupRoleName)
	if err != nil {
		return err
	}

	scope, err := resolveScope(ctx, st, removeGroupRoleProjectFlag, removeGroupRoleEnvFlag)
	if err != nil {
		return err
	}

	if err := st.RemoveRoleFromGroup(ctx, groupID, roleID, scope); err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	suffix := scopeSuffix(removeGroupRoleProjectFlag, removeGroupRoleEnvFlag)
	fmt.Printf("Successfully removed role '%s' from group '%s'%s\n", removeGroupRoleName, removeGroupRoleGroupFlag, suffix)
	return nil
}

// ── list-group-roles ──────────────────────────────────────────────────────────

var listGroupRolesCmd = &cobra.Command{
	Use:   "list-group-roles",
	Short: "List roles assigned to a group",
	Long:  "List all roles assigned to a specific group.",
	RunE:  runListGroupRoles,
}

func init() {
	listGroupRolesCmd.Flags().StringVar(&listGroupRoleGroupFlag, "group", "", "Group name or numeric ID (required)")
	_ = listGroupRolesCmd.MarkFlagRequired("group")
}

func runListGroupRoles(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runListGroupRolesRemote(ctx, rc, listGroupRoleGroupFlag)
	}

	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}

	groupID, err := resolveGroupID(ctx, st, listGroupRoleGroupFlag)
	if err != nil {
		return err
	}

	grants, err := st.GetGroupRoleGrants(ctx, groupID)
	if err != nil {
		return fmt.Errorf("failed to get group roles: %w", err)
	}

	if len(grants) == 0 {
		fmt.Printf("No roles assigned to group '%s'\n", listGroupRoleGroupFlag)
		return nil
	}

	printGroupRoleTable(grants)
	return nil
}

// ── remote implementations ────────────────────────────────────────────────────

func resolveGroupIDRemote(ctx context.Context, rc *common.RemoteClient, nameOrID string) (uint, string, error) {
	// If the flag value is a plain integer, treat it as a direct ID.
	if id, err := strconv.ParseUint(nameOrID, 10, 32); err == nil {
		return uint(id), nameOrID, nil
	}

	var resp struct {
		Groups []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"groups"`
	}
	if err := rc.Get(ctx, "/api/v1/groups", &resp); err != nil {
		return 0, "", fmt.Errorf("failed to list groups: %w", err)
	}
	for _, g := range resp.Groups {
		if strings.EqualFold(g.Name, nameOrID) {
			return g.ID, g.Name, nil
		}
	}
	return 0, "", fmt.Errorf("group %q not found", nameOrID)
}

func runAssignRoleToGroupRemote(ctx context.Context, rc *common.RemoteClient, group, role string, ttl time.Duration, project, env string) error {
	groupID, groupName, err := resolveGroupIDRemote(ctx, rc, group)
	if err != nil {
		return err
	}
	roleID, err := resolveRoleIDByName(ctx, rc, role)
	if err != nil {
		return err
	}

	body := map[string]interface{}{"role_id": roleID}
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
	if err := rc.Post(ctx, fmt.Sprintf("/api/v1/groups/%d/roles", groupID), body, &out); err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	suffix := scopeSuffix(project, env)
	if ttl > 0 {
		fmt.Printf("Assigned role '%s' to group '%s'%s for %s (time-bound)\n", role, groupName, suffix, ttl)
	} else {
		fmt.Printf("Successfully assigned role '%s' to group '%s'%s\n", role, groupName, suffix)
	}
	return nil
}

func runRemoveRoleFromGroupRemote(ctx context.Context, rc *common.RemoteClient, group, role, project, env string) error {
	groupID, groupName, err := resolveGroupIDRemote(ctx, rc, group)
	if err != nil {
		return err
	}
	roleID, err := resolveRoleIDByName(ctx, rc, role)
	if err != nil {
		return err
	}

	path := fmt.Sprintf("/api/v1/groups/%d/roles/%d", groupID, roleID)
	params := []string{}
	if project != "" {
		projectID, err := resolveProjectIDByName(ctx, rc, project)
		if err != nil {
			return err
		}
		params = append(params, fmt.Sprintf("project_id=%d", projectID))
		if env != "" {
			envID, err := resolveEnvironmentIDByName(ctx, rc, env)
			if err != nil {
				return err
			}
			params = append(params, fmt.Sprintf("environment_id=%d", envID))
		}
	}
	if len(params) > 0 {
		path = path + "?" + strings.Join(params, "&")
	}

	if err := rc.Delete(ctx, path); err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	suffix := scopeSuffix(project, env)
	fmt.Printf("Successfully removed role '%s' from group '%s'%s\n", role, groupName, suffix)
	return nil
}

type remoteGroupRole struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

func runListGroupRolesRemote(ctx context.Context, rc *common.RemoteClient, group string) error {
	groupID, groupName, err := resolveGroupIDRemote(ctx, rc, group)
	if err != nil {
		return err
	}

	var resp struct {
		GroupID uint              `json:"group_id"`
		Roles   []remoteGroupRole `json:"roles"`
	}
	if err := rc.Get(ctx, fmt.Sprintf("/api/v1/groups/%d/roles", groupID), &resp); err != nil {
		return fmt.Errorf("failed to get group roles: %w", err)
	}

	if len(resp.Roles) == 0 {
		fmt.Printf("No roles assigned to group '%s'\n", groupName)
		return nil
	}

	printRemoteGroupRoleTable(resp.Roles)
	return nil
}

// ── embedded helpers ──────────────────────────────────────────────────────────

// resolveGroupID resolves a group name or numeric ID string to a group ID using
// the embedded storage. If nameOrID parses as an integer it is used directly;
// otherwise all groups are listed and matched case-insensitively by name.
func resolveGroupID(ctx context.Context, st storage.Storage, nameOrID string) (uint, error) {
	if id, err := strconv.ParseUint(nameOrID, 10, 32); err == nil {
		return uint(id), nil
	}

	groups, err := st.ListGroups(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to list groups: %w", err)
	}
	for _, g := range groups {
		if strings.EqualFold(g.Name, nameOrID) {
			return g.ID, nil
		}
	}
	return 0, fmt.Errorf("group %q not found", nameOrID)
}

// resolveRoleIDEmbedded looks up a role's ID by name in the embedded store.
func resolveRoleIDEmbedded(ctx context.Context, st storage.Storage, name string) (uint, error) {
	role, err := st.GetRoleByName(ctx, name)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve role %q: %w", name, err)
	}
	return role.ID, nil
}

// ── display helpers ───────────────────────────────────────────────────────────

const groupRoleTableFmt = "%-20s %-35s %-10s\n"

func printGroupRoleTable(grants []*storage.GroupRoleGrant) {
	fmt.Printf(groupRoleTableFmt, "ROLE", "DESCRIPTION", "EXPIRES")
	fmt.Printf(groupRoleTableFmt, strings.Repeat("-", 20), strings.Repeat("-", 35), strings.Repeat("-", 10))
	for _, g := range grants {
		exp := "never"
		if g.ExpiresAt != nil {
			exp = g.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC")
		}
		fmt.Printf(groupRoleTableFmt, g.Name, g.Description, exp)
	}
}

func printRemoteGroupRoleTable(roles []remoteGroupRole) {
	fmt.Printf(groupRoleTableFmt, "ROLE", "DESCRIPTION", "EXPIRES")
	fmt.Printf(groupRoleTableFmt, strings.Repeat("-", 20), strings.Repeat("-", 35), strings.Repeat("-", 10))
	for _, r := range roles {
		exp := "never"
		if r.ExpiresAt != nil {
			exp = r.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC")
		}
		fmt.Printf(groupRoleTableFmt, r.Name, r.Description, exp)
	}
}
