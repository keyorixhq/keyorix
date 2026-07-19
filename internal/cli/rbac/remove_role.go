package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/spf13/cobra"
)

var removeRoleCmd = &cobra.Command{
	Use:   "remove-role",
	Short: "Remove a role from a user",
	Long: `Remove a role assignment from a user by email address.

With --project, removes only the grant scoped to that project.
With --environment, removes only the grant scoped to that environment within
the project (--project must also be supplied).`,
	RunE: runRemoveRole,
}

var (
	removeUserEmail   string
	removeRoleName    string
	removeProjectFlag string
	removeEnvFlag     string
)

func init() {
	removeRoleCmd.Flags().StringVar(&removeUserEmail, "user", "", "User email address (required)")
	removeRoleCmd.Flags().StringVar(&removeRoleName, "role", "", "Role name to remove (required)")
	removeRoleCmd.Flags().StringVar(&removeProjectFlag, "project", "", "Remove the grant scoped to this project (optional)")
	removeRoleCmd.Flags().StringVar(&removeEnvFlag, "environment", "", "Remove the grant scoped to this environment within --project (optional; requires --project)")

	_ = removeRoleCmd.MarkFlagRequired("user")
	_ = removeRoleCmd.MarkFlagRequired("role")
}

func runRemoveRole(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if removeEnvFlag != "" && removeProjectFlag == "" {
		return fmt.Errorf("--environment requires --project")
	}
	if rc, ok := common.NewRemoteClient(); ok {
		return runRemoveRoleRemote(ctx, rc, removeUserEmail, removeRoleName, removeProjectFlag, removeEnvFlag)
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}

	// Resolve scope.
	scope := storage.Scope{}
	if removeProjectFlag != "" {
		projectID, err := common.LookupProjectIDByName(ctx, st, removeProjectFlag)
		if err != nil {
			return fmt.Errorf("failed to resolve project: %w", err)
		}
		scope.ProjectID = projectID

		if removeEnvFlag != "" {
			envs, err := st.ListEnvironmentsByProject(ctx, projectID)
			if err != nil {
				return fmt.Errorf("failed to list environments: %w", err)
			}
			found := false
			for _, e := range envs {
				if strings.EqualFold(e.Name, removeEnvFlag) {
					scope.EnvironmentID = e.ID
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("environment %q not found in project %q", removeEnvFlag, removeProjectFlag)
			}
		}
	}

	// Create core service
	coreService := core.NewKeyorixCore(st)

	// Use core service to remove role at the resolved scope.
	err = coreService.RemoveUserRoleScoped(ctx, removeUserEmail, removeRoleName, scope)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	suffix := scopeSuffix(removeProjectFlag, removeEnvFlag)
	fmt.Printf("Successfully removed role '%s' from user '%s'%s\n", removeRoleName, removeUserEmail, suffix)
	return nil
}
