package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/spf13/cobra"
)

var assignRoleCmd = &cobra.Command{
	Use:   "assign-role",
	Short: "Assign a role to a user",
	Long: `Assign a role to a user by email address.

With --project, the grant is scoped to that project only (rather than globally).
With --environment, the grant is further narrowed to a single environment within
that project (--project must also be supplied).

With --ttl, the grant is time-bound (just-in-time access): it stops authorizing
once the window passes and is swept automatically. Useful for emergency or
contractor access. Example: --ttl 4h grants the role for four hours.

Time-bound grants require a server connection (run 'keyorix connect <server>').`,
	RunE: runAssignRole,
}

var (
	userEmail        string
	roleName         string
	roleTTL          time.Duration
	assignProjectFlag string
	assignEnvFlag     string
)

func init() {
	assignRoleCmd.Flags().StringVar(&userEmail, "user", "", "User email address (required)")
	assignRoleCmd.Flags().StringVar(&roleName, "role", "", "Role name to assign (required)")
	assignRoleCmd.Flags().DurationVar(&roleTTL, "ttl", 0, "Time-bound grant lifetime (e.g. 4h, 30m); omit for a permanent grant")
	assignRoleCmd.Flags().StringVar(&assignProjectFlag, "project", "", "Scope the grant to this project (optional)")
	assignRoleCmd.Flags().StringVar(&assignEnvFlag, "environment", "", "Scope the grant to this environment within --project (optional; requires --project)")

	_ = assignRoleCmd.MarkFlagRequired("user")
	_ = assignRoleCmd.MarkFlagRequired("role")
}

func runAssignRole(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if roleTTL < 0 {
		return fmt.Errorf("--ttl must be positive")
	}
	if assignEnvFlag != "" && assignProjectFlag == "" {
		return fmt.Errorf("--environment requires --project")
	}
	if rc, ok := common.NewRemoteClient(); ok {
		return runAssignRoleRemote(ctx, rc, userEmail, roleName, roleTTL, assignProjectFlag, assignEnvFlag)
	}

	// Embedded (direct-DB) mode has no time-bound path — the JIT expiry sweep runs
	// in the server, so a grant made here would never be reclaimed.
	if roleTTL > 0 {
		return fmt.Errorf("--ttl requires a server connection; run 'keyorix connect <server>'")
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}

	// Resolve scope.
	scope := storage.Scope{}
	if assignProjectFlag != "" {
		projectID, err := common.LookupProjectIDByName(ctx, st, assignProjectFlag)
		if err != nil {
			return fmt.Errorf("failed to resolve project: %w", err)
		}
		scope.ProjectID = projectID

		if assignEnvFlag != "" {
			envs, err := st.ListEnvironmentsByProject(ctx, projectID)
			if err != nil {
				return fmt.Errorf("failed to list environments: %w", err)
			}
			found := false
			for _, e := range envs {
				if strings.EqualFold(e.Name, assignEnvFlag) {
					scope.EnvironmentID = e.ID
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("environment %q not found in project %q", assignEnvFlag, assignProjectFlag)
			}
		}
	}

	// Create core service
	coreService := core.NewKeyorixCore(st)

	// Use core service to assign role at the resolved scope.
	err = coreService.AssignUserRoleScoped(ctx, userEmail, roleName, scope)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	suffix := scopeSuffix(assignProjectFlag, assignEnvFlag)
	fmt.Printf("Successfully assigned role '%s' to user '%s'%s\n", roleName, userEmail, suffix)
	return nil
}

// scopeSuffix returns a human-readable scope qualifier for display messages.
func scopeSuffix(project, env string) string {
	if project == "" {
		return ""
	}
	if env != "" {
		return fmt.Sprintf(" in project '%s' / environment '%s'", project, env)
	}
	return fmt.Sprintf(" in project '%s'", project)
}
