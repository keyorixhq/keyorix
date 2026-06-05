// user_to_machine.go — `keyorix migrate user-to-machine <username>` (ADR-023).
//
// Converts a service-account-shaped human user into a project machine identity.
// Local mode only (operator tool): resolves the acting admin via --by, the
// project via --project / KEYORIX_PROJECT / the active project, then delegates to
// core.MigrateUserToMachine. By default the source user is suspended so it can no
// longer log in; --keep-user leaves it active.
package migrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	u2mProject  string
	u2mType     string
	u2mName     string
	u2mBy       string
	u2mKeepUser bool
)

var userToMachineCmd = &cobra.Command{
	Use:   "user-to-machine <username>",
	Short: "Convert a service-account-shaped user into a machine identity",
	Long: "Materialise a project machine identity (ADR-023) for an existing user and,\n" +
		"unless --keep-user is set, suspend the source user so it can no longer log in.\n" +
		"The user is never deleted; suspension is reversible via `keyorix user reactivate`.",
	Args: cobra.ExactArgs(1),
	RunE: runUserToMachine,
}

func init() {
	userToMachineCmd.Flags().StringVar(&u2mProject, "project", "", "Project for the new machine identity (defaults to the active project)")
	userToMachineCmd.Flags().StringVar(&u2mType, "type", "service", "Identity type: ci | k8s | service | automation | other")
	userToMachineCmd.Flags().StringVar(&u2mName, "name", "", "Machine identity name (defaults to the username)")
	userToMachineCmd.Flags().StringVar(&u2mBy, "by", "", "Acting admin email (required, for audit)")
	userToMachineCmd.Flags().BoolVar(&u2mKeepUser, "keep-user", false, "Leave the source user active (default: suspend it)")
	_ = userToMachineCmd.MarkFlagRequired("by")
}

func runUserToMachine(cmd *cobra.Command, args []string) error {
	username := args[0]
	if u2mBy == "" {
		return errors.New("acting admin email is required (use --by)")
	}

	ctx := context.Background()
	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	admin, err := svc.GetUserByEmail(ctx, u2mBy)
	if err != nil {
		return fmt.Errorf("no user found for --by %q: %w", u2mBy, err)
	}

	projectID, err := resolveProjectID(ctx, svc, u2mProject)
	if err != nil {
		return err
	}

	m, err := svc.MigrateUserToMachine(ctx, username, projectID, u2mType, u2mName, admin.ID, !u2mKeepUser)
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	fmt.Printf("Migrated user %q to machine identity: id=%d name=%q type=%s state=%s\n",
		username, m.ID, m.Name, m.IdentityType, m.State)
	if !u2mKeepUser {
		fmt.Println("Source user suspended (login blocked). Use `keyorix user reactivate` to restore.")
	}
	return nil
}

// resolveProjectID resolves a project name (flag / env / active) to its numeric
// ID against the local core service.
func resolveProjectID(ctx context.Context, svc *core.KeyorixCore, flagValue string) (uint, error) {
	name, err := common.ResolveProject(flagValue)
	if err != nil {
		return 0, err
	}
	projects, err := svc.ListProjects(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to list projects: %w", err)
	}
	for _, p := range projects {
		if p.Name == name {
			return p.ID, nil
		}
	}
	return 0, fmt.Errorf("project %q not found", name)
}
