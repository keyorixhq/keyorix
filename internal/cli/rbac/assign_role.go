package rbac

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var assignRoleCmd = &cobra.Command{
	Use:   "assign-role",
	Short: "Assign a role to a user",
	Long:  "Assign a role to a user by email address",
	RunE:  runAssignRole,
}

var (
	userEmail string
	roleName  string
)

func init() {
	assignRoleCmd.Flags().StringVar(&userEmail, "user", "", "User email address (required)")
	assignRoleCmd.Flags().StringVar(&roleName, "role", "", "Role name to assign (required)")

	_ = assignRoleCmd.MarkFlagRequired("user")
	_ = assignRoleCmd.MarkFlagRequired("role")
}

func runAssignRole(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if rc, ok := common.NewRemoteClient(); ok {
		return runAssignRoleRemote(ctx, rc, userEmail, roleName)
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}

	// Create core service
	coreService := core.NewKeyorixCore(st)

	// Use core service to assign role
	err = coreService.AssignRoleToUser(ctx, userEmail, roleName)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	fmt.Printf("✅ Successfully assigned role '%s' to user '%s'\n", roleName, userEmail)
	return nil
}
