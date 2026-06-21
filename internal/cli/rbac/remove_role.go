package rbac

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var removeRoleCmd = &cobra.Command{
	Use:   "remove-role",
	Short: "Remove a role from a user",
	Long:  "Remove a role assignment from a user by email address",
	RunE:  runRemoveRole,
}

var (
	removeUserEmail string
	removeRoleName  string
)

func init() {
	removeRoleCmd.Flags().StringVar(&removeUserEmail, "user", "", "User email address (required)")
	removeRoleCmd.Flags().StringVar(&removeRoleName, "role", "", "Role name to remove (required)")

	_ = removeRoleCmd.MarkFlagRequired("user")
	_ = removeRoleCmd.MarkFlagRequired("role")
}

func runRemoveRole(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if rc, ok := common.NewRemoteClient(); ok {
		return runRemoveRoleRemote(ctx, rc, removeUserEmail, removeRoleName)
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}

	// Create core service
	coreService := core.NewKeyorixCore(st)

	// Use core service to remove role
	err = coreService.RemoveRoleFromUser(ctx, removeUserEmail, removeRoleName)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	fmt.Printf("✅ Successfully removed role '%s' from user '%s'\n", removeRoleName, removeUserEmail)
	return nil
}
