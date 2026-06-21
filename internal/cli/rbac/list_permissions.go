package rbac

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var listPermissionsCmd = &cobra.Command{
	Use:   "list-permissions",
	Short: "List all permissions for a user",
	Long:  "List all permissions assigned to a user through their roles",
	RunE:  runListPermissions,
}

var listPermissionsUserEmail string

func init() {
	listPermissionsCmd.Flags().StringVar(&listPermissionsUserEmail, "user", "", "User email address (required)")
	_ = listPermissionsCmd.MarkFlagRequired("user")
}

func runListPermissions(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if rc, ok := common.NewRemoteClient(); ok {
		return runListPermissionsRemote(ctx, rc, listPermissionsUserEmail)
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}

	// Initialize core service
	service := core.NewKeyorixCore(st)

	permissions, err := service.ListUserPermissionsByEmail(ctx, listPermissionsUserEmail)
	if err != nil {
		return fmt.Errorf("failed to list user permissions: %w", err)
	}

	if len(permissions) == 0 {
		fmt.Printf("No permissions found for user '%s'\n", listPermissionsUserEmail)
		return nil
	}

	fmt.Printf("Permissions for user '%s':\n", listPermissionsUserEmail)

	// Group permissions by resource
	resourceMap := make(map[string][]interface{})
	for _, perm := range permissions {
		resourceMap["permissions"] = append(resourceMap["permissions"], perm)
	}

	for _, perm := range permissions {
		fmt.Printf("  - Permission: %+v\n", perm)
	}

	return nil
}
