package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var checkPermissionCmd = &cobra.Command{
	Use:   "check-permission",
	Short: "Check if a user has a specific permission",
	Long:  "Check if a user has a specific permission by email address and permission name",
	RunE:  runCheckPermission,
}

var (
	checkUserEmail      string
	checkPermissionName string
)

func init() {
	checkPermissionCmd.Flags().StringVar(&checkUserEmail, "user", "", "User email address (required)")
	checkPermissionCmd.Flags().StringVar(&checkPermissionName, "permission", "", "Permission name to check (required)")

	_ = checkPermissionCmd.MarkFlagRequired("user")
	_ = checkPermissionCmd.MarkFlagRequired("permission")
}

func runCheckPermission(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if rc, ok := common.NewRemoteClient(); ok {
		return runCheckPermissionRemote(ctx, rc, checkUserEmail, checkPermissionName)
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}

	// Initialize core service
	service := core.NewKeyorixCore(st)

	// Permissions are named "resource.action" (e.g. secrets.read, system.admin).
	resource, action, perr := splitPermissionName(checkPermissionName)
	if perr != nil {
		return perr
	}

	hasPermission, err := service.HasPermissionByEmail(ctx, checkUserEmail, resource, action)
	if err != nil {
		return fmt.Errorf("failed to check permission: %w", err)
	}

	if hasPermission {
		fmt.Printf("✅ User '%s' has permission '%s'\n", checkUserEmail, checkPermissionName)
	} else {
		fmt.Printf("❌ User '%s' does NOT have permission '%s'\n", checkUserEmail, checkPermissionName)
	}

	return nil
}

// splitPermissionName parses a "resource.action" permission name into its parts.
func splitPermissionName(name string) (resource, action string, err error) {
	parts := strings.SplitN(name, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("permission must be in 'resource.action' form (e.g. secrets.read), got %q", name)
	}
	return parts[0], parts[1], nil
}
