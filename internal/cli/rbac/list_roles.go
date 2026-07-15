package rbac

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var listRolesCmd = &cobra.Command{
	Use:   "list-roles",
	Short: "List all available roles",
	Long:  "List all roles in the system",
	RunE:  runListRoles,
}

func runListRoles(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if rc, ok := common.NewRemoteClient(); ok {
		return runListRolesRemote(ctx, rc)
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}

	// ListRoles is called via storage directly; a core-service wrapper is a tracked backlog item
	roles, err := st.ListRoles(ctx)
	if err != nil {
		return fmt.Errorf("failed to list roles: %w", err)
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
