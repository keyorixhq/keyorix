package user

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/spf13/cobra"
)

var (
	listPage     int
	listPageSize int
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List users",
	RunE:  runList,
}

func init() {
	listCmd.Flags().IntVar(&listPage, "page", 1, "Page number")
	listCmd.Flags().IntVar(&listPageSize, "page-size", 20, "Page size (max 100)")
}

func runList(cmd *cobra.Command, args []string) error {
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	users, total, err := service.ListUsers(ctx, &storage.UserFilter{
		Page:     listPage,
		PageSize: listPageSize,
	})
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	fmt.Printf("Total: %d\n", total)
	fmt.Printf("%-6s %-20s %-30s %-10s\n", "ID", "USERNAME", "EMAIL", "ACTIVE")
	for _, u := range users {
		fmt.Printf("%-6d %-20s %-30s %-10t\n", u.ID, u.Username, u.Email, u.IsActive)
	}
	return nil
}
