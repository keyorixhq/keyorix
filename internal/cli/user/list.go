package user

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

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
	if rc, ok := common.NewRemoteClient(); ok {
		return runListRemote(rc)
	}

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

// runListRemote lists users via GET /api/v1/users against the connected
// server (server/http/handlers/users_list.go), so the listing reflects the
// server's real user store instead of a stray local SQLite file. Matches
// userToAPIResponse's wire shape (the "active" field, not "is_active").
func runListRemote(rc *common.RemoteClient) error {
	params := url.Values{}
	params.Set("page", strconv.Itoa(listPage))
	params.Set("page_size", strconv.Itoa(listPageSize))

	var resp struct {
		Users []struct {
			ID       uint   `json:"id"`
			Username string `json:"username"`
			Email    string `json:"email"`
			Active   bool   `json:"active"`
		} `json:"users"`
		Total int64 `json:"total"`
	}
	if err := rc.Get(context.Background(), "/api/v1/users?"+params.Encode(), &resp); err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	fmt.Printf("Total: %d\n", resp.Total)
	fmt.Printf("%-6s %-20s %-30s %-10s\n", "ID", "USERNAME", "EMAIL", "ACTIVE")
	for _, u := range resp.Users {
		fmt.Printf("%-6d %-20s %-30s %-10t\n", u.ID, u.Username, u.Email, u.Active)
	}
	return nil
}
