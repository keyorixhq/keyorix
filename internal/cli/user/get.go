package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	getUserID    uint
	getUserEmail string
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a user by id or email",
	RunE:  runGet,
}

func init() {
	getCmd.Flags().UintVar(&getUserID, "id", 0, "User ID")
	getCmd.Flags().StringVar(&getUserEmail, "email", "", "User email")
}

func printUser(u *models.User) {
	dn := u.DisplayName
	if dn == "" {
		dn = u.Username
	}
	fmt.Printf("ID: %d\nUsername: %s\nEmail: %s\nDisplay: %s\nActive: %t\nCreated: %s\nUpdated: %s\n",
		u.ID, u.Username, u.Email, dn, u.IsActive,
		u.CreatedAt.Format("2006-01-02 15:04:05"),
		u.UpdatedAt.Format("2006-01-02 15:04:05"))
}

func runGet(cmd *cobra.Command, args []string) error {
	if getUserID == 0 && getUserEmail == "" {
		return errors.New("specify --id or --email")
	}
	if getUserID != 0 && getUserEmail != "" {
		return errors.New("use only one of --id or --email")
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	if getUserID != 0 {
		u, err := service.GetUser(ctx, getUserID)
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
		printUser(u)
		return nil
	}
	u, err := service.GetUserByEmail(ctx, getUserEmail)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	printUser(u)
	return nil
}
