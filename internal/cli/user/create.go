package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	createUsername    string
	createEmail       string
	createPassword    string
	createDisplayName string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	RunE:  runCreate,
}

func init() {
	createCmd.Flags().StringVar(&createUsername, "username", "", "Username (required)")
	createCmd.Flags().StringVar(&createEmail, "email", "", "Email (required)")
	createCmd.Flags().StringVar(&createPassword, "password", "", "Password (required)")
	createCmd.Flags().StringVar(&createDisplayName, "display-name", "", "Display name (defaults to username)")
}

func runCreate(cmd *cobra.Command, args []string) error {
	if createUsername == "" {
		return errors.New("username is required (use --username)")
	}
	if createEmail == "" {
		return errors.New("email is required (use --email)")
	}
	if createPassword == "" {
		return errors.New("password is required (use --password)")
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	display := createDisplayName
	if display == "" {
		display = createUsername
	}

	ctx := context.Background()
	u, err := service.CreateUser(ctx, &core.CreateUserRequest{
		Username:    createUsername,
		Email:       createEmail,
		DisplayName: display,
		Password:    createPassword,
	})
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	fmt.Printf("User created: id=%d username=%s email=%s\n", u.ID, u.Username, u.Email)
	return nil
}
