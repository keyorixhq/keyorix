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
	createSetupLink   bool
	createBy          string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	Long: "Create a new user. Supply --password to set an initial password, or use\n" +
		"--setup-link to provision an ADR-028 setup link instead: the account is created\n" +
		"in pending_first_login state and the user sets their own password via the link.\n" +
		"In out-of-band mode the link is printed for you to relay.",
	RunE: runCreate,
}

func init() {
	createCmd.Flags().StringVar(&createUsername, "username", "", "Username (required)")
	createCmd.Flags().StringVar(&createEmail, "email", "", "Email (required)")
	createCmd.Flags().StringVar(&createPassword, "password", "", "Initial password (required unless --setup-link)")
	createCmd.Flags().StringVar(&createDisplayName, "display-name", "", "Display name (defaults to username)")
	createCmd.Flags().BoolVar(&createSetupLink, "setup-link", false, "Provision a setup link instead of an admin-set password (ADR-028)")
	createCmd.Flags().StringVar(&createBy, "by", "", "Acting admin email (for audit; used with --setup-link)")
}

func runCreate(cmd *cobra.Command, args []string) error {
	if createUsername == "" {
		return errors.New("username is required (use --username)")
	}
	if createEmail == "" {
		return errors.New("email is required (use --email)")
	}
	if !createSetupLink && createPassword == "" {
		return errors.New("password is required (use --password), or use --setup-link")
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
	req := &core.CreateUserRequest{
		Username:    createUsername,
		Email:       createEmail,
		DisplayName: display,
		Password:    createPassword,
	}

	if createSetupLink {
		var createdBy uint
		if createBy != "" {
			if createdBy, err = resolveAdminID(ctx, service, createBy); err != nil {
				return err
			}
		}
		u, prov, err := service.CreateUserWithSetupLink(ctx, req, createdBy)
		if err != nil {
			return fmt.Errorf("failed to create user with setup link: %w", err)
		}
		fmt.Printf("User created: id=%d username=%s email=%s\n", u.ID, u.Username, u.Email)
		common.PrintProvisionResult(prov)
		return nil
	}

	u, err := service.CreateUser(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	fmt.Printf("User created: id=%d username=%s email=%s\n", u.ID, u.Username, u.Email)
	return nil
}
