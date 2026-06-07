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
	createUsername        string
	createEmail           string
	createPassword        string
	createDisplayName     string
	createSetupLink       bool
	createOneTimePassword bool
	createBy              string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	Long: "Create a new user. Supply --password to set an initial password, or use\n" +
		"--setup-link to provision an ADR-028 setup link instead: the account is created\n" +
		"in pending_first_login state and the user sets their own password via the link.\n" +
		"In out-of-band mode the link is printed for you to relay.\n\n" +
		"Or use --one-time-password to have the server generate an initial password\n" +
		"(ADR-028 Part E): the account is created in password_reset_required state, the\n" +
		"password is printed once for you to relay, and the user must change it on first\n" +
		"login.",
	RunE: runCreate,
}

func init() {
	createCmd.Flags().StringVar(&createUsername, "username", "", "Username (required)")
	createCmd.Flags().StringVar(&createEmail, "email", "", "Email (required)")
	createCmd.Flags().StringVar(&createPassword, "password", "", "Initial password (required unless --setup-link or --one-time-password)")
	createCmd.Flags().StringVar(&createDisplayName, "display-name", "", "Display name (defaults to username)")
	createCmd.Flags().BoolVar(&createSetupLink, "setup-link", false, "Provision a setup link instead of an admin-set password (ADR-028)")
	createCmd.Flags().BoolVar(&createOneTimePassword, "one-time-password", false, "Generate a one-time password instead of an admin-set password (ADR-028 Part E); must be changed on first login")
	createCmd.Flags().StringVar(&createBy, "by", "", "Acting admin email (for audit; used with --setup-link / --one-time-password)")
}

func runCreate(cmd *cobra.Command, args []string) error {
	if createUsername == "" {
		return errors.New("username is required (use --username)")
	}
	if createEmail == "" {
		return errors.New("email is required (use --email)")
	}
	if createSetupLink && createOneTimePassword {
		return errors.New("use either --setup-link or --one-time-password, not both")
	}
	if !createSetupLink && !createOneTimePassword && createPassword == "" {
		return errors.New("password is required (use --password), or use --setup-link or --one-time-password")
	}

	// Remote mode: go through the server so the user lands in the SAME store the
	// dashboard/API use, instead of a local SQLite file. Currently the password
	// mode is supported remotely; the setup-link / one-time-password provisioning
	// flows are embedded-only for now.
	if rc, ok := common.NewRemoteClient(); ok {
		if createSetupLink || createOneTimePassword {
			return errors.New("--setup-link / --one-time-password are not yet supported in remote mode; use --password, or run this command on the server host")
		}
		return runCreateRemote(rc)
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

	if createOneTimePassword {
		var createdBy uint
		if createBy != "" {
			if createdBy, err = resolveAdminID(ctx, service, createBy); err != nil {
				return err
			}
		}
		u, otp, err := service.CreateUserWithOneTimePassword(ctx, req, createdBy)
		if err != nil {
			return fmt.Errorf("failed to create user with one-time password: %w", err)
		}
		fmt.Printf("User created: id=%d username=%s email=%s\n", u.ID, u.Username, u.Email)
		common.PrintOneTimePasswordResult(otp)
		return nil
	}

	u, err := service.CreateUser(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	fmt.Printf("User created: id=%d username=%s email=%s\n", u.ID, u.Username, u.Email)
	return nil
}

// runCreateRemote creates the user via POST /api/v1/users (password mode), so it
// lands in the server's store rather than a local SQLite file.
func runCreateRemote(rc *common.RemoteClient) error {
	display := createDisplayName
	if display == "" {
		display = createUsername
	}
	body := map[string]string{
		"username":     createUsername,
		"email":        createEmail,
		"display_name": display,
		"password":     createPassword,
	}
	var u struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := rc.Post(context.Background(), "/api/v1/users", body, &u); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	fmt.Printf("User created: id=%d username=%s email=%s\n", u.ID, u.Username, u.Email)
	return nil
}
