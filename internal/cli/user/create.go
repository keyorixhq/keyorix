package user

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
	createCmd.Flags().StringVar(&createPassword, "password", "", "Initial password (INSECURE on the command line — prefer KEYORIX_INITIAL_PASSWORD or the interactive prompt; required in some form unless --setup-link or --one-time-password)")
	createCmd.Flags().StringVar(&createDisplayName, "display-name", "", "Display name (defaults to username)")
	createCmd.Flags().BoolVar(&createSetupLink, "setup-link", false, "Provision a setup link instead of an admin-set password (ADR-028)")
	createCmd.Flags().BoolVar(&createOneTimePassword, "one-time-password", false, "Generate a one-time password instead of an admin-set password (ADR-028 Part E); must be changed on first login")
	createCmd.Flags().StringVar(&createBy, "by", "", "Acting admin email (for audit; used with --setup-link / --one-time-password)")
}

func runCreate(cmd *cobra.Command, args []string) error { // NOSONAR -- cognitive complexity 33, suppress go:S3776
	if createUsername == "" {
		return errors.New("username is required (use --username)")
	}
	if createEmail == "" {
		return errors.New("email is required (use --email)")
	}
	if createSetupLink && createOneTimePassword {
		return errors.New("use either --setup-link or --one-time-password, not both")
	}

	// Resolve the initial password without ever requiring it on argv: the
	// (insecure, warned) --password flag if set, else KEYORIX_INITIAL_PASSWORD, else
	// an interactive no-echo prompt — mirroring `keyorix connect`'s resolveAPIKey /
	// resolveConnectPassword pattern. Not needed at all for --setup-link /
	// --one-time-password, which provision their own credential.
	var password string
	if !createSetupLink && !createOneTimePassword {
		pw, err := resolveInitialPassword(cmd)
		if err != nil {
			return err
		}
		if pw == "" {
			return errors.New("password is required (use --password, KEYORIX_INITIAL_PASSWORD, or the interactive prompt), or use --setup-link or --one-time-password")
		}
		password = pw
	}

	// Remote mode: go through the server so the user lands in the SAME store the
	// dashboard/API use, instead of a local SQLite file. All three credential modes
	// (password, setup-link, one-time-password) are forwarded to the server.
	if rc, ok := common.NewRemoteClient(); ok {
		return runCreateRemote(rc, password)
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
		Password:    password,
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

// runCreateRemote creates the user via POST /api/v1/users, forwarding whichever
// credential mode was requested (password, setup-link, or one-time-password), so
// the account lands in the server's store rather than a local SQLite file.
func runCreateRemote(rc *common.RemoteClient, password string) error {
	display := createDisplayName
	if display == "" {
		display = createUsername
	}
	body := map[string]interface{}{
		"username":     createUsername,
		"email":        createEmail,
		"display_name": display,
	}
	switch {
	case createSetupLink:
		body["deliver_setup_link"] = true
	case createOneTimePassword:
		body["generate_one_time_password"] = true
	default:
		body["password"] = password
	}

	// The response shape varies by mode:
	//   password:          the user object directly (data == user map)
	//   setup-link:        {"user": {...}, "setup_link": {...}}
	//   one-time-password: {"user": {...}, "one_time_password": {...}}
	// RemoteClient.Post already strips the outer {"data":…} envelope.
	var resp struct {
		// Classic password mode: server sends the user object as the data value.
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		// Setup-link and OTP modes: server nests the user under "user".
		User *struct {
			ID       uint   `json:"id"`
			Username string `json:"username"`
			Email    string `json:"email"`
		} `json:"user"`
		SetupLink *struct {
			Email        string `json:"email"`
			Channel      string `json:"channel"`
			Delivered    bool   `json:"delivered"`
			LinkForAdmin string `json:"link_for_admin,omitempty"`
		} `json:"setup_link"`
		OneTimePassword *struct {
			Email    string `json:"email"`
			OTPValue string `json:"one_time_password"`
		} `json:"one_time_password"`
	}
	if err := rc.Post(context.Background(), "/api/v1/users", body, &resp); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Determine which user fields to print: nested under "user" for setup-link/OTP,
	// flat for the classic password path.
	id, username, email := resp.ID, resp.Username, resp.Email
	if resp.User != nil {
		id, username, email = resp.User.ID, resp.User.Username, resp.User.Email
	}
	fmt.Printf("User created: id=%d username=%s email=%s\n", id, username, email)

	if resp.SetupLink != nil {
		sl := resp.SetupLink
		if sl.Delivered {
			fmt.Printf("Setup link delivered to %s via %s.\n", sl.Email, sl.Channel)
		} else {
			fmt.Printf("Setup link (relay this to %s securely — it is single-use and expires):\n  %s\n", sl.Email, sl.LinkForAdmin)
		}
	}
	if resp.OneTimePassword != nil {
		otp := resp.OneTimePassword
		fmt.Printf("One-time password for %s (relay securely — it must be changed on first login):\n  %s\n", otp.Email, otp.OTPValue) // codeql[go/clear-text-logging]
	}
	return nil
}

// resolveInitialPassword returns the new user's initial password without ever
// requiring it on argv: the (insecure, warned) --password flag if set, else
// KEYORIX_INITIAL_PASSWORD, else an interactive no-echo prompt. Mirrors
// `keyorix connect`'s resolveAPIKey/resolveConnectPassword argv-hygiene pattern
// (internal/cli/connect/connect.go) established earlier this campaign (#207/#208).
func resolveInitialPassword(cmd *cobra.Command) (string, error) {
	if createPassword != "" {
		fmt.Fprintln(os.Stderr, "⚠️  Passing --password on the command line is insecure (visible via ps/proc and saved in shell history); prefer the KEYORIX_INITIAL_PASSWORD environment variable, or omit it to be prompted.")
		return createPassword, nil
	}
	if pw := os.Getenv("KEYORIX_INITIAL_PASSWORD"); pw != "" {
		return pw, nil
	}
	fmt.Fprint(os.Stderr, "Initial password: ")
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(b), nil
}
