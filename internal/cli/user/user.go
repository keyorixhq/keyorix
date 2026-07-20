package user

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

// UserCmd is the root command for user operations.
var UserCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users",
	Long:  "Create, read, update, delete, list, and manage the account lifecycle of users in the local database.",
}

func init() {
	UserCmd.AddCommand(createCmd)
	UserCmd.AddCommand(getCmd)
	UserCmd.AddCommand(updateCmd)
	UserCmd.AddCommand(deleteCmd)
	UserCmd.AddCommand(listCmd)
	UserCmd.AddCommand(suspendCmd)
	UserCmd.AddCommand(reactivateCmd)
	UserCmd.AddCommand(forcePasswordResetCmd)
	UserCmd.AddCommand(revokeSessionsCmd)
	UserCmd.AddCommand(resendSetupLinkCmd)
	UserCmd.AddCommand(suspendInactiveCmd)
}

// resolveAdminID resolves an admin email to a user ID for audit attribution.
// The local CLI has no session, so account-lifecycle commands take the acting
// admin's email via --by (mirrors the invite/request CLI).
func resolveAdminID(ctx context.Context, service *core.KeyorixCore, email string) (uint, error) {
	u, err := service.GetUserByEmail(ctx, email)
	if err != nil {
		return 0, fmt.Errorf("no user found for --by %q: %w", email, err)
	}
	return u.ID, nil
}
