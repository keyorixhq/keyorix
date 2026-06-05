// lifecycle.go — account-state transitions for the user CLI (ADR-025).
//
// suspend / reactivate / force-password-reset wire the account-state machine
// (internal/core/account_state.go) for operators who manage users from the
// command line. Each takes the target user via --id and the acting admin's
// email via --by (the local CLI has no session, so --by supplies the audited
// actor). Mirrors the keyorix machine and request CLI groups.
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
	suspendUserID            uint
	suspendBy                string
	reactivateUserID         uint
	reactivateBy             string
	forcePasswordResetUserID uint
	forcePasswordResetBy     string
)

var suspendCmd = &cobra.Command{
	Use:   "suspend",
	Short: "Suspend a user (blocks login)",
	Long:  "Suspend a user account. A suspended user is refused login entirely until reactivated.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runLifecycle(suspendUserID, suspendBy, "suspended",
			func(s *core.KeyorixCore, ctx context.Context, adminID, userID uint) error {
				return s.SuspendUser(ctx, adminID, userID)
			})
	},
}

var reactivateCmd = &cobra.Command{
	Use:   "reactivate",
	Short: "Reactivate a user (restores login)",
	Long:  "Return a suspended (or otherwise non-active) user to the active state.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runLifecycle(reactivateUserID, reactivateBy, "reactivated",
			func(s *core.KeyorixCore, ctx context.Context, adminID, userID uint) error {
				return s.ReactivateUser(ctx, adminID, userID)
			})
	},
}

var forcePasswordResetCmd = &cobra.Command{
	Use:   "force-password-reset",
	Short: "Require a user to change their password at next login",
	Long: "Force a user into a restricted session until they change their password.\n" +
		"They can authenticate but every endpoint except change-password is blocked until then.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runLifecycle(forcePasswordResetUserID, forcePasswordResetBy, "required to reset their password",
			func(s *core.KeyorixCore, ctx context.Context, adminID, userID uint) error {
				return s.RequirePasswordReset(ctx, adminID, userID)
			})
	},
}

func init() {
	suspendCmd.Flags().UintVar(&suspendUserID, "id", 0, "Target user ID (required)")
	suspendCmd.Flags().StringVar(&suspendBy, "by", "", "Acting admin email (required, for audit)")
	_ = suspendCmd.MarkFlagRequired("id")
	_ = suspendCmd.MarkFlagRequired("by")

	reactivateCmd.Flags().UintVar(&reactivateUserID, "id", 0, "Target user ID (required)")
	reactivateCmd.Flags().StringVar(&reactivateBy, "by", "", "Acting admin email (required, for audit)")
	_ = reactivateCmd.MarkFlagRequired("id")
	_ = reactivateCmd.MarkFlagRequired("by")

	forcePasswordResetCmd.Flags().UintVar(&forcePasswordResetUserID, "id", 0, "Target user ID (required)")
	forcePasswordResetCmd.Flags().StringVar(&forcePasswordResetBy, "by", "", "Acting admin email (required, for audit)")
	_ = forcePasswordResetCmd.MarkFlagRequired("id")
	_ = forcePasswordResetCmd.MarkFlagRequired("by")
}

// runLifecycle is the shared body for the three account-state commands: it
// validates flags, resolves the admin actor, applies the transition, and prints
// a confirmation. pastTense fills the "User N has been <pastTense>." message.
func runLifecycle(userID uint, by, pastTense string, apply func(*core.KeyorixCore, context.Context, uint, uint) error) error {
	if userID == 0 {
		return errors.New("user id is required (use --id)")
	}
	if by == "" {
		return errors.New("acting admin email is required (use --by)")
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	adminID, err := resolveAdminID(ctx, service, by)
	if err != nil {
		return err
	}

	if err := apply(service, ctx, adminID, userID); err != nil {
		return fmt.Errorf("failed: %w", err)
	}
	fmt.Printf("User %d has been %s.\n", userID, pastTense)
	return nil
}
