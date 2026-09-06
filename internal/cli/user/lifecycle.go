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

const (
	descActingAdminEmail = "Acting admin email (required, for audit)"
	descTargetUserID     = "Target user ID (required)"
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
		if suspendUserID == 0 {
			return errors.New("user id is required (use --id)")
		}
		if suspendBy == "" {
			return errors.New("acting admin email is required (use --by)")
		}
		if rc, ok := common.NewRemoteClient(); ok {
			return runAccountStateRemote(rc, suspendUserID, "suspend", "Suspending", "suspended")
		}
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
		if reactivateUserID == 0 {
			return errors.New("user id is required (use --id)")
		}
		if reactivateBy == "" {
			return errors.New("acting admin email is required (use --by)")
		}
		if rc, ok := common.NewRemoteClient(); ok {
			return runAccountStateRemote(rc, reactivateUserID, "reactivate", "Reactivating", "reactivated")
		}
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
		if forcePasswordResetUserID == 0 {
			return errors.New("user id is required (use --id)")
		}
		if forcePasswordResetBy == "" {
			return errors.New("acting admin email is required (use --by)")
		}
		if rc, ok := common.NewRemoteClient(); ok {
			return runAccountStateRemote(rc, forcePasswordResetUserID, "require-password-reset", "Requiring a password reset for", "required to reset their password")
		}
		return runLifecycle(forcePasswordResetUserID, forcePasswordResetBy, "required to reset their password",
			func(s *core.KeyorixCore, ctx context.Context, adminID, userID uint) error {
				return s.RequirePasswordReset(ctx, adminID, userID)
			})
	},
}

var (
	revokeSessionsUserID uint
	revokeSessionsBy     string
)

var revokeSessionsCmd = &cobra.Command{
	Use:   "revoke-sessions",
	Short: "Force-logout a user (revoke all active sessions)",
	Long: "Terminate every active session of a user immediately, without changing their\n" +
		"account state — for suspected session/token theft. The user can log back in after\n" +
		"re-authenticating. To block login entirely, use 'suspend' instead.",
	RunE: func(_ *cobra.Command, _ []string) error {
		if revokeSessionsUserID == 0 {
			return errors.New("user id is required (use --id)")
		}
		if revokeSessionsBy == "" {
			return errors.New("acting admin email is required (use --by)")
		}
		if rc, ok := common.NewRemoteClient(); ok {
			return runRevokeSessionsRemote(rc, revokeSessionsUserID)
		}
		service, err := common.InitializeCoreService()
		if err != nil {
			return fmt.Errorf("failed to initialize service: %w", err)
		}
		ctx := context.Background()
		adminID, err := resolveAdminID(ctx, service, revokeSessionsBy)
		if err != nil {
			return err
		}
		if err := requireUserAuthority(ctx, service, adminID, permUsersWrite); err != nil {
			return err
		}
		n, err := service.RevokeUserSessions(ctx, adminID, revokeSessionsUserID)
		if err != nil {
			return fmt.Errorf("failed: %w", err)
		}
		fmt.Printf("Revoked %d active session(s) for user %d.\n", n, revokeSessionsUserID)
		return nil
	},
}

func init() {
	suspendCmd.Flags().UintVar(&suspendUserID, "id", 0, descTargetUserID)
	suspendCmd.Flags().StringVar(&suspendBy, "by", "", descActingAdminEmail)
	_ = suspendCmd.MarkFlagRequired("id")
	_ = suspendCmd.MarkFlagRequired("by")

	reactivateCmd.Flags().UintVar(&reactivateUserID, "id", 0, descTargetUserID)
	reactivateCmd.Flags().StringVar(&reactivateBy, "by", "", descActingAdminEmail)
	_ = reactivateCmd.MarkFlagRequired("id")
	_ = reactivateCmd.MarkFlagRequired("by")

	forcePasswordResetCmd.Flags().UintVar(&forcePasswordResetUserID, "id", 0, descTargetUserID)
	forcePasswordResetCmd.Flags().StringVar(&forcePasswordResetBy, "by", "", descActingAdminEmail)
	_ = forcePasswordResetCmd.MarkFlagRequired("id")
	_ = forcePasswordResetCmd.MarkFlagRequired("by")

	revokeSessionsCmd.Flags().UintVar(&revokeSessionsUserID, "id", 0, descTargetUserID)
	revokeSessionsCmd.Flags().StringVar(&revokeSessionsBy, "by", "", descActingAdminEmail)
	_ = revokeSessionsCmd.MarkFlagRequired("id")
	_ = revokeSessionsCmd.MarkFlagRequired("by")
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
	if err := requireUserAuthority(ctx, service, adminID, permUsersWrite); err != nil {
		return err
	}

	if err := apply(service, ctx, adminID, userID); err != nil {
		return fmt.Errorf("failed: %w", err)
	}
	fmt.Printf("User %d has been %s.\n", userID, pastTense)
	return nil
}

// runAccountStateRemote performs the suspend/reactivate/require-password-reset
// transition against the connected server (POST /api/v1/users/{id}/<action>,
// server/http/router.go), landing it in the SAME account-state machine
// (setAccountState, ADR-025) the dashboard/API use, instead of a stray local
// SQLite file. The acting admin is the session identity behind the configured
// bearer token, not --by (which only has meaning for the local/embedded
// audit trail -- see resolveAdminID's doc comment). verbing/pastTense fill the
// "<verbing> <label> on <endpoint>..." / "<label> has been <pastTense> on
// <endpoint>." messages so an operator always sees which account AND which
// server were actually affected, never a bare "Success."
func runAccountStateRemote(rc *common.RemoteClient, userID uint, action, verbing, pastTense string) error {
	ctx := context.Background()
	label := remoteUserLabel(ctx, rc, userID)
	fmt.Printf("%s %s on %s...\n", verbing, label, rc.Endpoint)
	if err := rc.Post(ctx, fmt.Sprintf("/api/v1/users/%d/%s", userID, action), struct{}{}, nil); err != nil {
		return fmt.Errorf("failed to change account state for %s on %s: %w", label, rc.Endpoint, err)
	}
	fmt.Printf("%s has been %s on %s.\n", label, pastTense, rc.Endpoint)
	return nil
}

// runRevokeSessionsRemote force-logs-out a user via POST
// /api/v1/users/{id}/revoke-sessions against the connected server, so the
// revoked sessions are the user's REAL active sessions on that server,
// instead of whatever happened to be sitting in a stray local SQLite file. A
// destructive/security-sensitive action, so the response echoes the exact
// count revoked (never a bare "Success") -- including the zero case, stated
// explicitly rather than swallowed.
func runRevokeSessionsRemote(rc *common.RemoteClient, userID uint) error {
	ctx := context.Background()
	label := remoteUserLabel(ctx, rc, userID)
	fmt.Printf("Revoking active sessions for %s on %s...\n", label, rc.Endpoint)

	var resp struct {
		Revoked int `json:"revoked"`
	}
	if err := rc.Post(ctx, fmt.Sprintf("/api/v1/users/%d/revoke-sessions", userID), struct{}{}, &resp); err != nil {
		return fmt.Errorf("failed to revoke sessions for %s on %s: %w", label, rc.Endpoint, err)
	}
	if resp.Revoked == 0 {
		fmt.Printf("0 sessions revoked for %s on %s -- none were active.\n", label, rc.Endpoint)
		return nil
	}
	fmt.Printf("Revoked %d active session(s) for %s on %s.\n", resp.Revoked, label, rc.Endpoint)
	return nil
}
