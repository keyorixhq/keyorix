package user

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
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
// admin's email via --by (mirrors the invite/request CLI). This ONLY resolves
// the email to an ID — it proves nothing about the caller's authority to act
// as that user. Every call site must follow up with requireUserAuthority
// before crediting the resolved actor with the operation.
func resolveAdminID(ctx context.Context, service *core.KeyorixCore, email string) (uint, error) {
	u, err := service.GetUserByEmail(ctx, email)
	if err != nil {
		return 0, fmt.Errorf("no user found for --by %q: %w", email, err)
	}
	return u.ID, nil
}

// requireUserAuthority verifies that actorID — the user resolved from --by —
// actually holds the permission the equivalent HTTP route requires for this
// exact account-lifecycle operation (see router.go: "users.delete" gates
// DELETE /users/{id}; "users.write" gates suspend/reactivate/
// require-password-reset/revoke-sessions/resend-setup-link/create). The local
// CLI has no session/middleware to enforce this, so --by resolving ANY email —
// with zero authority check — would let a local operator attribute an
// arbitrary destructive account-lifecycle action (suspending/deleting a user)
// to any other admin's identity purely for what appears in the audit trail.
// None of the KeyorixCore methods these commands call (SuspendUser,
// ReactivateUser, DeleteUser, etc.) check permissions themselves (the HTTP
// handler's job is done by router middleware), so this must be verified here,
// at the CLI entrypoint, before the resolved actor is credited with the
// action. Sibling of requireInviteAuthority/requireReviewAuthority/
// requireTemplateAuthority (#264/#491).
func requireUserAuthority(ctx context.Context, svc *core.KeyorixCore, actorID uint, permission string) error {
	ok, err := svc.Authorize(ctx, actorID, permission, core.Scope{})
	if err != nil {
		return common.ByAuthorityUnavailableError(err,
			"run the equivalent request directly against the hub instead -- POST /api/v1/users/{id}/suspend, "+
				"/reactivate, /revoke-sessions, /resend-setup-link, or /require-password-reset, or DELETE "+
				"/api/v1/users/{id} -- authenticated with your own real session (e.g. via 'keyorix connect'), "+
				"since the hub, not this shared credential, decides who may act")
	}
	if !ok {
		return fmt.Errorf("--by actor does not hold %s; refusing to attribute this action to them", permission)
	}
	return nil
}

// Permission strings mirroring the equivalent HTTP routes in
// server/http/router.go (permUsersWrite / "users.delete"), used by
// requireUserAuthority.
const (
	permUsersWrite  = "users.write"
	permUsersDelete = "users.delete"
)
