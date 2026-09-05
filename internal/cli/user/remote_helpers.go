// remote_helpers.go — shared remote-mode helpers for the user CLI's
// account-lifecycle commands (suspend, reactivate, force-password-reset,
// revoke-sessions, delete, resend-setup-link).
//
// Every one of those commands must show the operator WHICH account and WHICH
// server it is about to affect before acting, not just print "Success"
// afterward -- an incident responder running `keyorix user suspend --id 42`
// believing they're hitting production must never be left guessing whether
// that's what actually happened. remoteUserLabel is the one place that
// resolves a human-readable "user <id> (<email>)" label, shared by every
// command above instead of each re-deriving its own.
package user

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
)

// remoteUserLabel resolves "user <id> (<email>)" via GET /api/v1/users/{id}
// against the connected server. A lookup failure (permission denied, the
// target already deleted, a transient error) falls back to the bare
// "user <id>" -- this is a display nicety for the operator, never a
// precondition for the actual mutating call that follows it, so it must not
// block or alter that call's outcome.
func remoteUserLabel(ctx context.Context, rc *common.RemoteClient, userID uint) string {
	var u struct {
		Email string `json:"email"`
	}
	if err := rc.Get(ctx, fmt.Sprintf("/api/v1/users/%d", userID), &u); err != nil || u.Email == "" {
		return fmt.Sprintf("user %d", userID)
	}
	return fmt.Sprintf("user %d (%s)", userID, u.Email)
}
