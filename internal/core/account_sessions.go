// account_sessions.go — admin force-logout: revoke every active session of a user
// without changing their account state. Distinct from suspension (which also drops
// sessions but blocks login): use this when a user's sessions may be compromised
// (stolen laptop, leaked token) but the account should stay active once they
// re-authenticate. Complements offboarding ([[secret_orphaned]]) and PAT hygiene
// ([[pat_hygiene]]) — the human-session half of cutting off access. Admin-only
// (route-gated users.write); audited.
package core

import (
	"context"
	"fmt"
)

// EventUserSessionsRevoked is audited when an admin force-logs-out a user.
const EventUserSessionsRevoked = "account.sessions_revoked"

// RevokeUserSessions terminates every active session belonging to userID, returning
// the number revoked. The account state is left unchanged — the user can log back in.
// adminID is the actor (for the audit trail).
func (c *KeyorixCore) RevokeUserSessions(ctx context.Context, adminID, userID uint) (int, error) {
	if userID == 0 {
		return 0, fmt.Errorf("user ID is required")
	}
	if _, err := c.storage.GetUser(ctx, userID); err != nil {
		return 0, fmt.Errorf("user not found: %w", err)
	}

	sessions, err := c.storage.ListSessionsByUser(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to list sessions: %w", err)
	}
	n := len(sessions)
	// exceptID 0 matches no session, so this drops them all.
	if err := c.storage.DeleteSessionsForUserExcept(ctx, userID, 0); err != nil {
		return 0, fmt.Errorf("failed to revoke sessions: %w", err)
	}

	aid := adminID
	c.writeAuditEventFull(ctx, EventUserSessionsRevoked, &aid, nil, nil, "",
		fmt.Sprintf("revoked %d active session(s) for user %d", n, userID))
	return n, nil
}
