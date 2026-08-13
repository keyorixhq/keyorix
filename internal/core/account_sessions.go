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

	// #G06: the eviction list must be built from the SAME (user_id=? OR
	// impersonated_by=?) predicate DeleteSessionsForUserExcept below actually
	// deletes with — ListSessionsByUser only matches user_id, so a session this
	// user STARTED as an impersonator (impersonated_by = userID) was deleted from
	// the DB but never evicted from the auth cache, leaving it live until the
	// positive-cache TTL expired. ListSessionTokenHashesForUser already unions
	// both predicates (it backs the same eviction need on other state-change
	// paths) and returns the exact session_token hashes invalidateTokenCache needs.
	tokens, err := c.storage.ListSessionTokenHashesForUser(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to list sessions: %w", err)
	}
	n := len(tokens)
	// exceptID 0 matches no session, so this drops them all.
	if err := c.storage.DeleteSessionsForUserExcept(ctx, userID, 0); err != nil {
		return 0, fmt.Errorf("failed to revoke sessions: %w", err)
	}
	// Evict every revoked session from the HTTP auth cache so a compromised token stops
	// authenticating on the NEXT request instead of lingering for the positive-cache TTL
	// — this is the incident-response control, so the residual window matters. The stored
	// session_token IS the SHA-256 cache key.
	c.invalidateTokenCache(tokens...)

	aid := adminID
	c.writeAuditEventFull(ctx, EventUserSessionsRevoked, &aid, nil, nil, "",
		fmt.Sprintf("revoked %d active session(s) for user %d", n, userID))
	return n, nil
}
