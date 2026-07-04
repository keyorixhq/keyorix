// impersonation.go — admin impersonation sessions and their audit trail.
//
// An admin starts impersonation of a target user; Keyorix issues a SEPARATE,
// short-lived session for the target user that records the initiating admin
// (Session.ImpersonatedBy). The admin's own session is left untouched, so the
// frontend swaps to the impersonation token and can swap back to the admin
// token without re-authentication ("Return to Admin").
//
// Discrete impersonation.start / impersonation.end events bracket the session.
// The end event reports duration and the count of actions taken while
// impersonating. Every action in between is tagged impersonation=true via the
// context propagation in audit_context.go.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// impersonationSessionTTL bounds how long an impersonation session is valid.
// Shorter than a normal 24h session — impersonation is a privileged, audited act.
const impersonationSessionTTL = 1 * time.Hour

// EventImpersonationStart / EventImpersonationEnd are the discrete bracket events.
const (
	EventImpersonationStart = "impersonation.start"
	EventImpersonationEnd   = "impersonation.end"
)

// StartImpersonation issues an impersonation session for targetID initiated by
// adminID and logs an impersonation.start event. Returns the new session (whose
// token the caller should hand back to the admin's client) and the target user.
func (c *KeyorixCore) StartImpersonation(ctx context.Context, adminID, targetID uint, ip string) (*models.Session, *models.User, error) {
	if adminID == targetID {
		return nil, nil, fmt.Errorf("cannot impersonate yourself")
	}
	// A request authenticated with a least-privilege PAT (ADR-042) must not LAUNDER that
	// restriction through impersonation: the impersonation session is a plain session
	// carrying no restriction, so it would act as the target with the target's FULL
	// permissions — escaping the bound the PAT deliberately imposed. Refuse, mirroring
	// IsGlobalAdmin's fail-closed convention for the PAT restriction.
	if patRestrictionFromContext(ctx) != nil {
		return nil, nil, fmt.Errorf("a restricted access token may not start impersonation")
	}
	admin, err := c.storage.GetUser(ctx, adminID)
	if err != nil {
		return nil, nil, fmt.Errorf("admin not found")
	}
	target, err := c.storage.GetUser(ctx, targetID)
	if err != nil {
		return nil, nil, fmt.Errorf("target user not found")
	}
	// Don't mint a session for a target who cannot log in: it would be dead on arrival
	// (ValidateSessionToken rejects blocked/inactive accounts on every request) and would
	// only produce a misleading impersonation.start audit event.
	if !target.IsActive || AccountLoginBlocked(target.AccountState) {
		return nil, nil, fmt.Errorf("cannot impersonate a suspended or inactive user")
	}
	// Admin-rank-ceiling check (#165): the impersonator must already hold authority
	// equal to or greater than the target's, at EVERY scope the target holds it —
	// not just the global scope a plain IsGlobalAdmin(target) check would catch.
	// Without this, a principal holding only users.impersonate (a permission that
	// by CONVENTION only global admins hold, but nothing enforces that as an
	// invariant) could impersonate an actual admin — global OR project-scoped,
	// direct OR group-inherited — then use that session to grant their own real
	// account admin via the ordinary role-assignment endpoints; the privilege
	// persists after the impersonation session ends. Today users.impersonate is
	// satisfiable only by global admins by convention, so for the common case this
	// check is a no-op; it keeps impersonation from escalating if that permission
	// is ever delegated to a lower-privileged (sub-admin) role, or if the target is
	// merely a project-scoped project_admin the older global-only check never saw.
	if err := c.requireEqualOrGreaterAdminAuthority(ctx, adminID, targetID, "impersonate"); err != nil {
		return nil, nil, err
	}
	token, err := generateSecureToken()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate session token: %w", err)
	}
	now := c.now()
	expiresAt := now.Add(impersonationSessionTTL)
	session := &models.Session{
		UserID:                 target.ID,
		SessionToken:           token,
		ImpersonatedBy:         &adminID,
		ImpersonationStartedAt: &now,
		LastSeenAt:             &now,
		ExpiresAt:              &expiresAt,
	}
	created, err := c.storage.CreateSession(ctx, session)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create impersonation session: %w", err)
	}
	c.writeImpersonationEvent(ctx, EventImpersonationStart, adminID, targetID, ip,
		fmt.Sprintf("%s started impersonating %s", admin.Username, target.Username), "")
	return created, target, nil
}

// EndImpersonation terminates the impersonation session identified by token,
// logging an impersonation.end event with the session duration and the number
// of actions taken while impersonating. The token must belong to an
// impersonation session. Restoring the admin's own session is a caller (HTTP
// handler) concern — see admin_impersonation.go's End, which stashes the
// admin's token in a second cookie at Start and reads it back here, rather than
// this core layer trying to recall a plaintext token it never retains (session
// tokens are stored only as a hash, see local_auth.go's hashSessionToken).
func (c *KeyorixCore) EndImpersonation(ctx context.Context, token string) error {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return fmt.Errorf("session not found")
	}
	if session.ImpersonatedBy == nil {
		return fmt.Errorf("not an impersonation session")
	}
	adminID := *session.ImpersonatedBy
	targetID := session.UserID

	start := c.now()
	if session.ImpersonationStartedAt != nil {
		start = *session.ImpersonationStartedAt
	}
	duration := c.now().Sub(start)
	actions, _ := c.storage.CountImpersonatedActions(ctx, targetID, adminID, start)

	diff := fmt.Sprintf(`{"duration_seconds":%d,"action_count":%d}`, int64(duration.Seconds()), actions)
	desc := fmt.Sprintf("impersonation ended after %s (%d action(s))", duration.Round(time.Second), actions)
	c.writeImpersonationEvent(ctx, EventImpersonationEnd, adminID, targetID, session.IPAddress, desc, diff)

	return c.storage.DeleteSession(ctx, session.ID)
}

// SessionImpersonator returns the initiating admin ID if token belongs to an
// impersonation session, or nil otherwise. Used by the auth middleware to tag
// the request context so downstream audit events are marked impersonated.
func (c *KeyorixCore) SessionImpersonator(ctx context.Context, token string) *uint {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return nil
	}
	return session.ImpersonatedBy
}

// writeImpersonationEvent records an audit event with explicit impersonation
// attribution (ImpersonatedBy = admin, ActingAs = target, Impersonation = true).
func (c *KeyorixCore) writeImpersonationEvent(ctx context.Context, eventType string, adminID, targetID uint, ip, description, diff string) {
	t := true
	ab, ta := adminID, targetID
	event := &models.AuditEvent{
		EventType:      eventType,
		UserID:         &ta,
		IPAddress:      ip,
		Description:    description,
		Success:        &t,
		EventTime:      time.Now(),
		Diff:           diff,
		ImpersonatedBy: &ab,
		ActingAs:       &ta,
		Impersonation:  true,
	}
	c.emitAudit(ctx, event)
}
