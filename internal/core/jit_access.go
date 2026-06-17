// jit_access.go — just-in-time / time-bound role grants. A grant carries an
// optional expiry; the storage authorization queries deny it the instant it
// passes, and RemoveExpiredRoleGrants (run by the JIT scheduler) sweeps the rows
// and audits each auto-expiry. The grant itself is created via the access-request
// approval flow (invitations.go) or directly through these helpers.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// AssignUserRoleWithExpiry assigns a time-bound role to a user at scope (the grant
// stops authorizing once expiresAt passes) and records the assignment. actorID is
// the granting principal (0 = unauthenticated/system).
func (c *KeyorixCore) AssignUserRoleWithExpiry(ctx context.Context, actorID, userID, roleID uint, scope Scope, expiresAt time.Time) error {
	if err := c.storage.AssignRoleWithExpiry(ctx, userID, roleID, scope, expiresAt); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogRoleAssigned(ctx, actorID, userID, roleID, scope)
	return nil
}

// AssignGroupRoleWithExpiry assigns a time-bound role to a group at scope; see
// AssignUserRoleWithExpiry.
func (c *KeyorixCore) AssignGroupRoleWithExpiry(ctx context.Context, actorID, groupID, roleID uint, scope Scope, expiresAt time.Time) error {
	if err := c.storage.AssignRoleToGroupWithExpiry(ctx, groupID, roleID, scope, expiresAt); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogGroupRoleAssigned(ctx, actorID, groupID, roleID, scope)
	return nil
}

// EventShareExpired is audited when a time-bound secret share is swept after expiry.
const EventShareExpired = "share.expired"

// RemoveExpiredShares removes every time-bound secret share whose expiry is at or
// before `before` and audits each as share.expired (the system sweep, no actor).
// Returns the number removed. Idempotent. Expired shares already stop authorizing
// the instant they pass (the permission queries filter on expiry); this just reclaims
// the rows and writes the expiry audit trail. Backs the JIT access-expiry scheduler.
func (c *KeyorixCore) RemoveExpiredShares(ctx context.Context, before time.Time) (int, error) {
	removed, err := c.storage.DeleteExpiredShareRecords(ctx, before)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	for _, s := range removed {
		sid := s.SecretID
		recipientKind := "user"
		if s.IsGroup {
			recipientKind = "group"
		}
		c.writeAuditEvent(ctx, EventShareExpired, nil, &sid,
			fmt.Sprintf("time-bound share of secret %d expired for %s %d", s.SecretID, recipientKind, s.RecipientID))
	}
	return len(removed), nil
}

// RemoveExpiredRoleGrants removes every user/group role grant whose expiry is at or
// before `before` and audits each as role.expired (actor 0 = the system sweep).
// Returns the number of grants removed. Idempotent — a tick that finds nothing
// removes nothing. Backs the JIT access-expiry scheduler.
func (c *KeyorixCore) RemoveExpiredRoleGrants(ctx context.Context, before time.Time) (int, error) {
	removed, err := c.storage.DeleteExpiredRoleGrants(ctx, before)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	for _, g := range removed {
		scope := Scope{ProjectID: g.ProjectID, EnvironmentID: g.EnvironmentID}
		detail := rbacAuditDetail{
			RoleID:        g.RoleID,
			ProjectID:     g.ProjectID,
			EnvironmentID: g.EnvironmentID,
		}
		var desc string
		if g.PrincipalType == "group" {
			detail.GroupID = g.PrincipalID
			desc = fmt.Sprintf("role %d expired for group %d", g.RoleID, g.PrincipalID)
		} else {
			detail.TargetUserID = g.PrincipalID
			desc = fmt.Sprintf("role %d expired for user %d", g.RoleID, g.PrincipalID)
		}
		c.writeRBACAudit(ctx, EventRoleExpired, desc, 0, scope, detail)
	}
	return len(removed), nil
}
