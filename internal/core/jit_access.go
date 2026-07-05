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
//
// KNOWN GAP (tracked, not fixed here): unlike AssignUserRole, this does NOT run
// requireGranterHoldsRolePermissions (#93/#107/#141) — it writes directly via
// storage, bypassing the grant-ceiling check entirely. The HTTP JIT-assign-with-
// expiry path (POST /user-roles with expires_at) and the access-request TTL-grant
// path (invitations.go) both reach this unguarded, so a roles.assign holder can
// currently bundle-grant a time-bound role with a permission they don't hold. Left
// unfixed in this change deliberately: break_glass.go's self-service emergency
// grant also calls this, and legitimately MUST elevate a user beyond their current
// permissions (that's break-glass's entire purpose) — closing this gap needs a
// break-glass-aware carve-out, which is its own follow-up, not a mechanical mirror
// of AssignUserRole's fix.
//
// #419: the separation-of-duties preventive gate (requireNoSoDViolation) DOES
// apply here by default, unlike the ceiling check above — this is precisely the
// JIT-timing-evasion vector the finding describes ("a toxic-permission overlap
// that both starts and fully expires between two SoD digest runs ... concretely
// constructible by arranging two overlapping short-lived grants"). Break-glass
// is the one caller that legitimately cannot be blocked by it (same reasoning as
// the ceiling-check gap above): see assignUserRoleWithExpirySkipSoD, which
// break_glass.go calls instead.
func (c *KeyorixCore) AssignUserRoleWithExpiry(ctx context.Context, actorID, userID, roleID uint, scope Scope, expiresAt time.Time) error {
	if err := c.requireNoSoDViolation(ctx, userID, roleID); err != nil {
		return err
	}
	return c.assignUserRoleWithExpirySkipSoD(ctx, actorID, userID, roleID, scope, expiresAt)
}

// assignUserRoleWithExpirySkipSoD performs the identical time-bound grant as
// AssignUserRoleWithExpiry but deliberately SKIPS the #419 separation-of-duties
// preventive check. Use it ONLY where the action is break-glass's self-service
// emergency access (break_glass.go's ActivateBreakGlass): break-glass is
// documented as "Deliberately un-gated by RBAC — the whole point is access the
// user does NOT already have", so a false-positive SoD block during a genuine
// incident is an unacceptable failure mode for the control that exists to
// remediate incidents — mirroring the exact reasoning already established above
// for the escalation-by-proxy ceiling check this function also (deliberately)
// skips. Never call this from any other path — the HTTP JIT-assign endpoint and
// the access-request TTL-approval path must go through AssignUserRoleWithExpiry
// so the SoD gate applies.
func (c *KeyorixCore) assignUserRoleWithExpirySkipSoD(ctx context.Context, actorID, userID, roleID uint, scope Scope, expiresAt time.Time) error {
	if err := c.storage.AssignRoleWithExpiry(ctx, userID, roleID, scope, expiresAt); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogRoleAssigned(ctx, actorID, userID, roleID, scope)
	return nil
}

// AssignGroupRoleWithExpiry assigns a time-bound role to a group at scope, gated by
// the same escalation-by-proxy ceiling as the permanent grant (AssignRoleToGroup —
// a JIT admin grant to a group is just as much a self-escalation vector as a
// permanent one); see AssignUserRoleWithExpiry. Also gated by the #419
// separation-of-duties preventive check (requireGroupGrantNoSoDViolation) — no
// caller of this function needs a break-glass-style carve-out, unlike the direct
// user grant above.
func (c *KeyorixCore) AssignGroupRoleWithExpiry(ctx context.Context, actorID, groupID, roleID uint, scope Scope, expiresAt time.Time) error {
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if err := c.requireAuthorityForRole(ctx, actorID, scope.ProjectID, role.Name); err != nil {
		return err
	}
	if err := c.requireGroupGrantNoSoDViolation(ctx, groupID, roleID); err != nil {
		return err
	}
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
