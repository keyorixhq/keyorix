// role_expiry_notify.go — proactive JIT role-grant expiry notifications.
//
// CheckRoleExpiry scans all UserRole rows with a non-nil ExpiresAt and emits
// in-app Notification rows for those expiring within 7 days (warning) or 1 day
// (critical). It is idempotent: a user/role pair that already has an unread
// notification of the appropriate severity in the last 24 h is skipped.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// NotificationRoleExpiryReminder is the in-app notification type for a
// time-bound role grant that is approaching its expiry deadline.
const NotificationRoleExpiryReminder = "role.expiry_reminder"

// roleExpiryWarningWindow is the look-ahead for the "expiring soon" warning.
const roleExpiryWarningWindow = 7 * 24 * time.Hour

// roleExpiryCriticalWindow is the look-ahead for the "imminent" critical alert.
const roleExpiryCriticalWindow = 1 * 24 * time.Hour

// RoleExpiryCheckResult summarises what was emitted by CheckRoleExpiry.
type RoleExpiryCheckResult struct {
	Warnings  int // notifications created/escalated for the 7-day window
	Criticals int // notifications created/escalated for the 1-day window
}

// CheckRoleExpiry scans all UserRole rows with a non-nil ExpiresAt and emits
// in-app Notification rows for those expiring within 7 days (warning) or 1 day
// (critical). Already-expired grants are not counted — they have lapsed and the
// sweep will remove them; this function is forward-looking only.
//
// Idempotent: if the user already has an unread notification of the same type
// for the same role at the same or higher severity, it is skipped (or escalated
// in place when the new severity is strictly higher, matching the
// expiry/rotation/license reminder dedup pattern).
func (k *KeyorixCore) CheckRoleExpiry(ctx context.Context) (*RoleExpiryCheckResult, error) {
	now := k.now()
	// Fetch all grants expiring within the wider window (7 days). We pass the
	// 7-day cutoff so the DB filters out grants beyond that horizon.
	cutoff := now.Add(roleExpiryWarningWindow)
	grants, err := k.storage.ListExpiringUserRoles(ctx, cutoff)
	if err != nil {
		return nil, fmt.Errorf("list expiring user roles: %w", err)
	}

	result := &RoleExpiryCheckResult{}
	for _, g := range grants {
		if g.ExpiresAt == nil {
			continue
		}
		// Skip already-expired grants — forward-looking only.
		if !g.ExpiresAt.After(now) {
			continue
		}

		severity := roleExpirySeverity(g.ExpiresAt, now)

		roleName := k.roleName(ctx, g.RoleID)
		title, msg := roleExpiryMessage(roleName, g.ExpiresAt)
		link := roleExpiryLink(g.RoleID, g.ProjectID, g.EnvironmentID)

		// #G21/#G22: no DB backstop for this check-then-act — see
		// read_quota_alerts.go's CheckReadQuotas for why the existing #488
		// reminder-dedup index can't simply be extended to cover this type.
		// Deferred; worst case is a duplicate notification, not a
		// security/data-integrity issue. Dedup itself is keyed on the grant's
		// stable (role, project, environment) tuple (encoded in Link via
		// roleExpiryLink), not the role's display name — two distinct roles
		// (e.g. same-named roles scoped to different projects) can share a
		// Name, and matching on name would let one grant's standing reminder
		// silently mask a distinct grant's reminder (#G22).
		existing := k.unreadRoleExpiryReminder(ctx, g.UserID, g.RoleID, g.ProjectID, g.EnvironmentID)
		if existing != nil {
			if severity <= existing.Severity {
				continue // no worse than what's standing — don't pile up
			}
			if k.upgradeReminder(ctx, existing, title, msg, severity) {
				k.bumpRoleExpiryCount(result, severity)
			}
			continue
		}
		k.notifyWithSeverity(ctx, g.UserID, NotificationRoleExpiryReminder, title, msg, nil, link, severity)
		k.bumpRoleExpiryCount(result, severity)
	}
	return result, nil
}

// roleExpirySeverity returns Critical when the grant expires within 1 day,
// Warning when it expires within 7 days.
func roleExpirySeverity(expiresAt *time.Time, now time.Time) models.NotificationSeverity {
	if expiresAt.Before(now.Add(roleExpiryCriticalWindow)) {
		return models.NotificationSeverityCritical
	}
	return models.NotificationSeverityWarning
}

// bumpRoleExpiryCount increments the appropriate counter on result.
func (k *KeyorixCore) bumpRoleExpiryCount(result *RoleExpiryCheckResult, severity models.NotificationSeverity) {
	if severity >= models.NotificationSeverityCritical {
		result.Criticals++
	} else {
		result.Warnings++
	}
}

// roleName returns the human-readable role name for a role ID, falling back to
// a "#N" label if the role cannot be fetched.
func (k *KeyorixCore) roleName(ctx context.Context, roleID uint) string {
	r, err := k.storage.GetRole(ctx, roleID)
	if err != nil || r == nil {
		return fmt.Sprintf("#%d", roleID)
	}
	return r.Name
}

// roleExpiryMessage builds the notification title and message for a role grant
// approaching expiry.
func roleExpiryMessage(roleName string, expiresAt *time.Time) (string, string) {
	date := expiresAt.UTC().Format("2006-01-02 15:04 UTC")
	return "Role access expiring",
		fmt.Sprintf("Your %q role grant expires on %s.", roleName, date)
}

// roleExpiryLink builds the stable per-grant dedup key (and in-app navigation
// target) for a role-expiry reminder, keyed on the grant's (role, project,
// environment) tuple — the same tuple (together with user) that uniquely
// identifies a UserRole row — rather than the role's display Name. Two
// distinct grants (different RoleID/ProjectID/EnvironmentID) can resolve to
// roles that share the same Name, so matching on name would incorrectly
// collapse their reminders together (#G22).
func roleExpiryLink(roleID, projectID, environmentID uint) string {
	return fmt.Sprintf("/profile/roles?role=%d&project=%d&env=%d", roleID, projectID, environmentID)
}

// unreadRoleExpiryReminder returns the user's existing unread role-expiry
// reminder for the specific (role, project, environment) grant tuple, or nil
// if none exists.
func (k *KeyorixCore) unreadRoleExpiryReminder(ctx context.Context, userID, roleID, projectID, environmentID uint) *models.Notification {
	notes, err := k.storage.ListNotifications(ctx, userID, true, 200)
	if err != nil {
		return nil // on read error, prefer notifying over silently skipping
	}
	link := roleExpiryLink(roleID, projectID, environmentID)
	for _, n := range notes {
		if n.Type == NotificationRoleExpiryReminder && n.Link == link {
			return n
		}
	}
	return nil
}
