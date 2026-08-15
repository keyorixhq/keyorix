// token_expiry_remind.go — proactive PAT and machine-credential expiry notifications.
//
// CheckTokenExpiry scans PersonalAccessTokens and MachineIdentityCredentials with
// a non-nil ExpiresAt and emits in-app Notification rows for those expiring within
// 7 days (warning) or 1 day (critical). It mirrors the role-expiry-notifications
// pattern exactly (see role_expiry_notify.go).
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// NotificationPATExpiry is the in-app notification type for a PersonalAccessToken
// approaching its expiry deadline.
const NotificationPATExpiry = "pat_expiring_soon"

// NotificationMachineCredExpiry is the in-app notification type for a
// MachineIdentityCredential approaching its expiry deadline.
const NotificationMachineCredExpiry = "machine_cred_expiring_soon" // #nosec G101 -- notification type string, not a credential

// tokenExpiryWarningWindow is the look-ahead for the "expiring soon" warning.
const tokenExpiryWarningWindow = 7 * 24 * time.Hour

// tokenExpiryCriticalWindow is the look-ahead for the "imminent" critical alert.
const tokenExpiryCriticalWindow = 1 * 24 * time.Hour

// TokenExpiryCheckResult summarises what was emitted by CheckTokenExpiry.
type TokenExpiryCheckResult struct {
	PATWarnings      int // PATs expiring within 7 days
	PATCriticals     int // PATs expiring within 1 day
	MachineWarnings  int // machine credentials expiring within 7 days
	MachineCriticals int // machine credentials expiring within 1 day
}

// CheckTokenExpiry scans PersonalAccessTokens and MachineIdentityCredentials
// with non-nil ExpiresAt, emits Warning (7-day) or Critical (1-day) Notification
// rows. Skips already-expired and revoked tokens. Deduplicates: skips user/token
// pairs that already have an unread notification of that type for the same token
// in the past 24h (same-or-higher severity).
//
// PAT notifications are sent to the owning user. Machine-credential notifications
// are sent to every global admin (same as license-expiry reminders).
func (k *KeyorixCore) CheckTokenExpiry(ctx context.Context) (*TokenExpiryCheckResult, error) {
	now := k.now()
	cutoff := now.Add(tokenExpiryWarningWindow)
	result := &TokenExpiryCheckResult{}

	if err := k.checkPATExpiry(ctx, now, cutoff, result); err != nil {
		return nil, err
	}
	if err := k.checkMachineCredExpiry(ctx, now, cutoff, result); err != nil {
		return nil, err
	}
	return result, nil
}

// checkPATExpiry handles the PAT half of CheckTokenExpiry.
func (k *KeyorixCore) checkPATExpiry(ctx context.Context, now time.Time, cutoff time.Time, result *TokenExpiryCheckResult) error {
	pats, err := k.storage.ListExpiringPATs(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("list expiring PATs: %w", err)
	}
	for i := range pats {
		p := &pats[i]
		if p.ExpiresAt == nil {
			continue
		}
		// Skip already-expired tokens — forward-looking only.
		if !p.ExpiresAt.After(now) {
			continue
		}
		severity := tokenExpirySeverity(p.ExpiresAt, now)
		title, msg := patExpiryMessage(p.Name, p.ExpiresAt)
		link := patExpiryLink(p.ID)

		// #G21/#G22: no DB backstop for this check-then-act — see
		// read_quota_alerts.go's CheckReadQuotas for why the existing #488
		// reminder-dedup index can't simply be extended to cover this type.
		// Deferred; worst case is a duplicate notification, not a
		// security/data-integrity issue. Dedup itself is keyed on the token's
		// stable ID (encoded in Link via patExpiryLink), not its display name —
		// two PATs owned by the same user can share a Name, and matching on
		// name would let one token's standing reminder silently mask a
		// distinct token's reminder (#G22).
		existing := k.unreadPATExpiryReminder(ctx, p.UserID, link)
		if existing != nil {
			if severity <= existing.Severity {
				continue
			}
			if k.upgradeReminder(ctx, existing, title, msg, severity) {
				bumpTokenExpiryCount(result, severity, true)
			}
			continue
		}
		k.notifyWithSeverity(ctx, p.UserID, NotificationPATExpiry, title, msg, nil, link, severity)
		bumpTokenExpiryCount(result, severity, true)
	}
	return nil
}

// notifyMachineCredAdmins delivers or upgrades a machine-cred expiry notification
// to each admin. It counts the credential only once per credential (not per admin).
// Dedup is keyed on the credential's stable ID (encoded in link, see
// machineCredExpiryLink), not its display name — two machine credentials can
// share a Name, and matching on name would let one credential's standing
// reminder silently mask a distinct credential's reminder (#G22).
// Returns true when a bump was recorded for result.
func (k *KeyorixCore) notifyMachineCredAdmins(ctx context.Context, link string, title, msg string, severity models.NotificationSeverity, admins []uint, result *TokenExpiryCheckResult) {
	counted := false
	for _, uid := range admins {
		existing := k.unreadMachineCredExpiryReminder(ctx, uid, link)
		if existing != nil {
			if severity <= existing.Severity {
				continue
			}
			if k.upgradeReminder(ctx, existing, title, msg, severity) && !counted {
				bumpTokenExpiryCount(result, severity, false)
				counted = true
			}
			continue
		}
		k.notifyWithSeverity(ctx, uid, NotificationMachineCredExpiry, title, msg, nil, link, severity)
		if !counted {
			bumpTokenExpiryCount(result, severity, false)
			counted = true
		}
	}
}

// checkMachineCredExpiry handles the machine-credential half of CheckTokenExpiry.
func (k *KeyorixCore) checkMachineCredExpiry(ctx context.Context, now time.Time, cutoff time.Time, result *TokenExpiryCheckResult) error {
	creds, err := k.storage.ListExpiringMachineCredentials(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("list expiring machine credentials: %w", err)
	}
	if len(creds) == 0 {
		return nil
	}

	admins, err := k.globalAdminIDs(ctx)
	if err != nil {
		return fmt.Errorf("list admin IDs for machine-cred expiry: %w", err)
	}

	for i := range creds {
		c := &creds[i]
		if c.ExpiresAt == nil || !c.ExpiresAt.After(now) {
			continue
		}
		severity := tokenExpirySeverity(c.ExpiresAt, now)
		title, msg := machineCredExpiryMessage(c.Name, c.ExpiresAt)
		k.notifyMachineCredAdmins(ctx, machineCredExpiryLink(c.ID), title, msg, severity, admins, result)
	}
	return nil
}

// tokenExpirySeverity returns Critical when the token expires within 1 day,
// Warning when it expires within 7 days.
func tokenExpirySeverity(expiresAt *time.Time, now time.Time) models.NotificationSeverity {
	if expiresAt.Before(now.Add(tokenExpiryCriticalWindow)) {
		return models.NotificationSeverityCritical
	}
	return models.NotificationSeverityWarning
}

// bumpTokenExpiryCount increments the appropriate counter on result.
// isPAT=true bumps PAT counters; false bumps Machine counters.
func bumpTokenExpiryCount(result *TokenExpiryCheckResult, severity models.NotificationSeverity, isPAT bool) {
	isCritical := severity >= models.NotificationSeverityCritical
	if isPAT {
		if isCritical {
			result.PATCriticals++
		} else {
			result.PATWarnings++
		}
	} else {
		if isCritical {
			result.MachineCriticals++
		} else {
			result.MachineWarnings++
		}
	}
}

// patExpiryMessage builds the notification title and message for a PAT approaching expiry.
func patExpiryMessage(tokenName string, expiresAt *time.Time) (string, string) {
	date := expiresAt.UTC().Format("2006-01-02 15:04 UTC")
	return "Personal access token expiring",
		fmt.Sprintf("Your personal access token %q expires on %s.", tokenName, date)
}

// machineCredExpiryMessage builds the notification title and message for a
// machine credential approaching expiry.
func machineCredExpiryMessage(credName string, expiresAt *time.Time) (string, string) {
	date := expiresAt.UTC().Format("2006-01-02 15:04 UTC")
	return "Machine credential expiring",
		fmt.Sprintf("Machine credential %q expires on %s.", credName, date)
}

// patExpiryLink builds the stable per-token dedup key (and in-app navigation
// target) for a PAT expiry reminder. Keyed on the token's ID — not its
// display Name — because two PATs belonging to the same user are not
// required to have distinct names; matching on name would let one token's
// standing reminder silently suppress a distinct token's reminder (#G22).
func patExpiryLink(tokenID uint) string {
	return fmt.Sprintf("/profile/tokens?token=%d", tokenID)
}

// machineCredExpiryLink builds the stable per-credential dedup key (and
// in-app navigation target) for a machine-credential expiry reminder. Keyed
// on the credential's ID — not its display Name — for the same reason as
// patExpiryLink (#G22).
func machineCredExpiryLink(credID uint) string {
	return fmt.Sprintf("/system/machines?cred=%d", credID)
}

// unreadPATExpiryReminder returns an existing unread PAT-expiry reminder for
// the given user matching link (see patExpiryLink), or nil if none exists.
func (k *KeyorixCore) unreadPATExpiryReminder(ctx context.Context, userID uint, link string) *models.Notification {
	notes, err := k.storage.ListNotifications(ctx, userID, true, 200)
	if err != nil {
		return nil
	}
	for _, n := range notes {
		if n.Type == NotificationPATExpiry && n.Link == link {
			return n
		}
	}
	return nil
}

// unreadMachineCredExpiryReminder returns an existing unread machine-cred-expiry
// reminder for the given admin user matching link (see machineCredExpiryLink),
// or nil if none exists.
func (k *KeyorixCore) unreadMachineCredExpiryReminder(ctx context.Context, userID uint, link string) *models.Notification {
	notes, err := k.storage.ListNotifications(ctx, userID, true, 200)
	if err != nil {
		return nil
	}
	for _, n := range notes {
		if n.Type == NotificationMachineCredExpiry && n.Link == link {
			return n
		}
	}
	return nil
}
