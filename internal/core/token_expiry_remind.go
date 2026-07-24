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
	"strings"
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

		existing := k.unreadPATExpiryReminder(ctx, p.UserID, p.Name)
		if existing != nil {
			if severity <= existing.Severity {
				continue
			}
			if k.upgradeReminder(ctx, existing, title, msg, severity) {
				bumpTokenExpiryCount(result, severity, true)
			}
			continue
		}
		k.notifyWithSeverity(ctx, p.UserID, NotificationPATExpiry, title, msg, nil, "/profile/tokens", severity)
		bumpTokenExpiryCount(result, severity, true)
	}
	return nil
}

// notifyMachineCredAdmins delivers or upgrades a machine-cred expiry notification
// to each admin. It counts the credential only once per credential (not per admin).
// Returns true when a bump was recorded for result.
func (k *KeyorixCore) notifyMachineCredAdmins(ctx context.Context, credName string, title, msg string, severity models.NotificationSeverity, admins []uint, result *TokenExpiryCheckResult) {
	counted := false
	for _, uid := range admins {
		existing := k.unreadMachineCredExpiryReminder(ctx, uid, credName)
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
		k.notifyWithSeverity(ctx, uid, NotificationMachineCredExpiry, title, msg, nil, "/system/machines", severity)
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
		k.notifyMachineCredAdmins(ctx, c.Name, title, msg, severity, admins, result)
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

// unreadPATExpiryReminder returns an existing unread PAT-expiry reminder for the
// given user and token name, or nil if none exists.
func (k *KeyorixCore) unreadPATExpiryReminder(ctx context.Context, userID uint, tokenName string) *models.Notification {
	notes, err := k.storage.ListNotifications(ctx, userID, true, 200)
	if err != nil {
		return nil
	}
	needle := fmt.Sprintf("%q", tokenName)
	for _, n := range notes {
		if n.Type == NotificationPATExpiry && strings.Contains(n.Message, needle) {
			return n
		}
	}
	return nil
}

// unreadMachineCredExpiryReminder returns an existing unread machine-cred-expiry
// reminder for the given admin user and credential name, or nil if none exists.
func (k *KeyorixCore) unreadMachineCredExpiryReminder(ctx context.Context, userID uint, credName string) *models.Notification {
	notes, err := k.storage.ListNotifications(ctx, userID, true, 200)
	if err != nil {
		return nil
	}
	needle := fmt.Sprintf("%q", credName)
	for _, n := range notes {
		if n.Type == NotificationMachineCredExpiry && strings.Contains(n.Message, needle) {
			return n
		}
	}
	return nil
}
