package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// NotificationLicenseExpiry is the in-app/external notification type for an offline
// commercial license that is expiring soon or has expired (ADR-065 Phase 2c).
const NotificationLicenseExpiry = "license.expiry_reminder"

// globalAdminRoleNames are the install-wide admin roles. A license is install-wide, so its
// expiry is notified to these admins — NOT project_admin, which is project-scoped.
var globalAdminRoleNames = map[string]struct{}{
	"super_admin": {}, "admin": {}, "system_admin": {},
}

// ScanLicenseExpiry checks the installed offline license and, when it is within leadDays of
// expiry or already expired, notifies every install-wide admin (deduped so it does not spam
// on each tick). It also compares the newly computed severity (an actually-expired license is
// more severe than merely expiring soon) against what an existing unread reminder was recorded
// with: an escalation updates the standing reminder in place rather than being silently
// suppressed, so an unread reminder can't freeze at a stale, now-superseded severity (#250). It
// returns the number of notifications created or escalated. It is the proactive counterpart to
// the fail-safe gate: a commercial license that lapses silently would disable airgap_updates
// with no warning, so admins are reminded ahead of the lapse.
//
// Only a validly-signed license with a real expiry triggers a reminder. No license
// (community baseline) and an invalid/untrusted token are intentionally silent here — the
// former is a deliberate state, the latter is surfaced at startup and on the status
// endpoint and would otherwise spam on a misconfiguration.
func (c *KeyorixCore) ScanLicenseExpiry(ctx context.Context, leadDays int) (int, error) {
	if leadDays <= 0 {
		leadDays = 30
	}
	st := c.LicenseStatus()
	switch st.State {
	case license.StateActive, license.StateExpiringSoon, license.StateExpired:
		// a real, signed license — proceed
	default: // none, invalid
		return 0, nil
	}
	if st.NotAfter.IsZero() {
		return 0, nil
	}
	// Notify only once the license is within the lead window of expiry (or already past it).
	if st.NotAfter.After(c.now().Add(time.Duration(leadDays) * 24 * time.Hour)) {
		return 0, nil
	}

	admins, err := c.globalAdminIDs(ctx)
	if err != nil {
		return 0, err
	}
	title, msg := licenseExpiryNotice(st)
	severity := licenseExpirySeverity(st)
	sent := 0
	for _, uid := range admins {
		if existing := c.unreadLicenseExpiry(ctx, uid); existing != nil {
			if severity <= existing.Severity {
				continue // no worse than what's already standing — don't pile up
			}
			if c.upgradeReminder(ctx, existing, title, msg, severity) {
				sent++ // escalated in place (#250): expiring soon → now expired
			}
			continue
		}
		c.notifyWithSeverity(ctx, uid, NotificationLicenseExpiry, title, msg, nil, "/admin/license", severity)
		sent++
	}
	return sent, nil
}

// licenseExpirySeverity ranks the license state: an already-expired license is
// strictly more severe than merely expiring soon (#250).
func licenseExpirySeverity(st license.Status) models.NotificationSeverity {
	if st.State == license.StateExpired {
		return models.NotificationSeverityCritical
	}
	return models.NotificationSeverityWarning
}

// globalAdminIDsPageSize bounds each page of the active-users walk in globalAdminIDs.
// A single fixed-size page silently under-lists admins once the install has more
// active users than the page size; paginating through every page instead keeps
// this correct at any install scale.
const globalAdminIDsPageSize = 500

// globalAdminIDs returns the user IDs of every active install-wide admin.
func (c *KeyorixCore) globalAdminIDs(ctx context.Context) ([]uint, error) { // NOSONAR -- cognitive complexity 18, suppress go:S3776
	active := true
	var ids []uint
	for page := 1; ; page++ {
		users, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{IsActive: &active, Page: page, PageSize: globalAdminIDsPageSize})
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			roles, rerr := c.storage.GetUserRoles(ctx, u.ID)
			if rerr != nil {
				continue
			}
			for _, r := range roles {
				if _, ok := globalAdminRoleNames[r.Name]; ok {
					ids = append(ids, u.ID)
					break
				}
			}
		}
		if len(users) < globalAdminIDsPageSize || int64(page*globalAdminIDsPageSize) >= total {
			break
		}
	}
	return ids, nil
}

// unreadLicenseExpiry returns the user's existing unread license-expiry
// reminder, or nil if none exists, so a standing reminder is not re-created on
// every scheduler tick.
func (c *KeyorixCore) unreadLicenseExpiry(ctx context.Context, userID uint) *models.Notification {
	notes, err := c.storage.ListNotifications(ctx, userID, true, 100)
	if err != nil {
		return nil // on read error, prefer notifying over silently skipping
	}
	for _, n := range notes {
		if n.Type == NotificationLicenseExpiry {
			return n
		}
	}
	return nil
}

// licenseExpiryNotice builds the admin reminder title + message for the license state.
func licenseExpiryNotice(st license.Status) (string, string) {
	who := st.Licensee
	if who == "" {
		who = "this deployment"
	}
	date := st.NotAfter.UTC().Format("2006-01-02")
	if st.State == license.StateExpired {
		return "Keyorix license expired",
			fmt.Sprintf("The Keyorix license for %s expired on %s — commercial features have degraded to the community baseline. Install a renewed license to restore them.", who, date)
	}
	return "Keyorix license expiring",
		fmt.Sprintf("The Keyorix license for %s expires on %s. Renew it before then to avoid losing commercial features.", who, date)
}
