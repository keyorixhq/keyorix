package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/license"
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
// on each tick). It returns the number of notifications created. It is the proactive
// counterpart to the fail-safe gate: a commercial license that lapses silently would
// disable airgap_updates with no warning, so admins are reminded ahead of the lapse.
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
	sent := 0
	for _, uid := range admins {
		if c.hasUnreadLicenseExpiry(ctx, uid) {
			continue
		}
		c.notify(ctx, uid, NotificationLicenseExpiry, title, msg, nil, "/admin/license")
		sent++
	}
	return sent, nil
}

// globalAdminIDs returns the user IDs of every active install-wide admin.
func (c *KeyorixCore) globalAdminIDs(ctx context.Context) ([]uint, error) {
	active := true
	users, _, err := c.storage.ListUsers(ctx, &storage.UserFilter{IsActive: &active, Page: 1, PageSize: 1000})
	if err != nil {
		return nil, err
	}
	var ids []uint
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
	return ids, nil
}

// hasUnreadLicenseExpiry reports whether the user already has an unread license-expiry
// reminder, so a standing reminder is not re-created on every scheduler tick.
func (c *KeyorixCore) hasUnreadLicenseExpiry(ctx context.Context, userID uint) bool {
	notes, err := c.storage.ListNotifications(ctx, userID, true, 100)
	if err != nil {
		return false // on read error, prefer notifying over silently skipping
	}
	for _, n := range notes {
		if n.Type == NotificationLicenseExpiry {
			return true
		}
	}
	return false
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
