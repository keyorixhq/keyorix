// expiry_reminders.go — proactive secret-expiry hygiene: a background scheduler
// (opt-in, see main.go) finds secrets that are expired or approaching their expiration
// and notifies project admins, so a secret never silently lapses and breaks its
// consumers. Mirrors the rotation-reminder mechanism (notify project approvers once,
// de-duplicating standing reminders).
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// NotificationExpiryReminder marks an in-app secret-expiry reminder notification.
const NotificationExpiryReminder = "secret.expiry_reminder"

// SendExpiryReminders finds every secret expiring within leadDays (or already expired)
// and, for each project with such secrets, sends ONE standing digest notification to
// each of that project's admins. De-duplicates like rotation reminders: an admin who
// already has an unread expiry reminder for the project is not re-notified. leadDays <= 0
// falls back to the default lead window. Returns the number of notifications created.
func (c *KeyorixCore) SendExpiryReminders(ctx context.Context, leadDays int) (int, error) {
	if leadDays <= 0 {
		leadDays = defaultExpiryLeadDays
	}
	now := c.now()
	cutoff := now.Add(time.Duration(leadDays) * 24 * time.Hour)
	secrets, err := c.listSecretsExpiringBefore(ctx, cutoff)
	if err != nil {
		return 0, err
	}

	// Tally expired / soon-to-expire secrets per project.
	type counts struct{ expired, soon int }
	byProject := map[uint]*counts{}
	for _, s := range secrets {
		if s.Expiration == nil {
			continue
		}
		ct := byProject[s.ProjectID]
		if ct == nil {
			ct = &counts{}
			byProject[s.ProjectID] = ct
		}
		if s.Expiration.Before(now) {
			ct.expired++
		} else {
			ct.soon++
		}
	}

	sent := 0
	for projectID, ct := range byProject {
		if projectID == 0 || (ct.expired == 0 && ct.soon == 0) {
			continue
		}
		members, err := c.storage.ListProjectMembers(ctx, projectID)
		if err != nil {
			continue
		}
		pid := projectID
		msg := expiryReminderMessage(c.projectLabel(ctx, projectID), ct.expired, ct.soon)
		for _, mbr := range members {
			if !isApproverRole(mbr.RoleName) {
				continue
			}
			if c.hasUnreadExpiryReminder(ctx, mbr.UserID, projectID) {
				continue // a standing reminder already exists — don't pile up
			}
			c.notify(ctx, mbr.UserID, NotificationExpiryReminder,
				"Secrets expiring", msg, &pid, "/secrets/expiry")
			sent++
		}
	}
	return sent, nil
}

const (
	defaultExpiryLeadDays  = 14
	expiryReminderPageSize = 500
)

// listSecretsExpiringBefore returns every secret (across all projects) whose expiration
// is set and before cutoff, paging through all of them — expiry evaluation must not
// silently cap.
func (c *KeyorixCore) listSecretsExpiringBefore(ctx context.Context, cutoff time.Time) ([]*models.SecretNode, error) {
	var all []*models.SecretNode
	for page := 1; ; page++ {
		secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			Page: page, PageSize: expiryReminderPageSize, ExpiresBefore: &cutoff,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, secrets...)
		if len(secrets) < expiryReminderPageSize || int64(len(all)) >= total {
			break
		}
	}
	return all, nil
}

// hasUnreadExpiryReminder reports whether the user already has an unread expiry-reminder
// notification for the given project.
func (c *KeyorixCore) hasUnreadExpiryReminder(ctx context.Context, userID, projectID uint) bool {
	notes, err := c.storage.ListNotifications(ctx, userID, true, 100)
	if err != nil {
		return false // on a read error, prefer notifying over silently skipping
	}
	for _, n := range notes {
		if n.Type == NotificationExpiryReminder && n.ProjectID != nil && *n.ProjectID == projectID {
			return true
		}
	}
	return false
}

func expiryReminderMessage(project string, expired, soon int) string {
	switch {
	case expired > 0 && soon > 0:
		return fmt.Sprintf("%d secret(s) in %s have expired and %d more are expiring soon.", expired, project, soon)
	case expired > 0:
		return fmt.Sprintf("%d secret(s) in %s have expired.", expired, project)
	default:
		return fmt.Sprintf("%d secret(s) in %s are expiring soon.", soon, project)
	}
}
