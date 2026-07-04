// rotation_reminders.go — proactive rotation hygiene (a NIS2/ISO control): a
// background scheduler (opt-in, see main.go) evaluates active rotation policies and
// notifies project admins of secrets overdue or approaching their rotation deadline.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// NotificationRotationDue marks an in-app rotation-reminder notification.
const NotificationRotationDue = "rotation.reminder"

// SendRotationReminders evaluates every active rotation policy and, for each project
// with secrets overdue or approaching rotation, sends ONE standing digest
// notification to each of that project's admins. It de-duplicates: an admin who
// already has an unread rotation reminder for the project is not re-notified, so
// reminders don't pile up — once they read it (and the secret is still overdue) the
// next run nudges them again. It also compares the newly computed severity
// (overdue is more severe than merely approaching) against what an existing
// unread reminder was recorded with: an escalation (e.g. approaching → overdue)
// updates the standing reminder in place rather than being silently suppressed,
// so an unread reminder can't freeze at a stale, now-superseded severity (#250).
// Returns the number of notifications created or escalated.
func (c *KeyorixCore) SendRotationReminders(ctx context.Context) (int, error) {
	evals, err := c.EvaluateRotationPolicies(ctx, nil, nil)
	if err != nil {
		return 0, err
	}
	if len(evals) == 0 {
		return 0, nil
	}

	// Tally overdue / approaching secrets per project.
	type counts struct{ overdue, approaching int }
	byProject := map[uint]*counts{}
	for _, e := range evals {
		if e.ProjectID == 0 {
			continue
		}
		ct := byProject[e.ProjectID]
		if ct == nil {
			ct = &counts{}
			byProject[e.ProjectID] = ct
		}
		switch {
		case e.IsOverdue:
			ct.overdue++
		case e.IsApproaching:
			ct.approaching++
		}
	}

	sent := 0
	for projectID, ct := range byProject {
		if ct.overdue == 0 && ct.approaching == 0 {
			continue
		}
		members, err := c.storage.ListProjectMembers(ctx, projectID)
		if err != nil {
			continue
		}
		pid := projectID
		title := "Secrets due for rotation"
		msg := rotationReminderMessage(c.projectLabel(ctx, projectID), ct.overdue, ct.approaching)
		severity := rotationSeverity(ct.overdue)
		for _, mbr := range members {
			if !isApproverRole(mbr.RoleName) {
				continue
			}
			if existing := c.unreadRotationReminder(ctx, mbr.UserID, projectID); existing != nil {
				if severity <= existing.Severity {
					continue // no worse than what's already standing — don't pile up
				}
				if c.upgradeReminder(ctx, existing, title, msg, severity) {
					sent++ // escalated in place (#250): approaching → now overdue
				}
				continue
			}
			c.notifyWithSeverity(ctx, mbr.UserID, NotificationRotationDue, title, msg, &pid, "/rotation-policies", severity)
			sent++
		}
	}
	return sent, nil
}

// rotationSeverity ranks a project's rotation state: any overdue secret is
// strictly more severe than merely having secrets approaching their deadline
// (#250).
func rotationSeverity(overdue int) models.NotificationSeverity {
	if overdue > 0 {
		return models.NotificationSeverityCritical
	}
	return models.NotificationSeverityWarning
}

// unreadRotationReminder returns the user's existing unread rotation-reminder
// notification for the given project, or nil if none exists (including on a
// storage read error — on error, prefer notifying over silently skipping).
// This queries at the DB level for exactly this (user, type, project) triple —
// it does NOT page through "the newest N notifications of any type" — so a
// user with a large volume of other unrelated unread notifications can't push
// a genuine standing reminder out of an arbitrary top-N window and defeat the
// dedup guard (#399).
func (c *KeyorixCore) unreadRotationReminder(ctx context.Context, userID, projectID uint) *models.Notification {
	n, err := c.storage.GetUnreadNotification(ctx, userID, NotificationRotationDue, projectID)
	if err != nil {
		return nil
	}
	return n
}

func rotationReminderMessage(project string, overdue, approaching int) string {
	switch {
	case overdue > 0 && approaching > 0:
		return fmt.Sprintf("%d secret(s) in %s are overdue for rotation and %d more are approaching their deadline.", overdue, project, approaching)
	case overdue > 0:
		return fmt.Sprintf("%d secret(s) in %s are overdue for rotation.", overdue, project)
	default:
		return fmt.Sprintf("%d secret(s) in %s are approaching their rotation deadline.", approaching, project)
	}
}
