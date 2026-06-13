// rotation_reminders.go — proactive rotation hygiene (a NIS2/ISO control): a
// background scheduler (opt-in, see main.go) evaluates active rotation policies and
// notifies project admins of secrets overdue or approaching their rotation deadline.
package core

import (
	"context"
	"fmt"
)

// NotificationRotationDue marks an in-app rotation-reminder notification.
const NotificationRotationDue = "rotation.reminder"

// SendRotationReminders evaluates every active rotation policy and, for each project
// with secrets overdue or approaching rotation, sends ONE standing digest
// notification to each of that project's admins. It de-duplicates: an admin who
// already has an unread rotation reminder for the project is not re-notified, so
// reminders don't pile up — once they read it (and the secret is still overdue) the
// next run nudges them again. Returns the number of notifications created.
func (c *KeyorixCore) SendRotationReminders(ctx context.Context) (int, error) {
	evals, err := c.EvaluateRotationPolicies(ctx, nil)
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
		msg := rotationReminderMessage(c.projectLabel(ctx, projectID), ct.overdue, ct.approaching)
		for _, mbr := range members {
			if !isApproverRole(mbr.RoleName) {
				continue
			}
			if c.hasUnreadRotationReminder(ctx, mbr.UserID, projectID) {
				continue // a standing reminder already exists — don't pile up
			}
			c.notify(ctx, mbr.UserID, NotificationRotationDue,
				"Secrets due for rotation", msg, &pid, "/rotation-policies")
			sent++
		}
	}
	return sent, nil
}

// hasUnreadRotationReminder reports whether the user already has an unread
// rotation-reminder notification for the given project.
func (c *KeyorixCore) hasUnreadRotationReminder(ctx context.Context, userID, projectID uint) bool {
	notes, err := c.storage.ListNotifications(ctx, userID, true, 100)
	if err != nil {
		return false // on a read error, prefer notifying over silently skipping
	}
	for _, n := range notes {
		if n.Type == NotificationRotationDue && n.ProjectID != nil && *n.ProjectID == projectID {
			return true
		}
	}
	return false
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
