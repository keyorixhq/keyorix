// recertification.go — scheduled access recertification (ISO 27001 A.5.18, "review
// access rights at planned intervals"). access_review_campaign.go provides the
// manual cycle (open → decide → close); this enforces the *cadence*: a background
// scheduler (opt-in, see main.go) finds projects whose access is due for review —
// never reviewed, or last reviewed longer ago than the configured window — and
// either auto-opens a campaign (system-actored) or reminds the project's admins to,
// and nudges admins of in-flight campaigns that still have pending items.
package core

import (
	"context"
	"fmt"
)

// DefaultRecertificationCadenceDays is the review interval assumed when none is
// configured (a quarter — a common recertification cadence).
const DefaultRecertificationCadenceDays = 90

// NotificationRecertificationDue marks an in-app recertification reminder.
const NotificationRecertificationDue = "access_review.recertification_due"

// RecertificationResult reports what one scheduled run did.
type RecertificationResult struct {
	Opened   int `json:"opened"`   // campaigns auto-opened for overdue projects
	Reminded int `json:"reminded"` // admin notifications sent
}

// SetRecertificationCadence records the review cadence (days) so the compliance
// posture can flag overdue projects. 0 leaves the default in effect.
func (c *KeyorixCore) SetRecertificationCadence(days int) {
	c.recertCadenceDays = days
}

// recertCadence returns the effective cadence in days (the configured value, or the
// default when unset).
func (c *KeyorixCore) recertCadence() int {
	if c.recertCadenceDays > 0 {
		return c.recertCadenceDays
	}
	return DefaultRecertificationCadenceDays
}

// RunScheduledRecertification enforces the recertification cadence across every
// project. For each project it determines whether access is "due" — never reviewed,
// or the most recent campaign closed more than cadenceDays ago — and that no
// campaign is currently open. For a due project: when autoOpen it opens a fresh
// campaign (system-actored) and notifies the project's admins; otherwise it notifies
// them that a review is due. Separately, a project whose open campaign still has
// pending items prompts a reminder to finish it. Admin reminders de-dupe against an
// existing unread recertification notification so they don't pile up. Returns the
// number of campaigns opened and admins notified. Auto-open is a create, not a
// delete, so this is NOT legal-hold-gated.
func (c *KeyorixCore) RunScheduledRecertification(ctx context.Context, cadenceDays int, autoOpen bool) (*RecertificationResult, error) {
	if cadenceDays <= 0 {
		cadenceDays = DefaultRecertificationCadenceDays
	}
	projects, err := c.ListProjects(ctx)
	if err != nil {
		return nil, err
	}
	res := &RecertificationResult{}
	cutoff := c.now().AddDate(0, 0, -cadenceDays)

	for _, proj := range projects {
		pid := proj.ID
		campaigns, err := c.ListAccessReviewCampaigns(ctx, pid)
		if err != nil {
			continue // a per-project read error must not abort the whole sweep
		}
		open, lastClosed := splitCampaigns(campaigns)

		// A review is already in progress — nudge admins only if items remain.
		if open != nil {
			if open.Progress.Pending > 0 {
				res.Reminded += c.remindRecertificationAdmins(ctx, pid,
					fmt.Sprintf("Access recertification for %s has %d item(s) still pending review.",
						c.projectLabel(ctx, pid), open.Progress.Pending))
			}
			continue
		}

		// No open campaign — is the project due for one?
		due := lastClosed == nil // never reviewed
		if lastClosed != nil && lastClosed.Campaign.ClosedAt != nil {
			due = lastClosed.Campaign.ClosedAt.Before(cutoff)
		}
		if !due {
			continue
		}

		if autoOpen {
			name := fmt.Sprintf("Scheduled recertification %s", c.now().Format("2006-01-02"))
			if _, err := c.OpenAccessReviewCampaign(WithActorType(ctx, ActorTypeSystem), 0, pid, name); err != nil {
				continue
			}
			res.Opened++
			res.Reminded += c.remindRecertificationAdmins(ctx, pid,
				fmt.Sprintf("A scheduled access-recertification campaign was opened for %s — please review and attest the listed access.",
					c.projectLabel(ctx, pid)))
		} else {
			res.Reminded += c.remindRecertificationAdmins(ctx, pid,
				fmt.Sprintf("Access in %s is due for recertification (ISO 27001 A.5.18) — please open a review campaign.",
					c.projectLabel(ctx, pid)))
		}
	}
	return res, nil
}

// splitCampaigns returns the open campaign (if any) and the most-recent closed one.
// The list is newest-first, so the first match in each case is the latest.
func splitCampaigns(campaigns []*CampaignWithProgress) (open *CampaignWithProgress, lastClosed *CampaignWithProgress) {
	for _, cw := range campaigns {
		if cw.Campaign.State == CampaignStateOpen {
			if open == nil {
				open = cw
			}
			continue
		}
		if lastClosed == nil {
			lastClosed = cw
		}
	}
	return open, lastClosed
}

// remindRecertificationAdmins sends one standing reminder to each of the project's
// admins, skipping any who already hold an unread one. Returns the number sent.
func (c *KeyorixCore) remindRecertificationAdmins(ctx context.Context, projectID uint, msg string) int {
	members, err := c.storage.ListProjectMembers(ctx, projectID)
	if err != nil {
		return 0
	}
	pid := projectID
	sent := 0
	for _, mbr := range members {
		if !isApproverRole(mbr.RoleName) {
			continue
		}
		if c.hasUnreadRecertificationReminder(ctx, mbr.UserID, projectID) {
			continue
		}
		c.notify(ctx, mbr.UserID, NotificationRecertificationDue,
			"Access recertification", msg, &pid, "/projects")
		sent++
	}
	return sent
}

// hasUnreadRecertificationReminder reports whether the user already holds an unread
// recertification reminder for the project.
func (c *KeyorixCore) hasUnreadRecertificationReminder(ctx context.Context, userID, projectID uint) bool {
	notes, err := c.storage.ListNotifications(ctx, userID, true, 100)
	if err != nil {
		return false // on a read error, prefer notifying over silently skipping
	}
	for _, n := range notes {
		if n.Type == NotificationRecertificationDue && n.ProjectID != nil && *n.ProjectID == projectID {
			return true
		}
	}
	return false
}
