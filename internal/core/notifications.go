// notifications.go — in-app notifications (ADR-024).
//
// Notifications are addressed to a single user and surfaced via the header bell.
// Emission is best-effort: a delivery failure never blocks the action that
// triggered it (same contract as audit emission). In addition to the in-app row,
// notify() fans each event out to a configured external channel when a
// recipientNotificationSink is wired.
//
// #391: every event this file emits (secret shared, share revoked, ownership
// transferred, access requested, anomaly alert, break-glass activation, …) is
// addressed to exactly one user — the recipient this file already computed. It is
// dispatched to recipientNotificationSink, NOT the deployment-wide broadcast
// notificationSink (used elsewhere for the compliance digest / rotation-failure
// summaries): chat (Slack/Teams) and generic webhook channels are one fixed
// destination an operator configures, with no per-user identity mapping to target a
// specific recipient, so handing them a per-user event would broadcast it to
// everyone with channel visibility regardless of project membership or secret
// access. Only recipient-addressable channels (email) are wired into
// recipientNotificationSink; see SetRecipientNotificationSink and server/main.go.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Notification types.
const (
	NotificationMembershipActivated        = "membership.activated"
	NotificationAccessRequested            = "access_request.created"
	NotificationAccessApproved             = "access_request.approved"
	NotificationAccessRejected             = "access_request.rejected"
	NotificationSecretShared               = "secret.shared"
	NotificationSecretShareRevoked         = "secret.share_revoked"
	NotificationSecretOwnershipTransferred = "secret.ownership_transferred"
)

// approverRoleNames are the project/system roles whose holders can approve access
// requests — the recipients of a "new request" notification.
var approverRoleNames = map[string]struct{}{
	"project_admin": {}, "system_admin": {}, "admin": {}, "super_admin": {},
}

// isApproverRole reports whether holders of roleName can approve access requests.
func isApproverRole(roleName string) bool {
	_, ok := approverRoleNames[roleName]
	return ok
}

// notify creates one in-app notification, best-effort (errors are swallowed so a
// failed insert can't roll back the triggering action).
func (c *KeyorixCore) notify(ctx context.Context, userID uint, nType, title, message string, projectID *uint, link string) {
	c.notifyWithSeverity(ctx, userID, nType, title, message, projectID, link, models.NotificationSeverityNone)
}

// notifyWithSeverity is notify plus a recorded NotificationSeverity (#250):
// reminder schedulers (expiry/rotation/license) use this so a later recheck can
// compare a newly computed severity against what's recorded here on the
// standing unread reminder — see upgradeReminder. Notification types that don't
// participate in escalation-aware dedup should keep using plain notify(), which
// records NotificationSeverityNone.
//
// #488: a failed CreateNotification — including the benign duplicate-skip a
// concurrent reminder run hits against the unread-reminder dedup index — must not
// still fire an out-of-band delivery for a row that was never actually persisted,
// or the race this index closes at the DB layer would still duplicate the
// user-visible email/webhook. Mirrors upgradeReminder's identical guard (#482).
func (c *KeyorixCore) notifyWithSeverity(ctx context.Context, userID uint, nType, title, message string, projectID *uint, link string, severity models.NotificationSeverity) { // NOSONAR -- domain-driven parameter count
	if userID == 0 {
		return
	}
	if _, err := c.storage.CreateNotification(ctx, &models.Notification{
		UserID:    userID,
		ProjectID: projectID,
		Type:      nType,
		Title:     title,
		Message:   message,
		Link:      link,
		Severity:  severity,
		CreatedAt: c.now(),
	}); err != nil {
		return
	}
	c.dispatchNotification(ctx, userID, nType, title, message, projectID, link)
}

// upgradeReminder overwrites Title/Message/Severity on an existing unread
// standing reminder notification in place and persists it (#250). Used when a
// recheck finds a strictly more severe state than what the notification was
// last created/updated with, so the escalation reaches the user without
// piling up a second unread notification of the same (user, type, project).
// Returns whether the update succeeded (best-effort — a storage failure here
// just means the stale reminder stands until the next tick).
//
// #482: an escalation must also re-fire the out-of-band channel exactly like a
// fresh notification does, or a Warning-level reminder silently escalating to
// Critical (e.g. "expiring soon" → "now expired") would update the DB row but
// never re-send the email/webhook that made the state change visible in the
// first place. dispatchNotification is only called after the DB update
// succeeds, mirroring notifyWithSeverity's create path.
func (c *KeyorixCore) upgradeReminder(ctx context.Context, n *models.Notification, title, message string, severity models.NotificationSeverity) bool {
	n.Title, n.Message, n.Severity = title, message, severity
	if c.storage.UpdateNotification(ctx, n) != nil {
		return false
	}
	c.dispatchNotification(ctx, n.UserID, n.Type, title, message, n.ProjectID, n.Link)
	return true
}

// dispatchNotification fans a per-user notification out to the recipient-addressable
// external channel (email), resolving the recipient's email best-effort. A no-op
// when no such sink is wired; the sink itself is non-blocking, so this never delays
// the caller.
//
// This deliberately uses recipientNotificationSink, not the deployment-wide
// notificationSink — see the package comment and #391.
func (c *KeyorixCore) dispatchNotification(ctx context.Context, userID uint, nType, title, message string, projectID *uint, link string) {
	if c.recipientNotificationSink == nil {
		return
	}
	ev := NotificationEvent{
		UserID:    userID,
		Type:      nType,
		Title:     title,
		Message:   message,
		ProjectID: projectID,
		Link:      link,
	}
	if u, err := c.storage.GetUser(ctx, userID); err == nil && u != nil {
		ev.Email = u.Email
	}
	c.recipientNotificationSink.Deliver(ev)
}

// projectLabel returns a human label for a project ("Payments" or "#3").
func (c *KeyorixCore) projectLabel(ctx context.Context, projectID uint) string {
	if p, err := c.storage.GetProject(ctx, projectID); err == nil && p.Name != "" {
		return p.Name
	}
	return fmt.Sprintf("#%d", projectID)
}

// notifyMembershipActivated tells the inviter their invitee is now active.
func (c *KeyorixCore) notifyMembershipActivated(ctx context.Context, m *models.ProjectMembership) {
	if m.InvitedBy == 0 || m.InvitedBy == m.UserID {
		return // self-serve activation: nobody distinct to notify.
	}
	pid := m.ProjectID
	link := fmt.Sprintf("/projects/%d", m.ProjectID)
	c.notify(ctx, m.InvitedBy, NotificationMembershipActivated,
		"Member activated",
		fmt.Sprintf("User %d is now an active member of %s.", m.UserID, c.projectLabel(ctx, m.ProjectID)),
		&pid, link)
}

// notifyAccessRequested fans a new-request notification out to project approvers.
func (c *KeyorixCore) notifyAccessRequested(ctx context.Context, req *models.AccessRequest) {
	members, err := c.storage.ListProjectMembers(ctx, req.ProjectID)
	if err != nil {
		return
	}
	pid := req.ProjectID
	label := c.projectLabel(ctx, req.ProjectID)
	link := fmt.Sprintf("/projects/%d", req.ProjectID)
	for _, mbr := range members {
		if mbr.UserID == req.UserID {
			continue // don't notify the requester of their own request.
		}
		if !isApproverRole(mbr.RoleName) {
			continue
		}
		c.notify(ctx, mbr.UserID, NotificationAccessRequested,
			"New access request",
			fmt.Sprintf("User %d requested %s access to %s.", req.UserID, req.SuggestedRole, label),
			&pid, link)
	}
}

// notifyAccessResolved tells the requester their request was approved/rejected.
func (c *KeyorixCore) notifyAccessResolved(ctx context.Context, req *models.AccessRequest, approved bool) {
	pid := req.ProjectID
	label := c.projectLabel(ctx, req.ProjectID)
	link := fmt.Sprintf("/projects/%d", req.ProjectID)
	if approved {
		c.notify(ctx, req.UserID, NotificationAccessApproved,
			"Access request approved",
			fmt.Sprintf("Your request for access to %s was approved as %s.", label, req.GrantedRole),
			&pid, link)
		return
	}
	c.notify(ctx, req.UserID, NotificationAccessRejected,
		"Access request rejected",
		fmt.Sprintf("Your request for access to %s was rejected.", label),
		&pid, link)
}

// notifySecretShared tells a recipient a secret was shared with them directly. Self-
// shares are skipped. Best-effort — failure never blocks the share.
func (c *KeyorixCore) notifySecretShared(ctx context.Context, secret *models.SecretNode, recipientID, sharedBy uint, permission string) {
	if secret == nil || recipientID == 0 || recipientID == sharedBy {
		return
	}
	var pid *uint
	if secret.ProjectID != 0 {
		p := secret.ProjectID
		pid = &p
	}
	c.notify(ctx, recipientID, NotificationSecretShared,
		"Secret shared with you",
		fmt.Sprintf("You were granted %s access to secret %q.", permission, secret.Name),
		pid, fmt.Sprintf("/secrets/%d", secret.ID))
}

// notifyGroupSecretShared fans the "shared with you" notification out to every member
// of a group a secret was shared with (excluding the sharer). Best-effort — a member
// lookup failure just means no fan-out.
func (c *KeyorixCore) notifyGroupSecretShared(ctx context.Context, secret *models.SecretNode, groupID, sharedBy uint, permission string) {
	if secret == nil {
		return
	}
	members, err := c.storage.ListGroupMembers(ctx, groupID)
	if err != nil {
		return
	}
	for _, m := range members {
		c.notifySecretShared(ctx, secret, m.ID, sharedBy, permission)
	}
}

// notifySecretShareRevoked tells a recipient their access to a secret was revoked.
// Direct shares only (a group share has no single user); skips the actor revoking
// their own share. Best-effort.
func (c *KeyorixCore) notifySecretShareRevoked(ctx context.Context, secret *models.SecretNode, recipientID, revokedBy uint) {
	if secret == nil || recipientID == 0 || recipientID == revokedBy {
		return
	}
	var pid *uint
	if secret.ProjectID != 0 {
		p := secret.ProjectID
		pid = &p
	}
	c.notify(ctx, recipientID, NotificationSecretShareRevoked,
		"Secret access revoked",
		fmt.Sprintf("Your access to secret %q was revoked.", secret.Name),
		pid, fmt.Sprintf("/secrets/%d", secret.ID))
}

// notifyGroupSecretShareRevoked fans the revoke notification out to every member of a
// group whose share was revoked (excluding the actor). Best-effort.
func (c *KeyorixCore) notifyGroupSecretShareRevoked(ctx context.Context, secret *models.SecretNode, groupID, revokedBy uint) {
	if secret == nil {
		return
	}
	members, err := c.storage.ListGroupMembers(ctx, groupID)
	if err != nil {
		return
	}
	for _, m := range members {
		c.notifySecretShareRevoked(ctx, secret, m.ID, revokedBy)
	}
}

// notifySecretOwnershipTransferred tells a user they are now the owner of a secret.
// Skipped when the actor transferred it to themselves. Best-effort.
func (c *KeyorixCore) notifySecretOwnershipTransferred(ctx context.Context, secret *models.SecretNode, newOwnerID, actorID uint) {
	if secret == nil || newOwnerID == 0 || newOwnerID == actorID {
		return
	}
	var pid *uint
	if secret.ProjectID != 0 {
		p := secret.ProjectID
		pid = &p
	}
	c.notify(ctx, newOwnerID, NotificationSecretOwnershipTransferred,
		"You are now a secret owner",
		fmt.Sprintf("You were made the owner of secret %q.", secret.Name),
		pid, fmt.Sprintf("/secrets/%d", secret.ID))
}

// notifySecretsReassigned tells a new owner that a batch of secrets was re-homed to
// them (bulk offboarding) — one summary instead of one-per-secret. Best-effort.
func (c *KeyorixCore) notifySecretsReassigned(ctx context.Context, newOwnerID, actorID, projectID uint, count int) {
	if newOwnerID == 0 || newOwnerID == actorID || count == 0 {
		return
	}
	var pid *uint
	if projectID != 0 {
		p := projectID
		pid = &p
	}
	c.notify(ctx, newOwnerID, NotificationSecretOwnershipTransferred,
		"Secrets reassigned to you",
		fmt.Sprintf("%d secret(s) in %s were reassigned to you.", count, c.projectLabel(ctx, projectID)),
		pid, fmt.Sprintf("/projects/%d", projectID))
}

// ── Self-scoped reads/writes (the authenticated user) ───────────────────────

// ListNotifications returns the user's notifications, newest first.
func (c *KeyorixCore) ListNotifications(ctx context.Context, userID uint, unreadOnly bool, limit int) ([]*models.Notification, error) {
	return c.storage.ListNotifications(ctx, userID, unreadOnly, limit)
}

// UnreadNotificationCount returns how many unread notifications the user has.
func (c *KeyorixCore) UnreadNotificationCount(ctx context.Context, userID uint) (int64, error) {
	return c.storage.CountUnreadNotifications(ctx, userID)
}

// MarkNotificationRead marks one of the user's notifications read (ownership-checked).
func (c *KeyorixCore) MarkNotificationRead(ctx context.Context, id, userID uint) error {
	return c.storage.MarkNotificationRead(ctx, id, userID)
}

// MarkAllNotificationsRead marks all of the user's notifications read.
func (c *KeyorixCore) MarkAllNotificationsRead(ctx context.Context, userID uint) error {
	return c.storage.MarkAllNotificationsRead(ctx, userID)
}
