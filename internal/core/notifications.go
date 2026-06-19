// notifications.go — in-app notifications (ADR-024).
//
// Notifications are addressed to a single user and surfaced via the header bell.
// Emission is best-effort: a delivery failure never blocks the action that
// triggered it (same contract as audit emission). In addition to the in-app row,
// notify() fans each event out to a configured external channel (email/webhook)
// when a NotificationSink is wired.
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
	if userID == 0 {
		return
	}
	_, _ = c.storage.CreateNotification(ctx, &models.Notification{
		UserID:    userID,
		ProjectID: projectID,
		Type:      nType,
		Title:     title,
		Message:   message,
		Link:      link,
		CreatedAt: c.now(),
	})
	c.dispatchNotification(ctx, userID, nType, title, message, projectID, link)
}

// dispatchNotification fans a notification out to the configured external channel
// (email/webhook), resolving the recipient's email best-effort. A no-op when no
// sink is wired; the sink itself is non-blocking, so this never delays the caller.
func (c *KeyorixCore) dispatchNotification(ctx context.Context, userID uint, nType, title, message string, projectID *uint, link string) {
	if c.notificationSink == nil {
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
	c.notificationSink.Deliver(ev)
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
