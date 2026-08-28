// remote_notifications.go — in-app notifications for RemoteStorage (ADR-024).
//
// The self-scoped user-facing surface (GET /notifications, POST /notifications/
// {id}/read, POST /notifications/read-all — see server/http/router.go and
// notifications_handler.go) is real and proxied below for ListNotifications/
// CountUnreadNotifications/MarkNotificationRead/MarkAllNotificationsRead.
//
// HasUnreadNotification/GetUnreadNotification/UpdateNotification stay
// unconditional stubs correctly: these three back ONLY the escalation-aware
// reminder dedup path (upgradeReminder, notifications.go; the various
// *_reminders.go/*_expiry.go/*_alerts.go schedulers), invoked exclusively from
// server-internal background jobs and the system.write-gated POST
// /admin/jobs/* on-demand triggers — both of which always run against the
// server's own LocalStorage, never against a remote client's storage.Storage.
// There is no self-scoped route that lets an authenticated end user
// create/escalate an arbitrary notification for themselves (rightly so: that
// would let a self-scoped-only credential forge notifications, e.g.
// impersonate a "your access was approved" system message), so there is
// nothing for these three to proxy to.
//
// CreateNotification is a DIFFERENT case, and the claim above does not extend
// to it: it backs notify()/notifyWithSeverity() generally, not just the
// reminder/dedup path — every notification-worthy core action (access
// requests, membership activation, secret sharing, ...) calls through it, and
// several of those ARE reachable from an unguarded CLI command running
// embedded against `storage.type: remote` (`keyorix request access`/`request
// secret-access`/`request review`, none behind a NewRemoteClient()-family
// guard). Confirmed LIVE, and it FAILS OPEN: notifyWithSeverity swallows
// whatever error this stub returns, so the triggering action (e.g. the access
// request itself) reports success while the notification is silently never
// created. Filed as #1589, not fixed pending a Wave 2 design decision
// (implement the write over the wire vs. make the failure visible some other
// way) — see docs/adr-087-remote-storage-deletion-pass.md and the #1589
// liveness re-confirmation this comment was corrected alongside.
//
// For the local (GORM) equivalent see local_notifications.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateNotification(_ context.Context, _ *models.Notification) (*models.Notification, error) {
	return nil, remoteUnsupported("CreateNotification")
}

// notificationWireResponse mirrors notificationToAPI's response shape
// (server/http/handlers/notifications_handler.go) — the actual wire shape GET
// /notifications returns. models.Notification carries no json tags of its own,
// so decoding straight into it would suffer the identical field-name mismatch
// class as #496: encoding/json's case-insensitive fallback saves single-word
// fields ("id"/"type"/"title"/"message"/"link" happen to still match "ID"/
// "Type"/"Title"/"Message"/"Link"), but "is_read"/"created_at"/"project_id" do
// NOT case-insensitively equal "IsRead"/"CreatedAt"/"ProjectID" — those three
// would silently come back zeroed (a read notification would misreport as
// unread, and every list/scoping decision keyed on CreatedAt ordering or
// ProjectID would be wrong) without this explicit tagging.
type notificationWireResponse struct {
	ID        uint      `json:"id"`
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	Link      string    `json:"link"`
	IsRead    bool      `json:"is_read"`
	CreatedAt time.Time `json:"created_at"`
	ProjectID *uint     `json:"project_id,omitempty"`
}

func (w notificationWireResponse) toModel() *models.Notification {
	return &models.Notification{
		ID:        w.ID,
		ProjectID: w.ProjectID,
		Type:      w.Type,
		Title:     w.Title,
		Message:   w.Message,
		Link:      w.Link,
		IsRead:    w.IsRead,
		CreatedAt: w.CreatedAt,
	}
}

// notificationListResponse is the full GET /notifications envelope: the page of
// notifications plus the bell-badge unread count, computed server-side
// independently of the list's own unread/limit filters.
type notificationListResponse struct {
	Notifications []notificationWireResponse `json:"notifications"`
	UnreadCount   int64                      `json:"unread_count"`
}

// fetchNotifications calls the self-scoped GET /notifications route. userID is
// deliberately not sent: like MarkNotificationRead/MarkAllNotificationsRead
// below, the server derives the caller from the authenticated session/token
// (ADR-024, "self-scoped, no permission gate") — there is no user_id query
// parameter honored server-side, so a caller can never widen this beyond its own
// identity by passing a different userID here.
func (rs *RemoteStorage) fetchNotifications(ctx context.Context, unreadOnly bool, limit int) (*notificationListResponse, error) {
	path := "/api/v1/notifications"
	q := ""
	if unreadOnly {
		q += "unread=true"
	}
	if limit > 0 {
		if q != "" {
			q += "&"
		}
		q += "limit=" + strconv.Itoa(limit)
	}
	if q != "" {
		path += "?" + q
	}
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list notifications: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list notifications failed: %s", resp.Error.Error())
	}
	var result notificationListResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// ListNotifications returns the caller's notifications, newest first, via the
// self-scoped GET /notifications route. See fetchNotifications for the
// userID-is-implicit scoping note.
func (rs *RemoteStorage) ListNotifications(ctx context.Context, _ uint, unreadOnly bool, limit int) ([]*models.Notification, error) {
	result, err := rs.fetchNotifications(ctx, unreadOnly, limit)
	if err != nil {
		return nil, err
	}
	out := make([]*models.Notification, 0, len(result.Notifications))
	for _, w := range result.Notifications {
		out = append(out, w.toModel())
	}
	return out, nil
}

// CountUnreadNotifications reads the unread count off the same GET
// /notifications response used by ListNotifications — there is no separate
// count-only endpoint. limit=1 keeps the accompanying (here-discarded)
// notification page minimal; the server computes unread_count independently of
// the list's own unread/limit filters, so a small limit does not affect the
// count itself.
func (rs *RemoteStorage) CountUnreadNotifications(ctx context.Context, _ uint) (int64, error) {
	result, err := rs.fetchNotifications(ctx, false, 1)
	if err != nil {
		return 0, err
	}
	return result.UnreadCount, nil
}

func (rs *RemoteStorage) HasUnreadNotification(_ context.Context, _ uint, _ string, _ uint) (bool, error) {
	return false, remoteUnsupported("HasUnreadNotification")
}

func (rs *RemoteStorage) GetUnreadNotification(_ context.Context, _ uint, _ string, _ uint) (*models.Notification, error) {
	return nil, remoteUnsupported("GetUnreadNotification")
}

func (rs *RemoteStorage) UpdateNotification(_ context.Context, _ *models.Notification) error {
	return remoteUnsupported("UpdateNotification")
}

func (rs *RemoteStorage) MarkNotificationRead(ctx context.Context, id, _ uint) error {
	// The server scopes the mark to the authenticated user (the client's own
	// session), so userID is implicit in the endpoint.
	resp, err := rs.client.Post(ctx, fmt.Sprintf("/api/v1/notifications/%d/read", id), nil)
	if err != nil {
		return fmt.Errorf("failed to mark notification read: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("mark notification read failed: %s", resp.Error.Error())
	}
	return nil
}

func (rs *RemoteStorage) MarkAllNotificationsRead(ctx context.Context, _ uint) error {
	resp, err := rs.client.Post(ctx, "/api/v1/notifications/read-all", nil)
	if err != nil {
		return fmt.Errorf("failed to mark all notifications read: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("mark all notifications read failed: %s", resp.Error.Error())
	}
	return nil
}
