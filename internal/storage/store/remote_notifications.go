// remote_notifications.go — in-app notifications for RemoteStorage (ADR-024).
//
// The self-scoped user-facing surface (GET /notifications, POST /notifications/
// {id}/read, POST /notifications/read-all — see server/http/router.go and
// notifications_handler.go) is real and proxied below for ListNotifications/
// CountUnreadNotifications/MarkNotificationRead/MarkAllNotificationsRead.
//
// CreateNotification is ALSO real, proxied via POST /api/v1/system/notifications
// (server/http/handlers/notification_proxy.go, #1589). It backs notify()/
// notifyWithSeverity() (internal/core/notifications.go) generally, not just the
// reminder/dedup path — every notification-worthy core action (access requests,
// membership activation, secret sharing, ...) calls through it, and several are
// reachable from an unguarded CLI command running embedded against
// storage.type: remote (`keyorix request access`/`request secret-access`/
// `request review`). Before this fix it was an unconditional remoteUnsupported
// stub: notifyWithSeverity is a best-effort, error-swallowing wrapper by design
// (the same contract as audit emission), so a 100%-failing stub composed with
// that contract produced a silent, permanent feature outage rather than a
// visible error — every one of those actions succeeded while its notification
// was dropped with no signal anywhere. See #1589 for the full liveness trace
// and docs/adr-087-remote-storage-deletion-pass.md for the classification pass
// that found it.
//
// HasUnreadNotification/GetUnreadNotification/UpdateNotification stay
// unconditional stubs correctly: these three back ONLY the escalation-aware
// reminder dedup path (upgradeReminder; the *_reminders.go/*_expiry.go/
// *_alerts.go schedulers), invoked exclusively from server-internal background
// jobs and the system.write-gated POST /admin/jobs/* on-demand triggers — both
// of which always run against the server's own LocalStorage, never against a
// remote client's storage.Storage. There is no self-scoped route that lets an
// authenticated end user create/escalate an arbitrary notification for
// themselves (rightly so: that would let a self-scoped-only credential forge
// notifications, e.g. impersonate a "your access was approved" system
// message), so there is nothing for these three to proxy to.
//
// For the local (GORM) equivalent see local_notifications.go.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
)

// notificationCreateWire mirrors models.Notification's PERSISTED fields
// exactly (snake_case) — matches server/http/handlers/notification_proxy.go's
// notificationProxyWire byte for byte (the actual wire shape POST
// /api/v1/system/notifications sends/expects). Deliberately distinct from
// notificationWireResponse below: that struct is the self-scoped GET
// /notifications DISPLAY shape, which omits SecretNodeID/Severity — a create
// needs the full persisted shape so every field notifyWithSeverity sets
// round-trips.
type notificationCreateWire struct {
	ID           uint      `json:"id"`
	UserID       uint      `json:"user_id"`
	SecretNodeID *uint     `json:"secret_node_id,omitempty"`
	ProjectID    *uint     `json:"project_id,omitempty"`
	Type         string    `json:"type"`
	Title        string    `json:"title"`
	Message      string    `json:"message"`
	Link         string    `json:"link"`
	Severity     int       `json:"severity"`
	IsRead       bool      `json:"is_read"`
	CreatedAt    time.Time `json:"created_at"`
}

func newNotificationCreateWire(n *models.Notification) notificationCreateWire {
	return notificationCreateWire{
		UserID:       n.UserID,
		SecretNodeID: n.SecretNodeID,
		ProjectID:    n.ProjectID,
		Type:         n.Type,
		Title:        n.Title,
		Message:      n.Message,
		Link:         n.Link,
		Severity:     int(n.Severity),
		CreatedAt:    n.CreatedAt,
	}
}

func (w notificationCreateWire) toModel() *models.Notification {
	return &models.Notification{
		ID:           w.ID,
		UserID:       w.UserID,
		SecretNodeID: w.SecretNodeID,
		ProjectID:    w.ProjectID,
		Type:         w.Type,
		Title:        w.Title,
		Message:      w.Message,
		Link:         w.Link,
		Severity:     models.NotificationSeverity(w.Severity),
		IsRead:       w.IsRead,
		CreatedAt:    w.CreatedAt,
	}
}

// notificationDuplicateReminderCode mirrors
// notification_proxy.go's identical constant — the wire-level signal used to
// reconstruct storage.ErrDuplicateReminderNotification across this HTTP hop,
// the same pattern remote_secret_dependencies.go's
// duplicateSecretDependencyCode uses for CreateSecretDependencyExclusive.
const notificationDuplicateReminderCode = "DUPLICATE_REMINDER_NOTIFICATION"

// CreateNotification persists a notification via POST
// /api/v1/system/notifications — see the package doc for the liveness history
// and server/http/handlers/notification_proxy.go's package doc for why there
// is no wire-actor concern here (models.Notification carries no actor/origin
// field to misattribute).
func (rs *RemoteStorage) CreateNotification(ctx context.Context, n *models.Notification) (*models.Notification, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/notifications", newNotificationCreateWire(n))
	if err != nil {
		var httpErr *remote.HTTPError
		if errors.As(err, &httpErr) && httpErr.ErrorType == notificationDuplicateReminderCode {
			return nil, fmt.Errorf("%w: %s", storage.ErrDuplicateReminderNotification, httpErr.Message)
		}
		return nil, fmt.Errorf("failed to create notification: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create notification failed: %s", resp.Error.Error())
	}
	var wire notificationCreateWire
	if err := json.Unmarshal(resp.Data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
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
