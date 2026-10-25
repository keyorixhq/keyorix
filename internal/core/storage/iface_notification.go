package storage

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// NotificationStore is the Storage slice for notifications, notification channels and alert escalation.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type NotificationStore interface {
	// In-app notifications (ADR-024).
	CreateNotification(ctx context.Context, n *models.Notification) (*models.Notification, error)
	// ListNotifications returns a user's notifications newest-first; when
	// unreadOnly is set, only unread ones. limit caps the result (0 = default).
	ListNotifications(ctx context.Context, userID uint, unreadOnly bool, limit int) ([]*models.Notification, error)
	CountUnreadNotifications(ctx context.Context, userID uint) (int64, error)
	// HasUnreadNotification reports whether the user has an unread notification of
	// the given type scoped to the given project. Filters at the DB level (no
	// unbounded/"top N of everything" fetch), so it finds a match regardless of
	// how many other unread notifications of other types/projects exist (#399).
	HasUnreadNotification(ctx context.Context, userID uint, nType string, projectID uint) (bool, error)
	// GetUnreadNotification returns the user's unread notification of the given
	// type scoped to the given project, or nil if none exists. Unlike
	// HasUnreadNotification, this returns the full row so a dedup check can also
	// compare (and, on escalation, update) its recorded Severity instead of only
	// checking existence (#250).
	GetUnreadNotification(ctx context.Context, userID uint, nType string, projectID uint) (*models.Notification, error)
	// UpdateNotification updates an existing notification's Title/Message/Severity
	// in place, scoped to its owner (id + userID must both match or nothing is
	// changed). Used to escalate a standing reminder when a recheck finds a more
	// severe state than what was originally recorded (#250), instead of creating
	// a second unread notification and piling up.
	UpdateNotification(ctx context.Context, n *models.Notification) error
	// MarkNotificationRead marks one notification read, scoped to its owner.
	MarkNotificationRead(ctx context.Context, id, userID uint) error
	MarkAllNotificationsRead(ctx context.Context, userID uint) error
	// The Scoped variants see only the user's notifications inside scope (see
	// NotificationScope): the feed of a restricted personal access token. The
	// narrowing is in the query, so limit and the count apply to the rows the token
	// can see, not to a newest-N window of all of them (PAT-GUARD-1).
	ListScopedNotifications(ctx context.Context, userID uint, scope NotificationScope, unreadOnly bool, limit int) ([]*models.Notification, error)
	CountUnreadScopedNotifications(ctx context.Context, userID uint, scope NotificationScope) (int64, error)
	// MarkScopedNotificationRead returns not-found for a notification outside scope.
	MarkScopedNotificationRead(ctx context.Context, id, userID uint, scope NotificationScope) error
	MarkAllScopedNotificationsRead(ctx context.Context, userID uint, scope NotificationScope) error

	// Notification channel management — runtime-managed outbound destinations
	// (webhook/slack/teams/email). The REST API is the remote surface; these
	// methods only run server-side via LocalStorage.
	ListNotificationChannels(ctx context.Context) ([]*models.NotificationChannel, error)
	GetNotificationChannel(ctx context.Context, id uint) (*models.NotificationChannel, error)
	GetNotificationChannelByName(ctx context.Context, name string) (*models.NotificationChannel, error)
	CreateNotificationChannel(ctx context.Context, ch *models.NotificationChannel) error
	UpdateNotificationChannel(ctx context.Context, ch *models.NotificationChannel) error
	DeleteNotificationChannel(ctx context.Context, id uint) error
	// UpdateNotificationRetryPolicy updates the retry fields on a NotificationChannel row.
	UpdateNotificationRetryPolicy(ctx context.Context, channelID uint, maxRetries, backoffMs int) error

	// AlertEscalationPolicy CRUD
	CreateAlertEscalationPolicy(ctx context.Context, p *models.AlertEscalationPolicy) error
	GetAlertEscalationPolicy(ctx context.Context, id uint) (*models.AlertEscalationPolicy, error)
	ListAlertEscalationPolicies(ctx context.Context) ([]models.AlertEscalationPolicy, error)
	UpdateAlertEscalationPolicy(ctx context.Context, p *models.AlertEscalationPolicy) error
	DeleteAlertEscalationPolicy(ctx context.Context, id uint) error
}
