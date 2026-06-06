// local_notifications.go — in-app notification persistence (ADR-024).
//
// Notifications are addressed to a single user and surfaced via the header bell.
// For the remote (HTTP) equivalent see remote_notifications.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const defaultNotificationLimit = 50

func (ls *LocalStorage) CreateNotification(ctx context.Context, n *models.Notification) (*models.Notification, error) {
	if err := ls.db.WithContext(ctx).Create(n).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return n, nil
}

func (ls *LocalStorage) ListNotifications(ctx context.Context, userID uint, unreadOnly bool, limit int) ([]*models.Notification, error) {
	if limit <= 0 || limit > 200 {
		limit = defaultNotificationLimit
	}
	q := ls.db.WithContext(ctx).Where("user_id = ?", userID)
	if unreadOnly {
		q = q.Where("is_read = ?", false)
	}
	var rows []*models.Notification
	if err := q.Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) CountUnreadNotifications(ctx context.Context, userID uint) (int64, error) {
	var n int64
	if err := ls.db.WithContext(ctx).Model(&models.Notification{}).
		Where("user_id = ? AND is_read = ?", userID, false).
		Count(&n).Error; err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return n, nil
}

func (ls *LocalStorage) MarkNotificationRead(ctx context.Context, id, userID uint) error {
	res := ls.db.WithContext(ctx).Model(&models.Notification{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("is_read", true)
	if res.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected == 0 {
		// No row for this (id, user) — not found or not the caller's.
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) MarkAllNotificationsRead(ctx context.Context, userID uint) error {
	if err := ls.db.WithContext(ctx).Model(&models.Notification{}).
		Where("user_id = ? AND is_read = ?", userID, false).
		Update("is_read", true).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}
