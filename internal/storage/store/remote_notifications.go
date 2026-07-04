// remote_notifications.go — in-app notifications for RemoteStorage.
//
// Notifications are processed server-side in remote mode; these are stubs. For
// the local (GORM) equivalent see local_notifications.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateNotification(_ context.Context, _ *models.Notification) (*models.Notification, error) {
	return nil, remoteUnsupported("CreateNotification")
}

func (rs *RemoteStorage) ListNotifications(_ context.Context, _ uint, _ bool, _ int) ([]*models.Notification, error) {
	return nil, remoteUnsupported("ListNotifications")
}

func (rs *RemoteStorage) CountUnreadNotifications(_ context.Context, _ uint) (int64, error) {
	return 0, remoteUnsupported("CountUnreadNotifications")
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
