// local_notification_channels.go — runtime-managed outbound notification channel
// persistence. Channels can be created, updated, and deleted at runtime without
// editing config files. The REST API is the remote surface; all methods here run
// server-side via LocalStorage only (see remote_notification_channels.go).
package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) ListNotificationChannels(ctx context.Context) ([]*models.NotificationChannel, error) {
	var rows []*models.NotificationChannel
	if err := ls.db.WithContext(ctx).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) GetNotificationChannel(ctx context.Context, id uint) (*models.NotificationChannel, error) {
	var row models.NotificationChannel
	err := ls.db.WithContext(ctx).First(&row, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &row, nil
}

// GetNotificationChannelByName returns the channel with the given name, or nil, nil
// when no such channel exists.
func (ls *LocalStorage) GetNotificationChannelByName(ctx context.Context, name string) (*models.NotificationChannel, error) {
	var row models.NotificationChannel
	err := ls.db.WithContext(ctx).Where("name = ?", name).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &row, nil
}

func (ls *LocalStorage) CreateNotificationChannel(ctx context.Context, ch *models.NotificationChannel) error {
	if err := ls.db.WithContext(ctx).Create(ch).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) UpdateNotificationChannel(ctx context.Context, ch *models.NotificationChannel) error {
	res := ls.db.WithContext(ctx).Model(ch).Updates(map[string]interface{}{
		"name":    ch.Name,
		"type":    ch.Type,
		"enabled": ch.Enabled,
		"url":     ch.URL,
		"email":   ch.Email,
		"events":  ch.Events,
	})
	if res.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

// DeleteNotificationChannel performs a hard delete of the channel with the given id.
func (ls *LocalStorage) DeleteNotificationChannel(ctx context.Context, id uint) error {
	res := ls.db.WithContext(ctx).Delete(&models.NotificationChannel{}, id)
	if res.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}
