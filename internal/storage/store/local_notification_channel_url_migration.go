// local_notification_channel_url_migration.go — one-time backfill moving
// NotificationChannel's legacy plaintext `url` column into the encrypted
// url_enc/url_meta columns (#2433).
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// legacyNotificationChannelURLRow reads only the two columns this migration
// needs, via the raw "url" column name — models.NotificationChannel.URL is
// gorm:"-" (not persisted) as of #2433, so a normal Find into that model
// would never see the legacy plaintext value at all.
type legacyNotificationChannelURLRow struct {
	ID  uint
	URL string `gorm:"column:url"`
}

// MigrateNotificationChannelURLsToEncrypted backfills every NotificationChannel
// row that still carries its URL in the legacy plaintext `url` column: encrypts
// it (bound to the channel's own ID, the same AAD notification_channels.go's
// CRUD methods use) when encryptor is non-nil and enabled, or copies it through
// as-is otherwise — mirroring internal/core's own encryptAuthSecret
// disabled-encryption passthrough exactly, so a later core-layer decrypt reads
// either form back correctly. Clears the legacy `url` column on success so the
// plaintext bytes don't linger in the row once its encrypted replacement is
// durable.
//
// Idempotent and safe to call on every startup, not just the first one after
// upgrading: a row whose url_enc is already populated is left untouched, and a
// row with no legacy plaintext (newly created after #2433, or already migrated)
// is simply not selected.
func (ls *LocalStorage) MigrateNotificationChannelURLsToEncrypted(ctx context.Context, encryptor ports.EncryptionProvider) (int, error) {
	// A fresh install never had a `url` column at all --
	// models.NotificationChannel.URL is gorm:"-", so AutoMigrate never creates
	// it from scratch there. Only an install upgrading from a pre-#2433 binary
	// has one. Querying a nonexistent column would error, not just return zero
	// rows, so check first -- via ColumnTypes (portable across SQLite/Postgres),
	// not HasColumn, which resolves by STRUCT FIELD name and "url" is no
	// longer one.
	cols, err := ls.db.WithContext(ctx).Migrator().ColumnTypes(&models.NotificationChannel{})
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	hasLegacyColumn := false
	for _, c := range cols {
		if c.Name() == "url" {
			hasLegacyColumn = true
			break
		}
	}
	if !hasLegacyColumn {
		return 0, nil
	}
	var rows []legacyNotificationChannelURLRow
	err = ls.db.WithContext(ctx).Model(&models.NotificationChannel{}).
		Select("id, url").
		Where("(url_enc IS NULL OR length(url_enc) = 0) AND url IS NOT NULL AND url != ''").
		Find(&rows).Error
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	migrated := 0
	for _, r := range rows {
		var urlEnc, urlMeta []byte
		if encryptor != nil && encryptor.IsEnabled() {
			var eerr error
			urlEnc, urlMeta, eerr = encryptor.EncryptSecretWithAAD([]byte(r.URL), ports.NotificationChannelURLAAD(r.ID))
			if eerr != nil {
				return migrated, fmt.Errorf("failed to encrypt notification channel %d URL during migration: %w", r.ID, eerr)
			}
		} else {
			urlEnc = []byte(r.URL)
		}
		res := ls.db.WithContext(ctx).Model(&models.NotificationChannel{}).Where("id = ?", r.ID).
			Updates(map[string]interface{}{"url_enc": urlEnc, "url_meta": urlMeta, "url": ""})
		if res.Error != nil {
			return migrated, fmt.Errorf("%s: failed to persist migrated URL for notification channel %d: %w", i18n.T("ErrorStorageFailed", nil), r.ID, res.Error)
		}
		migrated++
	}
	return migrated, nil
}
