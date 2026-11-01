package admin

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// refuseUnmigratedLegacyNotificationURLs fails a backup whose source database
// still holds a webhook URL only in the plaintext legacy notification_channels.url
// column, i.e. one upgraded in place from v0.95.x and backed up before the new
// server's first start ran MigrateNotificationChannelURLsToEncrypted.
//
// The archive writer maps only the current model's columns, and the model's URL
// field is gorm:"-", so such a row would be archived with an empty url_enc and
// no URL anywhere: the restored channel has no destination, and nothing says so.
// Carrying the value is not an option short of writing the plaintext into the
// archive: encrypting it here needs the DEK (a live server holds dek.lock, and
// INV-ENCRYPTION-01 forbids initializing against the live key directory), and
// AES-GCM output differs on every call, so the writer's hashing pass and writing
// pass would disagree on the table's SHA-256. The server's startup backfill is
// the one place that does this encryption, so the backup asks for it to have run.
//
// Reads through db, the same snapshot/lock the archive is read through, and
// before the archive file exists. A database without the legacy column (a fresh
// install, or a restored one) and a legacy column the backfill already cleared
// both pass. Rows are read without the soft-delete scope: the archive carries
// soft-deleted rows too.
func refuseUnmigratedLegacyNotificationURLs(db *gorm.DB) error {
	cols, err := db.Migrator().ColumnTypes("notification_channels")
	if err != nil {
		return fmt.Errorf("read notification_channels columns: %w", err)
	}
	hasLegacy := false
	for _, c := range cols {
		if c.Name() == "url" {
			hasLegacy = true
			break
		}
	}
	if !hasLegacy {
		return nil
	}
	var rows []struct {
		ID     uint
		URLEnc []byte `gorm:"column:url_enc"`
	}
	if err := db.Table("notification_channels").Select("id, url_enc").
		Where("url IS NOT NULL AND url <> ''").Find(&rows).Error; err != nil {
		return fmt.Errorf("read legacy notification channel URLs: %w", err)
	}
	var ids []string
	for _, r := range rows {
		tag, _, err := ports.UnwrapNotificationChannelURL(r.URLEnc)
		if err != nil {
			return fmt.Errorf("notification channel %d: %w", r.ID, err)
		}
		if tag == ports.NotificationChannelURLTagAbsent {
			ids = append(ids, fmt.Sprint(r.ID))
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return fmt.Errorf("refusing to back up: %d notification channel(s) (id %s) still keep their webhook URL only in the "+
		"plaintext legacy notification_channels.url column, because this database was upgraded in place and the new "+
		"server has not finished its upgrade migrations, so a backup taken now would silently drop those URLs. "+
		"To fix: start the server once to finish the upgrade migrations, then back up "+
		"(its startup encrypts the URLs and clears the legacy column)",
		len(ids), strings.Join(ids, ", "))
}
