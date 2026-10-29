package admin

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/storage"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// encryptRestoredNotificationURLs runs, on the just-restored database with
// its just-installed key files, the notification-channel URL backfill the
// server runs at every start (MigrateNotificationChannelURLsToEncrypted,
// #2433/#2468). A backup written before #2468 (v0.95.x) carries each webhook
// URL in plaintext; backupfmt.LoadArchive puts it back into the legacy `url`
// column (#3452), and this moves it into url_enc/url_meta and clears the
// plaintext before anything else reads or backs up the database. A later
// `admin backup` taken before the first server start would otherwise not
// carry it at all: the current model does not map the legacy column.
//
// Idempotent, and a no-op on a database without the legacy column. It runs
// while the restore journal still exists, so a failure keeps the journal and
// `admin restore --recover` runs it again; the server's own startup runs the
// same backfill too and refuses to start until it succeeds. It unlocks with
// the restore run's passphrase (restorePassphrase), never by reading a
// one-shot --passphrase-stdin/--passphrase-fd source a second time.
func encryptRestoredNotificationURLs(cfg *config.Config) error {
	// Opened directly, not through the storage factory: the factory migrates,
	// and a restore must not rewrite the rows it just loaded.
	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		return fmt.Errorf("open the restored database: %w", err)
	}
	defer closeGormDB(db)
	if has, err := hasLegacyNotificationURLColumn(db); err != nil || !has {
		return err // only a pre-#2468 archive brings the column back (backupfmt's legacyColumns)
	}
	var enc ports.EncryptionProvider
	if cfg.Storage.Encryption.Enabled {
		svc, err := unlockEncryptionService(cfg, restorePassphrase.resolve)
		if err != nil {
			return err
		}
		defer svc.Shutdown()
		enc = svc
	}
	n, err := localstore.NewLocalStorage(db).MigrateNotificationChannelURLsToEncrypted(context.Background(), enc)
	if err != nil {
		return err
	}
	if n > 0 {
		fmt.Printf("Encrypted %d notification channel URL(s) carried in plaintext by this older backup.\n", n)
	}
	return nil
}

func hasLegacyNotificationURLColumn(db *gorm.DB) (bool, error) {
	cols, err := db.Migrator().ColumnTypes("notification_channels")
	if err != nil {
		return false, fmt.Errorf("read notification_channels columns: %w", err)
	}
	for _, c := range cols {
		if c.Name() == "url" {
			return true, nil
		}
	}
	return false, nil
}
