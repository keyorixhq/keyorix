package admin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// A database upgraded in place from v0.95.x keeps the plaintext legacy
// notification_channels.url column, and its rows have no url_enc until the new
// server's first start runs MigrateNotificationChannelURLsToEncrypted. The
// backup writer maps only the current model's columns, so a backup taken in
// that window used to drop every webhook URL without a word (ABT-1 item 1).
//
// The state is built from the v0.95.3 fixture #3807 added
// (testdata/v0.95.3-backup.tar.gz, restored by setupV0953ArchiveRestore) and
// then put back into the in-place-upgrade state: legacy `url` holding the
// plaintext, url_enc/url_meta empty. scripts/release-qa/
// backup_inplace_upgrade_check.sh drives the same path with a real old binary.

// inPlaceLegacyBackupRefusal is the operator-facing remedy the refusal names.
const inPlaceLegacyBackupRefusal = "start the server once to finish the upgrade migrations, then back up"

// TestAdminBackup_InPlaceUpgradeBeforeFirstStart_NeverDropsTheURL: whichever way
// the backup goes (refuse, or carry the value), the channel URL is never
// silently lost. Red on a tree whose backup succeeds and restores an empty URL.
func TestAdminBackup_InPlaceUpgradeBeforeFirstStart_NeverDropsTheURL(t *testing.T) {
	forEachInPlaceBackend(t, func(t *testing.T, storageBlock func(string) string) {
		pass := setupInPlaceUpgradedDatabase(t, storageBlock)
		archive := filepath.Join(t.TempDir(), "backup.tar.gz")
		backupOutput = archive
		out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
		if err != nil {
			require.Contains(t, err.Error(), inPlaceLegacyBackupRefusal, "output:\n%s", out)
			_, statErr := os.Stat(archive)
			require.True(t, os.IsNotExist(statErr), "a refused backup must leave no archive")
			return
		}
		restoreAndRequireChannelURL(t, storageBlock, archive, pass)
	})
}

// TestAdminBackup_InPlaceUpgradeAfterFirstStart_CarriesTheURL is the remedy the
// refusal names, run for real: after the startup backfill the backup succeeds
// and the URL survives backup then restore.
func TestAdminBackup_InPlaceUpgradeAfterFirstStart_CarriesTheURL(t *testing.T) {
	forEachInPlaceBackend(t, func(t *testing.T, storageBlock func(string) string) {
		pass := setupInPlaceUpgradedDatabase(t, storageBlock)
		runFirstServerStartBackfill(t, pass)
		archive := filepath.Join(t.TempDir(), "backup.tar.gz")
		backupOutput = archive
		out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
		require.NoError(t, err, "output:\n%s", out)
		restoreAndRequireChannelURL(t, storageBlock, archive, pass)
	})
}

func forEachInPlaceBackend(t *testing.T, fn func(t *testing.T, storageBlock func(string) string)) {
	t.Run("SQLite", func(t *testing.T) {
		fn(t, func(dir string) string {
			return fmt.Sprintf("  type: local\n  database:\n    path: %s\n", filepath.Join(dir, "secrets.db"))
		})
	})
	t.Run("Postgres", func(t *testing.T) {
		base := pgAdminTestDSN(t)
		fn(t, func(string) string {
			return fmt.Sprintf("  type: postgres\n  database:\n    dsn: %q\n", pgAdminIsolatedDatabaseDSN(t, base))
		})
	})
}

// setupInPlaceUpgradedDatabase leaves the working directory holding a database
// in the state an in-place upgrade from v0.95.3 has before the new server's
// first start, with its keys and the passphrase in the environment. It returns
// the passphrase.
func setupInPlaceUpgradedDatabase(t *testing.T, storageBlock func(string) string) string {
	t.Helper()
	setupV0953ArchiveRestore(t, storageBlock)
	t.Setenv("KEYORIX_MASTER_PASSWORD", v0953FixturePassphrase)
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "restore of the v0.95.3 fixture:\n%s", out)

	cfg, err := loadConfig()
	require.NoError(t, err)
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	defer closeGormDB(gdb)
	// What a v0.95.3 database looks like after the new binary's schema
	// migrations but before its startup backfill: the plaintext URL in `url`,
	// nothing in url_enc/url_meta.
	// (The restore above left the `url` column in place: it added it to carry
	// the archive's value, and clearing the value does not drop the column.)
	require.NoError(t, gdb.Exec("UPDATE notification_channels SET url = ?, url_enc = NULL, url_meta = NULL WHERE id = 1",
		v0953FixtureChannelURL).Error)
	return v0953FixturePassphrase
}

// runFirstServerStartBackfill is what the new server's first start does to
// this database (cmd/server's MigrateNotificationChannelURLsToEncrypted call),
// run in the working directory against its keys.
func runFirstServerStartBackfill(t *testing.T, passphrase string) {
	t.Helper()
	cfg, err := loadConfig()
	require.NoError(t, err)
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	defer closeGormDB(gdb)
	enc := encryption.NewService(&cfg.Storage.Encryption, ".")
	require.NoError(t, enc.Initialize(passphrase))
	defer enc.Shutdown()
	n, err := localstore.NewLocalStorage(gdb).MigrateNotificationChannelURLsToEncrypted(context.Background(), enc)
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

// restoreAndRequireChannelURL restores archive into a fresh target (a new
// working directory, and a new database on Postgres) and requires channel 1's
// URL to decrypt to the original under the restored keys.
func restoreAndRequireChannelURL(t *testing.T, storageBlock func(string) string, archive, passphrase string) {
	t.Helper()
	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	cfgPath := filepath.Join(dstDir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("storage:\n"+storageBlock(dstDir)+
		"  encryption:\n    enabled: true\n    dek_path: keys/dek.key\n    salt_path: keys/kek.salt\n"), 0o600))
	configPathFlag = cfgPath
	restoreInput = archive
	t.Setenv("KEYORIX_MASTER_PASSWORD", passphrase)
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "restore output:\n%s", out)

	cfg, err := loadConfig()
	require.NoError(t, err)
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	enc := encryption.NewService(&cfg.Storage.Encryption, ".")
	require.NoError(t, enc.Initialize(passphrase))
	defer enc.Shutdown()
	c := core.NewKeyorixCore(st)
	c.SetAuthEncryptor(enc)
	ch, err := c.GetNotificationChannel(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, v0953FixtureChannelURL, ch.URL, "the webhook URL must survive backup then restore")
}
