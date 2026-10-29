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
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// testdata/v0.95.3-backup.tar.gz is the literal `admin backup` output of the
// v0.95.3 release binary (built from the tag), made by
// scripts/release-qa/scenario_restore_compat.sh with
// KEYORIX_QA_MASTER_PASSWORD=v0953-fixture-passphrase-1234,
// KEYORIX_QA_SECRET_VALUE=v0953-fixture-secret-value and
// KEYORIX_QA_CHANNEL_URL=https://203.0.113.10/v0953-fixture-hook. It holds an
// admin with TOTP enrolled, a second user, one secret shared with that user,
// one webhook notification channel and the audit chain those writes made.
// v0.95.3 predates #2468, so the channel's URL is in the plaintext `url`
// column the current model no longer maps.
const (
	v0953FixturePassphrase = "v0953-fixture-passphrase-1234"
	v0953FixtureChannelURL = "https://203.0.113.10/v0953-fixture-hook"
)

// TestAdminRestore_V0953Archive (#3452): before the fix restore refused this
// archive outright ("table notification_channels ... has column url, which
// this binary's current schema neither has nor lists ..."), so nobody on
// 0.95 could restore a backup into a current release. Now the archive
// restores on both backends with a VALID audit chain, every seeded row
// family arrives, and the webhook URL ends up encrypted under the restored
// keys with no plaintext left in the legacy column.
func TestAdminRestore_V0953Archive(t *testing.T) {
	t.Run("SQLite", func(t *testing.T) {
		runV0953ArchiveRestore(t, func(dir string) string {
			return fmt.Sprintf("  type: local\n  database:\n    path: %s\n", filepath.Join(dir, "secrets.db"))
		})
	})
	t.Run("Postgres", func(t *testing.T) {
		base := pgAdminTestDSN(t)
		runV0953ArchiveRestore(t, func(string) string {
			return fmt.Sprintf("  type: postgres\n  database:\n    dsn: %q\n", pgAdminIsolatedDatabaseDSN(t, base))
		})
	})
}

func runV0953ArchiveRestore(t *testing.T, storageBlock func(dir string) string) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", v0953FixturePassphrase)

	wd, err := os.Getwd()
	require.NoError(t, err)
	fixturePath := filepath.Join(wd, "testdata", "v0.95.3-backup.tar.gz")

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	// admin init's default key paths, which the archive recorded.
	cfgPath := filepath.Join(dstDir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("storage:\n"+storageBlock(dstDir)+
		"  encryption:\n    enabled: true\n    dek_path: keys/dek.key\n    salt_path: keys/kek.salt\n"), 0o600))
	configPathFlag = cfgPath
	restoreInput = fixturePath

	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "restore output:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID")
	require.Contains(t, out, "Encrypted 1 notification channel URL(s)")

	cfg, err := loadConfig()
	require.NoError(t, err)
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	defer closeGormDB(gdb)
	for table, want := range map[string]int64{
		"users": 2, "mfa_secrets": 1, "mfa_recovery_codes": 10, "share_records": 1,
		"secret_nodes": 1, "secret_versions": 1, "notification_channels": 1, "audit_checkpoints": 1,
	} {
		var n int64
		require.NoError(t, gdb.Table(table).Count(&n).Error)
		require.Equal(t, want, n, "rows in %s", table)
	}
	var legacy string
	require.NoError(t, gdb.Raw("SELECT COALESCE(url, '') FROM notification_channels WHERE id = 1").Scan(&legacy).Error)
	require.Empty(t, legacy, "the plaintext URL must not stay in the legacy column")

	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	enc := encryption.NewService(&cfg.Storage.Encryption, ".")
	require.NoError(t, enc.Initialize(v0953FixturePassphrase))
	c := core.NewKeyorixCore(st)
	c.SetAuthEncryptor(enc)
	ch, err := c.GetNotificationChannel(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, v0953FixtureChannelURL, ch.URL)
}
