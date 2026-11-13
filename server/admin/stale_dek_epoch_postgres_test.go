// stale_dek_epoch_postgres_test.go: the EXECUTED red/green proof that the prior
// backup-round-trip session only REASONED about. A store whose recorded DEK
// epoch (system_metadata[dek.epoch]) does not match the DEK its key files
// provide -- e.g. a backup restored with a stale dek.epoch, or key files copied
// from a different installation -- must be REFUSED at start-up by
// StartDEKEpochGuard with ErrDEKEpochMismatch, never silently started under a
// DEK that cannot decrypt the database's rows.
//
// The DEK-epoch guard is PostgreSQL-only (encryption.dekEpochApplies checks
// db.Name()=="postgres"), so this proof is Postgres-only and skips without
// KEYORIX_TEST_PG_DSN. It is independent of the fuzzer: it drives the real
// encryption.Service guard directly, with a clean control (matching epoch ->
// starts) and one plant (mismatched epoch -> refused).
package admin

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestStaleDEKEpochRefused_Postgres(t *testing.T) {
	base := bkPgBaseDSN(t) // skips when KEYORIX_TEST_PG_DSN is unset
	t.Setenv("KEYORIX_MASTER_PASSWORD", roundTripPassphrase)

	// newStore builds a fresh, migrated, encrypted Postgres store in its own
	// bk_<pid>_<n> database and returns the encryption service + a gorm handle.
	newStore := func(t *testing.T) (*encryption.Service, *gorm.DB) {
		t.Helper()
		dir := t.TempDir()
		chdirTest(t, dir)
		encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
		enc := encryption.NewService(encCfg, dir)
		require.NoError(t, enc.Initialize(roundTripPassphrase))
		configPathFlag = writePostgresBackupRestoreTestConfig(t, dir, bkPgIsolatedDSN(t, base))
		cfg, err := loadConfig()
		require.NoError(t, err)
		if _, err := storage.NewStorageFactory().CreateStorage(cfg); err != nil { // runs migrations
			t.Fatalf("create storage: %v", err)
		}
		gdb, err := storage.OpenGormDB(cfg)
		require.NoError(t, err)
		return enc, gdb
	}

	// GREEN control: no stale epoch -> the guard seeds its own fingerprint and
	// starts. (A fresh database has no dek.epoch row; the guard seeds it.)
	t.Run("clean_matching_epoch_starts", func(t *testing.T) {
		enc, gdb := newStore(t)
		require.NoError(t, enc.StartDEKEpochGuard(gdb, nil),
			"a consistent DEK epoch must let the server start")
		require.True(t, enc.DEKEpochGuardRunning(), "guard should be running after a clean start")
		enc.Shutdown()
	})

	// RED plant: a mismatched dek.epoch (as a stale-backup restore or
	// wrong-key-files copy would leave) -> the guard REFUSES with
	// ErrDEKEpochMismatch and does NOT start.
	t.Run("stale_mismatched_epoch_refused", func(t *testing.T) {
		enc, gdb := newStore(t)
		own, err := enc.DEKFingerprint()
		require.NoError(t, err)
		stale := "stale-" + own // guaranteed distinct from the real fingerprint
		require.NoError(t, gdb.Create(&models.SystemMetadata{
			Key:   encryption.DEKEpochMetadataKey,
			Value: stale,
		}).Error, "plant a stale DEK epoch")

		gErr := enc.StartDEKEpochGuard(gdb, nil)
		require.Error(t, gErr, "a stale DEK epoch must be refused at start-up")
		require.ErrorIs(t, gErr, encryption.ErrDEKEpochMismatch)
		require.False(t, enc.DEKEpochGuardRunning(), "guard must NOT run after a refused start")
	})
}
