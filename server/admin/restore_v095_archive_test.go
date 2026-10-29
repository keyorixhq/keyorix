package admin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/restorejournal"
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
	for _, in := range v0953PassphraseInputs {
		t.Run("SQLite/"+in.name, func(t *testing.T) {
			runV0953ArchiveRestore(t, in.set, func(dir string) string {
				return fmt.Sprintf("  type: local\n  database:\n    path: %s\n", filepath.Join(dir, "secrets.db"))
			})
		})
		t.Run("Postgres/"+in.name, func(t *testing.T) {
			base := pgAdminTestDSN(t)
			runV0953ArchiveRestore(t, in.set, func(string) string {
				return fmt.Sprintf("  type: postgres\n  database:\n    dsn: %q\n", pgAdminIsolatedDatabaseDSN(t, base))
			})
		})
	}
}

// v0953PassphraseInputs are the documented ways to hand restore the master
// passphrase. A piped --passphrase-stdin and --passphrase-fd can be read only
// once (EOF, closed fd): REVIEW-3807-DEEP-2 found the URL backfill reading the
// source a second time after the commit, so a restore given either failed
// after it had committed and left the webhook URL in plaintext.
var v0953PassphraseInputs = []struct {
	name string
	set  func(t *testing.T)
}{
	{"env", func(t *testing.T) { t.Setenv("KEYORIX_MASTER_PASSWORD", v0953FixturePassphrase) }},
	{"stdin-pipe", func(t *testing.T) {
		r := v0953PassphrasePipe(t)
		oldStdin := os.Stdin
		os.Stdin = r
		t.Cleanup(func() { os.Stdin = oldStdin; _ = r.Close() })
		setRestorePassphraseSource(t, crypto.PassphraseSource{Stdin: true})
	}},
	{"passphrase-fd", func(t *testing.T) {
		r := v0953PassphrasePipe(t)
		// The reader closes the fd it is given, like a real inherited fd: hand it
		// a duplicate so r's own Close cannot close a reused descriptor number.
		fd, err := syscall.Dup(int(r.Fd()))
		require.NoError(t, err)
		require.NoError(t, r.Close())
		setRestorePassphraseSource(t, crypto.PassphraseSource{FD: fd, FDSet: true})
	}},
}

// v0953PassphrasePipe returns the read end of a pipe that holds the fixture
// passphrase and nothing more (its write end is closed).
func v0953PassphrasePipe(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString(v0953FixturePassphrase + "\n")
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return r
}

func setRestorePassphraseSource(t *testing.T, src crypto.PassphraseSource) {
	t.Helper()
	t.Setenv("KEYORIX_MASTER_PASSWORD", "") // only the one-shot source may supply it
	old := restorePassphraseSource
	restorePassphraseSource = src
	t.Cleanup(func() { restorePassphraseSource = old })
}

func runV0953ArchiveRestore(t *testing.T, setPassphrase func(*testing.T), storageBlock func(dir string) string) {
	setupV0953ArchiveRestore(t, storageBlock)
	setPassphrase(t)

	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "restore output:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID")
	require.NotContains(t, out, "could not derive the audit-checkpoint key",
		"the automatic verify-audit must get the same passphrase the restore was given")
	requireV0953ArchiveRestored(t, out)
}

// TestAdminRestore_V0953Archive_URLEncryptionFailureIsRecoverable: the URL
// encryption runs before the restore journal is removed, so when it fails
// (here: --recover given the wrong passphrase) the journal stays, the server
// stays refused and the next --recover finishes it. Before that ordering the
// journal was already gone: the command failed, a later --recover had nothing
// to do, and the plaintext URL stayed in the database.
func TestAdminRestore_V0953Archive_URLEncryptionFailureIsRecoverable(t *testing.T) {
	setupV0953ArchiveRestore(t, func(dir string) string {
		return fmt.Sprintf("  type: local\n  database:\n    path: %s\n", filepath.Join(dir, "secrets.db"))
	})
	t.Setenv("KEYORIX_MASTER_PASSWORD", v0953FixturePassphrase)
	orig := restoreStepHook
	t.Cleanup(func() { restoreStepHook = orig })
	restoreStepHook = func(step string) error {
		if step == "installed-1" {
			return errors.New("injected failure after the commit")
		}
		return nil
	}
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.Error(t, err, "output:\n%s", out)
	restoreStepHook = orig

	cfg, err := loadConfig()
	require.NoError(t, err)
	restoreRecover = true
	t.Cleanup(func() { restoreRecover = false })
	t.Setenv("KEYORIX_MASTER_PASSWORD", "not-the-v0953-fixture-passphrase")
	out, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.Error(t, err, "output:\n%s", out)
	require.Contains(t, err.Error(), "encrypting the notification channel URLs")
	require.Contains(t, err.Error(), "admin restore --recover")
	require.Error(t, restorejournal.RefuseIfPresent(cfg), "the journal must survive a failed URL encryption")

	t.Setenv("KEYORIX_MASTER_PASSWORD", v0953FixturePassphrase)
	out, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "recover output:\n%s", out)
	require.Contains(t, out, "Rolled forward")
	require.NoError(t, restorejournal.RefuseIfPresent(cfg), "recovery must remove the journal")
	requireV0953ArchiveRestored(t, out)
}

// setupV0953ArchiveRestore points the restore flags at the fixture archive
// and a fresh target directory (the working directory from here on).
func setupV0953ArchiveRestore(t *testing.T, storageBlock func(dir string) string) {
	t.Helper()
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())

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
}

// requireV0953ArchiveRestored checks the restored target: every seeded row
// family, no plaintext in the legacy column, and the URL decrypting to the
// original under the restored keys.
func requireV0953ArchiveRestored(t *testing.T, out string) {
	t.Helper()
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
