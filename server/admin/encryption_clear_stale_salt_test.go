package admin

// #4105: a kek.salt.pending that a successful boot proved unused refuses every
// backup. The refusal is now an audit event as well, and `admin encryption
// clear-stale-salt-pending` removes the file once it has proved, itself, that
// the file is unused. It never touches a DEK's staging file: every test here
// checks dek.key.pending (when planted) is byte-identical afterwards.

import (
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditEventsNamed reads the source database's events of type eventType.
func auditEventsNamed(t *testing.T, eventType string) []models.AuditEvent {
	t.Helper()
	cfg, err := loadConfig()
	require.NoError(t, err)
	db, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	defer closeGormDB(db)
	var evs []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", eventType).Order("id").Find(&evs).Error)
	return evs
}

// keyFilesSnapshot reads the active key files and every planted staging file.
func keyFilesSnapshot(t *testing.T, planted map[string][]byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, name := range []string{"dek.key", "kek.salt"} {
		data, err := os.ReadFile(name)
		require.NoError(t, err)
		out[name] = data
	}
	maps.Copy(out, planted)
	return out
}

// runClearStaleSalt runs the command through Execute, as the binary does.
func runClearStaleSalt(t *testing.T, extra ...string) (code int, stdout, stderr string) {
	t.Helper()
	old := encClearStaleSaltDryRun
	encClearStaleSaltDryRun = false // cobra keeps a flag's value between Execute calls
	t.Cleanup(func() { encClearStaleSaltDryRun = old })
	args := append([]string{"encryption", clearStaleSaltCmdName, "--config", configPathFlag}, extra...)
	stderr = captureStderr(t, func() {
		stdout, _ = captureStdout(t, func() error {
			code = Execute(args)
			return nil
		})
	})
	return code, stdout, stderr
}

// staleSaltAfterBoot is the issue's state: a leftover kek.salt.pending that a
// successful boot left in place.
func staleSaltAfterBoot(t *testing.T) map[string][]byte {
	t.Helper()
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	planted := plantStagingFiles(t, testSaltPending)
	recoverLikeBoot(t)
	require.FileExists(t, testSaltPending, "boot leaves an unused staging salt in place (unchanged)")
	return planted
}

// (1) The refusal is recorded in the audit chain, every time, and the posture
// signal says backups are refused, naming the file.
func TestAdminBackup_StaleSaltPending_RefusalIsAuditedAndInPosture(t *testing.T) {
	planted := staleSaltAfterBoot(t)
	require.Empty(t, auditEventsNamed(t, backupRefusedEventType), "control: no refusal yet")

	for i := 1; i <= 2; i++ {
		stderr := requireRefusedAndUntouched(t, planted)
		require.Contains(t, stderr, "This refusal was recorded to the audit chain ("+backupRefusedEventType+")")
		evs := auditEventsNamed(t, backupRefusedEventType)
		require.Len(t, evs, i, "one event per refused backup")
		ev := evs[i-1]
		require.NotNil(t, ev.Success)
		require.False(t, *ev.Success)
		require.Equal(t, adminActorType, ev.ActorType)
		require.Contains(t, ev.Description, "backup refused: key rotation staging file present ("+testSaltPending+")")
		require.Contains(t, ev.Description, "admin encryption "+clearStaleSaltCmdName)
	}
	require.Empty(t, auditEventsNamed(t, "admin.backup_created"), "a refused backup is not a backup")

	out := postureOutput(t)
	require.Contains(t, out, "backups are refused: key-rotation staging file present ("+testSaltPending+")", "posture output:\n%s", out)
	require.Contains(t, out, "admin encryption "+clearStaleSaltCmdName)
}

// The audit write never weakens the refusal: where it cannot be made without
// changing something (a server holds the SQLite database, or opening storage
// would migrate the schema), the backup is refused exactly as before, the
// event is skipped with a note, and the database is left as it was.
func TestAdminBackup_StaleSaltPending_RefusedEvenWhenTheAuditWriteIsSkipped(t *testing.T) {
	t.Run("a server holds the database", func(t *testing.T) {
		planted := staleSaltAfterBoot(t)
		cfg, err := loadConfig()
		require.NoError(t, err)
		p, err := serverguard.AcquirePresence(cfg)
		require.NoError(t, err)
		defer p.Release() //nolint:errcheck

		code, stderr := runBackupCommand(t, filepath.Join(t.TempDir(), "b.tar.gz"))
		require.Equal(t, backupRefusedExitCode, code, "stderr:\n%s", stderr)
		require.Contains(t, stderr, "note: this refusal was not recorded to the audit chain")
		require.Contains(t, stderr, "The backup is refused either way")
		require.NoError(t, p.Release())
		require.Empty(t, auditEventsNamed(t, backupRefusedEventType))
		requireFilesUnchanged(t, keyFilesSnapshot(t, planted), "refused backup")
	})
	t.Run("the database is at another schema epoch", func(t *testing.T) {
		planted := staleSaltAfterBoot(t)
		cfg, err := loadConfig()
		require.NoError(t, err)
		db, err := storage.OpenGormDB(cfg)
		require.NoError(t, err)
		older := strconv.Itoa(storage.CurrentSchemaEpoch() - 1)
		require.NoError(t, db.Model(&models.SystemMetadata{}).Where("key = ?", "schema_epoch").Update("value", older).Error)
		closeGormDB(db)

		code, stderr := runBackupCommand(t, filepath.Join(t.TempDir(), "b.tar.gz"))
		require.Equal(t, backupRefusedExitCode, code, "stderr:\n%s", stderr)
		require.Contains(t, stderr, "opening storage would migrate it before any backup of it exists")

		db, err = storage.OpenGormDB(cfg)
		require.NoError(t, err)
		defer closeGormDB(db)
		var m models.SystemMetadata
		require.NoError(t, db.Where("key = ?", "schema_epoch").Take(&m).Error)
		require.Equal(t, older, m.Value, "a refused backup must not migrate the database")
		var n int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", backupRefusedEventType).Count(&n).Error)
		require.Zero(t, n)
		requireFilesUnchanged(t, keyFilesSnapshot(t, planted), "refused backup")
	})
}

// (2) --dry-run decides and changes nothing; the command removes the file,
// records it, has nothing to do the second time; the next backup succeeds.
func TestClearStaleSaltPending_RemovesItAndTheNextBackupSucceeds(t *testing.T) {
	staleSaltAfterBoot(t)
	active := keyFilesSnapshot(t, nil)

	code, out, stderr := runClearStaleSalt(t, "--dry-run")
	require.Zero(t, code, "stdout:\n%s\nstderr:\n%s", out, stderr)
	require.Contains(t, out, "dry run: would remove "+testSaltPending)
	require.FileExists(t, testSaltPending, "--dry-run removes nothing")
	require.Empty(t, auditEventsNamed(t, clearStaleSaltEventType), "--dry-run writes no audit event")

	code, out, stderr = runClearStaleSalt(t)
	require.Zero(t, code, "stdout:\n%s\nstderr:\n%s", out, stderr)
	require.Contains(t, out, "removed "+testSaltPending)
	require.NoFileExists(t, testSaltPending)
	evs := auditEventsNamed(t, clearStaleSaltEventType)
	require.Len(t, evs, 1)
	require.NotNil(t, evs[0].Success)
	require.True(t, *evs[0].Success)
	require.Contains(t, evs[0].Description, "removed "+testSaltPending)

	code, out, stderr = runClearStaleSalt(t)
	require.Zero(t, code, "stdout:\n%s\nstderr:\n%s", out, stderr)
	require.Contains(t, out, "nothing to do")
	require.Len(t, auditEventsNamed(t, clearStaleSaltEventType), 1, "nothing done, nothing recorded")

	requireFilesUnchanged(t, active, "clear-stale-salt-pending")
	require.NotContains(t, postureOutput(t), backupRefusedPostureLine)
	code, stderr = runBackupCommand(t, filepath.Join(t.TempDir(), "after.tar.gz"))
	require.Zero(t, code, "stderr:\n%s", stderr)
}

// (3)+(4) Every case the command must refuse: it names why, exits non-zero,
// removes nothing, writes no audit event, and leaves dek.key.pending (when
// present) byte-identical. --dry-run refuses the same way.
func TestClearStaleSaltPending_Refusals(t *testing.T) {
	cases := []struct {
		name string
		// setup runs in a fresh encrypted SQLite source and returns what it
		// planted; hold, when set, keeps a lock for the command's run.
		setup func(t *testing.T) map[string][]byte
		want  string
	}{
		{"a DEK staging file is present", func(t *testing.T) map[string][]byte {
			return plantStagingFiles(t, testSaltPending, testDEKPending)
		}, testDEKPending + " is present"},
		{"a DEK staging file alone", func(t *testing.T) map[string][]byte {
			return plantStagingFiles(t, testDEKPending)
		}, testDEKPending + " is present"},
		{"a rotate-kek holds the key lock", func(t *testing.T) map[string][]byte {
			planted := plantStagingFiles(t, testSaltPending)
			recoverLikeBoot(t)
			cfg, err := loadConfig()
			require.NoError(t, err)
			// The lock rotate-kek takes first and holds for its whole run
			// (encryptionops.openKeyWriter).
			rotation := encryption.NewService(&cfg.Storage.Encryption, ".")
			require.NoError(t, rotation.AcquireExclusiveKeyLock())
			t.Cleanup(rotation.Shutdown)
			return planted
		}, "rotate-kek"},
		{"a server or another admin command holds the database", func(t *testing.T) map[string][]byte {
			planted := plantStagingFiles(t, testSaltPending)
			recoverLikeBoot(t)
			cfg, err := loadConfig()
			require.NoError(t, err)
			p, err := serverguard.AcquirePresence(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = p.Release() })
			return planted
		}, "appears to be using this database"},
		{"the active set does not open with the current passphrase", func(t *testing.T) map[string][]byte {
			planted := plantStagingFiles(t, testSaltPending)
			recoverLikeBoot(t)
			t.Setenv("KEYORIX_MASTER_PASSWORD", "not-the-passphrase-of-this-set")
			return planted
		}, "the active key set does not open with the current passphrase without " + testSaltPending},
		{"rotate-kek hazard window: the staged salt is the one the DEK needs", func(t *testing.T) map[string][]byte {
			require.NoError(t, os.Rename("kek.salt", testSaltPending))
			pending, err := os.ReadFile(testSaltPending)
			require.NoError(t, err)
			plantStagingFiles(t, "kek.salt")
			return map[string][]byte{testSaltPending: pending}
		}, "refused, nothing was removed"},
	}
	for _, c := range cases {
		for _, dry := range []bool{true, false} {
			name := c.name
			if dry {
				name += " (--dry-run)"
			}
			t.Run(name, func(t *testing.T) {
				resetBackupRestoreFlags(t)
				sqliteBackupSource(t)
				planted := c.setup(t)
				before := keyFilesSnapshot(t, planted)

				var extra []string
				if dry {
					extra = append(extra, "--dry-run")
				}
				code, out, stderr := runClearStaleSalt(t, extra...)
				require.NotZero(t, code, "stdout:\n%s\nstderr:\n%s", out, stderr)
				require.Contains(t, stderr, clearStaleSaltCmdName+" refused, nothing was removed")
				require.Contains(t, stderr, c.want)
				require.NotContains(t, out, "removed ")
				requireFilesUnchanged(t, before, "refused "+clearStaleSaltCmdName)
				require.Empty(t, auditEventsNamed(t, clearStaleSaltEventType))
			})
		}
	}
}

// The command's only removal is the salt staging path: the structural half of
// INV-ADMIN-clear-stale-salt-pending-never-touches-dek-pending. A second
// os.Remove (or any rename) in the file would be a new way to lose a file and
// must come with its own proof.
func TestClearStaleSaltPending_OnlyRemovalIsTheSaltStagingFile(t *testing.T) {
	require.Equal(t, clearStaleSaltCmdName, encClearStaleSaltCmd.Use, "the literal Use (for cmd/statemapgen) and the name the refusals print must agree")
	src, err := os.ReadFile("encryption_clear_stale_salt.go")
	require.NoError(t, err)
	s := string(src)
	require.Equal(t, 1, strings.Count(s, "os.Remove("), "exactly one removal, in removeStaleSaltPending")
	for _, banned := range []string{"os.RemoveAll(", "os.Rename(", "os.WriteFile(", "os.Create(", "os.OpenFile(", "CleanPendingDEK", "RecoverInterruptedRotation", "ReconcileKeySet("} {
		require.NotContains(t, s, banned, "%s would let this command change a key file other than the salt staging file", banned)
	}
}
