package admin

// #4104: with storage.encryption.key_dir_lock: database several key directories
// serve one PostgreSQL database, and a DEK rotation changes only the one it runs
// in. Crash point "after the sweep committed, before the rename"
// (docs/multi-replica-keys.md): the rows, the dek.epoch row and the redo marker
// are under the new DEK, the rotating directory holds it only as
// dek.key.pending, and every other directory still holds the old dek.key and no
// .pending file. A backup from such a directory must be refused: the archive
// would restore, but its server start is refused (ErrDEKEpochMismatch) and
// nothing in it decrypts. The state is built with a real rotation
// (RotateDEKWithSweep); only the final rename is undone, as the crash leaves it.
// Gated on KEYORIX_TEST_PG_DSN.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const markerGapPass = "test-passphrase-1234"

var markerGapEncCfg = config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}

// markerGapState is the crash state: dirA rotated (dek.key old, dek.key.pending
// new), dirB is another replica's copy of the old key set.
type markerGapState struct {
	dsn, dirA, dirB string
	aad             []byte
}

func writeKeyDirLockDatabaseConfig(t *testing.T, dir, dsn string) string {
	t.Helper()
	p := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(p, []byte(fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
  encryption:
    enabled: true
    dek_path: dek.key
    salt_path: kek.salt
    key_dir_lock: database
`, dsn)), 0o600))
	return p
}

func copyKeyFiles(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) == ".lock" || e.Name() == "keyorix.yaml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(from, e.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(to, e.Name()), b, 0o600))
	}
}

func buildRotationMarkerGap(t *testing.T) markerGapState {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", markerGapPass)
	st := markerGapState{dsn: pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t)), dirA: t.TempDir(), dirB: t.TempDir()}

	chdirTest(t, st.dirA)
	enc := markerGapEncCfg
	first := encryption.NewService(&enc, st.dirA)
	require.NoError(t, first.Initialize(markerGapPass))
	configPathFlag = writeKeyDirLockDatabaseConfig(t, st.dirA, st.dsn)
	cfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	// The first replica's start seeds the epoch; one secret is written under the old DEK.
	db := pgAdminRawOpen(t, st.dsn)
	require.NoError(t, first.StartDEKEpochGuard(pgAdminRawOpen(t, st.dsn), nil))
	project := models.Project{Name: "marker-gap"}
	require.NoError(t, db.Create(&project).Error)
	node := models.SecretNode{ProjectID: project.ID, Name: "s", IsSecret: true}
	require.NoError(t, db.Create(&node).Error)
	st.aad = encryption.SecretAAD(node.ID, node.ProjectID, 1)
	ct, meta, err := first.EncryptSecretWithAAD([]byte("value"), st.aad)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: ct, EncryptionMetadata: models.JSON(meta)}).Error)
	first.Shutdown()

	// Replica B's key directory: a copy of the same (old) key set.
	copyKeyFiles(t, st.dirA, st.dirB)
	oldDEK, err := os.ReadFile(filepath.Join(st.dirA, "dek.key"))
	require.NoError(t, err)

	// A real DEK rotation in A: the sweep commits the rows, the epoch and the marker.
	rot := encryption.NewService(&enc, st.dirA)
	require.NoError(t, rot.Initialize(markerGapPass))
	_, err = rot.RotateDEKWithSweep(markerGapPass, pgAdminRawOpen(t, st.dsn))
	require.NoError(t, err)
	rot.Shutdown()

	// Undo what happens after the commit: the rename and the marker delete.
	newDEK, err := os.ReadFile(filepath.Join(st.dirA, "dek.key"))
	require.NoError(t, err)
	require.False(t, bytes.Equal(oldDEK, newDEK))
	require.NoError(t, os.WriteFile(filepath.Join(st.dirA, "dek.key.pending"), newDEK, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(st.dirA, "dek.key"), oldDEK, 0o600))
	// The literal, not encryption.DEKRotationPromotePendingMetadataKey, so this
	// test also compiles (and shows the bug) on a tree without the fix.
	require.NoError(t, db.Create(&models.SystemMetadata{Key: "dek_rotation.promote_pending", Value: "v2"}).Error)
	return st
}

func readDirFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) == ".lock" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		out[e.Name()] = b
	}
	return out
}

func runBackupArgs(t *testing.T, args ...string) (code int, stderr string) {
	t.Helper()
	stderr = captureStderr(t, func() {
		_, _ = captureStdout(t, func() error {
			code = Execute(append([]string{"backup", "--config", configPathFlag}, args...))
			return nil
		})
	})
	return code, stderr
}

// markerGapConsequence restores archive on a clean host and reports what #4104
// says happens there: the start is refused and nothing decrypts.
func markerGapConsequence(t *testing.T, st markerGapState, archive string) string {
	t.Helper()
	dst := t.TempDir()
	dstDSN := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))
	chdirTest(t, dst)
	configPathFlag = writePostgresBackupRestoreTestConfig(t, dst, dstDSN)
	restoreInput, restoreOverwriteExisting, restoreMaxEntryBytes, restoreMaxTotalBytes = archive, false, 0, 0
	out, rerr := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	if rerr != nil {
		return fmt.Sprintf("restore failed: %v\n%s", rerr, out)
	}
	enc := markerGapEncCfg
	svc := encryption.NewService(&enc, dst)
	require.NoError(t, svc.Initialize(markerGapPass))
	defer svc.Shutdown()
	startErr := svc.StartDEKEpochGuard(pgAdminRawOpen(t, dstDSN), nil)
	var v models.SecretVersion
	require.NoError(t, pgAdminRawOpen(t, dstDSN).First(&v).Error)
	_, decErr := svc.DecryptSecretWithAAD(v.EncryptedValue, st.aad)
	return fmt.Sprintf("restored; clean-host start: %v (ErrDEKEpochMismatch=%v); decrypts=%v",
		startErr, errors.Is(startErr, encryption.ErrDEKEpochMismatch), decErr == nil)
}

func TestAdminBackup_Postgres_RefusedFromAKeyDirectoryBehindACommittedRotation(t *testing.T) {
	cases := []struct {
		name string
		args []string
		// holdKeyLock makes this directory look like a live server's (#2602's
		// live key path, liveKeyMaterial).
		holdKeyLock bool
	}{
		{"live snapshot", nil, false},
		{"exclusive", []string{"--exclusive"}, false},
		{"live server holds the key lock", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetBackupRestoreFlags(t)
			st := buildRotationMarkerGap(t)
			beforeA := readDirFiles(t, st.dirA)

			chdirTest(t, st.dirB)
			configPathFlag = writeKeyDirLockDatabaseConfig(t, st.dirB, st.dsn)
			beforeB := readDirFiles(t, st.dirB)
			if c.holdKeyLock {
				enc := markerGapEncCfg
				live := encryption.NewService(&enc, st.dirB)
				require.NoError(t, live.AcquireExclusiveKeyLock())
				defer live.Shutdown()
			}
			outDir := t.TempDir()
			archive := filepath.Join(outDir, "backup.tar.gz")
			code, stderr := runBackupArgs(t, append([]string{"--output", archive, fmt.Sprintf("--exclusive=%v", c.args != nil)}, c.args...)...)
			if code == 0 {
				t.Fatalf("#4104: backup from a key directory behind the database's DEK succeeded; %s", markerGapConsequence(t, st, archive))
			}
			require.Contains(t, stderr, "a DEK rotation committed its re-encryption sweep")
			require.Contains(t, stderr, "Finish the rotation in the key directory that holds dek.key.pending")
			require.Contains(t, stderr, "distribute the new key set")
			require.Contains(t, stderr, "no archive was written and no key file was changed")
			entries, err := os.ReadDir(outDir)
			require.NoError(t, err)
			require.Empty(t, entries, "a refused backup must leave nothing in the output directory")
			require.Equal(t, beforeB, readDirFiles(t, st.dirB), "a refused backup must not change this key directory")
			require.Equal(t, beforeA, readDirFiles(t, st.dirA), "the rotating directory's dek.key.pending must stay untouched")
		})
	}
}

// The rotating directory itself still gets the local refusal (#4058), not the
// database one: its dek.key.pending is found first.
func TestAdminBackup_Postgres_RotatingKeyDirectoryKeepsThePendingFileRefusal(t *testing.T) {
	resetBackupRestoreFlags(t)
	st := buildRotationMarkerGap(t)
	chdirTest(t, st.dirA)
	configPathFlag = writeKeyDirLockDatabaseConfig(t, st.dirA, st.dsn)
	pending, err := os.ReadFile(filepath.Join(st.dirA, "dek.key.pending"))
	require.NoError(t, err)
	stderr := requireRefusedAndUntouched(t, map[string][]byte{"dek.key.pending": pending})
	require.NotContains(t, stderr, "a DEK rotation committed its re-encryption sweep")
}

// Control: once the rotation is finished in A and the new key set is copied to
// B (the remedy the refusal names), B's backup works.
func TestAdminBackup_Postgres_BackupWorksAfterTheRotationIsFinishedAndDistributed(t *testing.T) {
	resetBackupRestoreFlags(t)
	st := buildRotationMarkerGap(t)
	chdirTest(t, st.dirA)
	configPathFlag = writeKeyDirLockDatabaseConfig(t, st.dirA, st.dsn)
	enc := markerGapEncCfg
	boot := encryption.NewService(&enc, st.dirA)
	require.NoError(t, boot.AcquireExclusiveKeyLock())
	require.NoError(t, boot.RecoverInterruptedRotation(pgAdminRawOpen(t, st.dsn)))
	boot.Shutdown()
	require.NoFileExists(t, filepath.Join(st.dirA, "dek.key.pending"))
	copyKeyFiles(t, st.dirA, st.dirB)

	chdirTest(t, st.dirB)
	configPathFlag = writeKeyDirLockDatabaseConfig(t, st.dirB, st.dsn)
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	code, stderr := runBackupArgs(t, "--output", archive, "--exclusive=false")
	require.Zero(t, code, "stderr:\n%s", stderr)
	require.Contains(t, markerGapConsequence(t, st, archive), "decrypts=true")
}
