// backup_rotation_marker_gap_postgres_test.go (C2, H1): reproduction of the
// multi-replica backup gap. With storage.encryption.key_dir_lock: database and a
// workspace-based DEK rotation (docs/multi-replica-keys.md), a rotation killed
// AFTER the sweep commit but BEFORE the pending->active rename leaves the
// database rows, the dek.epoch row and the redo marker (system_metadata
// dek_rotation.promote_pending) under the NEW DEK, while the new DEK lives only
// as dek.key.pending in the rotating directory. A DIFFERENT replica's key
// directory still holds the OLD dek.key and no .pending file.
//
// The contract under test (C2): after any interruption `admin backup` either
// (a) yields an archive that restores on a CLEAN host and whose secrets decrypt,
// or (b) refuses with NO archive written and NO key file changed.
//
// refusePendingKeyRotation (server/admin/backup.go) is the only pre-backup
// rotation gate, and it stats local <dek_path>.pending / <salt_path>.pending
// only (internal/keyfiles/pending_rotation.go). It never reads the redo marker
// row, and `admin backup` performs no DEK-epoch check. So a backup taken from
// the non-rotating replica in state B is NOT refused (branch b fails), and the
// archive it writes bundles the OLD dek.key with NEW-DEK ciphertext: on a clean
// host it does not decrypt and a server start is refused by the DEK epoch
// (branch a fails). The backup looks fine and cannot be restored.
//
// This test characterizes finding H1 against live PostgreSQL. It asserts the
// VIOLATING reality (the gap is present in production code). When the proposed
// fix lands (refuse the backup while the DB redo marker is present and this key
// directory does not hold the matching pending DEK), the backup must refuse,
// `sawRefusal` becomes true, and the H1-specific expectations below must be
// updated to assert refusal (branch b) -- never weaken the contract.
//
// Also contains #4104 regression tests: backup refused from a key directory
// that is behind a committed rotation (marker-gap state). Gated on
// KEYORIX_TEST_PG_DSN.
package admin

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

// ---- #4104 marker-gap tests -------------------------------------------------------

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

// ---- C2 / H1 reproduction test ----------------------------------------------------

// These are the exact string keys the production code uses in system_metadata.
// Unexported there (internal/encryption/service_rotation.go
// dekRotationPromotePendingKey, internal/encryption/dek_epoch.go dekEpochKey);
// copied here as literals because this is a cross-package (admin) test.
const (
	h1RedoMarkerKey = "dek_rotation.promote_pending"
	h1DEKEpochKey   = "dek.epoch"
)

func h1WriteKeyDirConfig(t *testing.T, dir, dsn string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	content := "storage:\n" +
		"  type: postgres\n" +
		"  database:\n" +
		"    dsn: " + "\"" + dsn + "\"" + "\n" +
		"  encryption:\n" +
		"    enabled: true\n" +
		"    dek_path: dek.key\n" +
		"    salt_path: kek.salt\n" +
		"    key_dir_lock: database\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))
	return cfgPath
}

func h1CopyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, b, 0o600))
}

// TestAdminBackup_Postgres_StateB_OtherKeyDir_UndecryptableArchive reproduces H1.
func TestAdminBackup_Postgres_StateB_OtherKeyDir_UndecryptableArchive(t *testing.T) {
	const pass = "h1-master-passphrase-0001"
	const plaintext = "h1-secret-plaintext-value"

	base := pgAdminTestDSN(t) // skips if KEYORIX_TEST_PG_DSN unset
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", pass)

	// Replay 3x on independent databases, as required for a finding.
	for attempt := 1; attempt <= 3; attempt++ {
		t.Run("replay", func(t *testing.T) {
			resetBackupRestoreFlags(t)
			srcDSN := pgAdminIsolatedDatabaseDSN(t, base)

			// dirA = the rotating workspace. Initialize encryption + migrate the DB.
			dirA := t.TempDir()
			chdirTest(t, dirA)
			encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt", KeyDirLock: config.KeyDirLockDatabase}
			svcA := encryption.NewService(encCfg, dirA)
			require.NoError(t, svcA.Initialize(pass))

			configPathFlag = h1WriteKeyDirConfig(t, dirA, srcDSN)
			srcCfg, err := loadConfig()
			require.NoError(t, err)
			_, err = storage.NewStorageFactory().CreateStorage(srcCfg) // migrate
			require.NoError(t, err)

			// dirB = a DIFFERENT replica's key directory, holding the OLD key set
			// (snapshot taken BEFORE the rotation) and no .pending file.
			dirB := t.TempDir()
			h1CopyFile(t, filepath.Join(dirA, "dek.key"), filepath.Join(dirB, "dek.key"))
			h1CopyFile(t, filepath.Join(dirA, "kek.salt"), filepath.Join(dirB, "kek.salt"))
			oldWrappedDEK, err := os.ReadFile(filepath.Join(dirA, "dek.key"))
			require.NoError(t, err)

			// Seed one secret version under the OLD DEK. A Project must exist so
			// the secret node's project_id reference is intact (restore enforces
			// referential integrity).
			db := pgAdminRawOpen(t, srcDSN)
			project := &models.Project{Name: "h1-proj"}
			require.NoError(t, db.Create(project).Error)
			node := &models.SecretNode{ProjectID: project.ID, Name: "h1-node", IsSecret: true}
			require.NoError(t, db.Create(node).Error)
			enc, meta, err := svcA.EncryptSecretWithAAD([]byte(plaintext), encryption.SecretAAD(node.ID, node.ProjectID, 1))
			require.NoError(t, err)
			require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}).Error)

			// Rotate in dirA: rows + epoch now under the NEW DEK; dirA's dek.key
			// becomes the new wrapped DEK; the marker is cleared on success.
			_, err = svcA.RotateDEKWithSweep(pass, db)
			require.NoError(t, err, "rotate-dek sweep")
			svcA.Shutdown()

			// Rewind dirA + the DB to state B (crash after commit, before rename):
			// re-insert the redo marker (RotateDEKWithSweep cleared it on full
			// success). The DB rows/epoch are already under the new DEK. dirB is
			// untouched (old key set, no pending) -- it is the backup source.
			var epoch models.SystemMetadata
			require.NoError(t, db.Where("key = ?", h1DEKEpochKey).First(&epoch).Error)
			require.NoError(t, db.Create(&models.SystemMetadata{Key: h1RedoMarkerKey, Value: epoch.Value}).Error)
			// (dirA is no longer used; dirB models the non-rotating replica.)
			_ = oldWrappedDEK

			// === admin backup from the non-rotating replica dirB ===
			chdirTest(t, dirB)
			configPathFlag = h1WriteKeyDirConfig(t, dirB, srcDSN)
			archivePath := filepath.Join(t.TempDir(), "h1-backup.tar.gz")
			backupOutput = archivePath
			backupExclusive = false

			out, backupErr := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
			sawRefusal := backupErr != nil

			if sawRefusal {
				// Contract branch (b): the backup must have written NO archive.
				_, statErr := os.Stat(archivePath)
				require.True(t, os.IsNotExist(statErr), "refused backup must leave no archive")
				t.Logf("attempt %d: backup REFUSED (contract branch b satisfied): %v", attempt, backupErr)
				t.Fatalf("H1 appears FIXED: backup refused in state B from the non-rotating replica. "+
					"Update this test to assert branch (b) permanently. backupErr=%v", backupErr)
			}

			// Branch (b) failed: the backup succeeded and wrote an archive.
			require.NoError(t, backupErr, "unexpected backup error (not the H1 gap):\n%s", out)
			fi, statErr := os.Stat(archivePath)
			require.NoError(t, statErr, "backup reported success but wrote no archive")
			require.Greater(t, fi.Size(), int64(0))
			t.Logf("attempt %d: H1 gap present -- backup SUCCEEDED from the state-B non-rotating replica (no refusal)", attempt)

			// === restore onto a CLEAN host and try to read the secret ===
			dstDSN := pgAdminIsolatedDatabaseDSN(t, base)
			dstDir := t.TempDir()
			chdirTest(t, dstDir)
			configPathFlag = h1WriteKeyDirConfig(t, dstDir, dstDSN)
			restoreInput = archivePath
			restoreOverwriteExisting = false
			restoreAllowRollback = true
			restoreMaxEntryBytes = 0
			restoreMaxTotalBytes = 0

			rOut, restoreErr := captureStdout(t, func() error { return runAdminRestore(nil, nil) })

			// The clean host now holds the archive's key files (OLD dek.key) and
			// the NEW-DEK rows + epoch + redo marker. Branch (a) requires the
			// secret to decrypt here. Model "start the server once": run crash
			// recovery, Initialize, the DEK epoch guard, then read the secret.
			dstSvc := encryption.NewService(
				&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt", KeyDirLock: config.KeyDirLockDatabase},
				dstDir,
			)
			dstDB := pgAdminRawOpen(t, dstDSN)
			recErr := dstSvc.RecoverInterruptedRotation(dstDB)
			initErr := dstSvc.Initialize(pass)
			var guardErr error
			if initErr == nil {
				guardErr = dstSvc.StartDEKEpochGuard(dstDB, nil)
				t.Cleanup(dstSvc.Shutdown)
			}

			decrypts := false
			if initErr == nil {
				var row models.SecretVersion
				if err := dstDB.Where("secret_node_id = ?", node.ID).Order("id").First(&row).Error; err == nil {
					if got, derr := dstSvc.DecryptSecretWithAAD(row.EncryptedValue, encryption.SecretAAD(node.ID, node.ProjectID, row.VersionNumber)); derr == nil {
						decrypts = string(got) == plaintext
					}
				}
			}

			t.Logf("attempt %d clean-host: restoreErr=%v recoverErr=%v initErr=%v guardErr=%v decrypts=%v\nrestore output:\n%s",
				attempt, restoreErr, recErr, initErr, guardErr, decrypts, rOut)

			// Contract: with the backup NOT refused (branch b false), branch (a)
			// must hold -- the restored secret must decrypt on the clean host.
			// H1 is the demonstration that it does NOT: neither branch holds.
			require.False(t, decrypts,
				"H1 appears FIXED or not reproduced: the state-B archive restored and the secret DECRYPTED on a clean host. "+
					"If the production fix landed, update this test; otherwise investigate.")
			// And the clean-host "start once" must be refused by the DEK epoch
			// (old key set vs new epoch) -- the server cannot come up either.
			require.Error(t, guardErr,
				"expected the clean-host start to be refused by the DEK epoch (old dek.key vs new dek.epoch)")
			require.ErrorIs(t, guardErr, encryption.ErrDEKEpochMismatch)
		})
	}
}
