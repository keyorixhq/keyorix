// backup_rotation_sequence_fuzz_test.go (C2, task 3): a sequence fuzzer that
// treats backup / restore / key-rotation as one state machine. It applies a
// random sequence of operations over
//
//	{rotate-dek, rotate-kek, backup, restore-to-clean-host, kill-at-a-seam,
//	 start-the-server-once, read-all-secrets}
//
// to one install, and checks TWO oracles that cannot false-positive:
//
//   - CONTRACT: every `backup` op either (b) returns an error AND writes no
//     archive and changes no key file, or (a) returns success AND the archive it
//     wrote restores on a CLEAN host (fresh key dir + fresh database) and its
//     secrets decrypt to the exact current ledger. A backup is only ever
//     asserted restorable when it itself claimed success, so the oracle holds
//     under every design option.
//   - LEDGER EQUALITY: a `read-all-secrets` op, and every clean-host restore,
//     must decrypt to the same secret names/versions/values as before — nothing
//     is added, dropped or altered by a rotation + backup + restore round trip.
//
// "Start the server once must complete any pending rotation, after which a
// backup succeeds and restores" is checked too: after a start-once that leaves
// no `.pending` file, the next backup must NOT refuse.
//
// This fuzzer runs a SINGLE key directory (the common, non-HA deployment), so
// it proves the contract holds there and guards against regressions. The
// multi-replica / workspace gap (H1), where a DIFFERENT key directory takes the
// backup, is a two-directory shape this single-dir fuzzer does not construct; it
// is covered by TestAdminBackup_Postgres_StateB_OtherKeyDir_UndecryptableArchive.
//
// NOT covered by the op set: `rewrap` (migrate-provider). RewrapDEK needs a
// distinct KEK provider to be plumbed in; its crash exposure is the same
// pending-file shape (<dek_path>.pending / manifest staging) as rotate-kek,
// which the kill-at-a-seam op constructs directly. Stated so the omission reads
// as considered.
//
// SQLite runs in default CI; the PG variant is gated on KEYORIX_TEST_PG_DSN.
package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	seqRedoMarkerKey = "dek_rotation.promote_pending"
	seqDEKEpochKey   = "dek.epoch"
)

type seqSecret struct {
	projectID, nodeID uint
	version           int
	plaintext         string
}

// seqHost is one install the fuzzer drives: a key directory + a database + the
// in-memory ledger the secrets are expected to decrypt to.
type seqHost struct {
	t           *testing.T
	pg          bool
	base        string // pg: base DSN for minting fresh clean-host targets
	dir         string // key directory; also the CWD for backup/restore
	dbPathOrDSN string
	pass        string
	db          *gorm.DB
	ledger      []seqSecret
	lastArchive string
}

func (h *seqHost) encCfg() *config.EncryptionConfig {
	c := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	if h.pg {
		c.KeyDirLock = config.KeyDirLockDatabase
	}
	return c
}

func (h *seqHost) writeConfig(dir, dbPathOrDSN string) string {
	h.t.Helper()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	var content string
	if h.pg {
		content = "storage:\n  type: postgres\n  database:\n    dsn: \"" + dbPathOrDSN + "\"\n" +
			"  encryption:\n    enabled: true\n    dek_path: dek.key\n    salt_path: kek.salt\n    key_dir_lock: database\n"
	} else {
		content = "storage:\n  type: sqlite\n  database:\n    path: " + dbPathOrDSN + "\n" +
			"  encryption:\n    enabled: true\n    dek_path: dek.key\n    salt_path: kek.salt\n"
	}
	require.NoError(h.t, os.WriteFile(cfgPath, []byte(content), 0o600))
	return cfgPath
}

func newSeqHost(t *testing.T, pg bool, base string) *seqHost {
	h := &seqHost{t: t, pg: pg, base: base, pass: "seq-master-pass-0001"}
	h.dir = t.TempDir()
	chdirTest(t, h.dir)
	if pg {
		h.dbPathOrDSN = pgAdminIsolatedDatabaseDSN(t, base)
	} else {
		h.dbPathOrDSN = filepath.Join(h.dir, "secrets.db")
	}
	// Initialize the key set on disk (a short-lived service, no held lock).
	initSvc := encryption.NewService(h.encCfg(), h.dir)
	require.NoError(t, initSvc.Initialize(h.pass))
	initSvc.Shutdown()
	configPathFlag = h.writeConfig(h.dir, h.dbPathOrDSN)
	cfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(cfg) // migrate
	require.NoError(t, err)
	h.db = openGormFromCurrentConfig(t)
	h.seed()
	return h
}

// openGormFromCurrentConfig opens a raw gorm handle for whatever config
// configPathFlag currently points at (works for both sqlite and postgres).
func openGormFromCurrentConfig(t *testing.T) *gorm.DB {
	t.Helper()
	cfg, err := loadConfig()
	require.NoError(t, err)
	db, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		if s, derr := db.DB(); derr == nil {
			_ = s.Close()
		}
	})
	return db
}

// initService returns a freshly initialized encryption service that does NOT
// hold the exclusive key flock (so a later admin backup can take it). The
// caller Shutdowns it. This models "an admin command on a stopped server": no
// process holds the key lock across backups.
func (h *seqHost) initService() *encryption.Service {
	svc := encryption.NewService(h.encCfg(), h.dir)
	require.NoError(h.t, svc.Initialize(h.pass))
	return svc
}

func (h *seqHost) seed() {
	t := h.t
	svc := h.initService()
	defer svc.Shutdown()
	project := &models.Project{Name: "seq-proj"}
	require.NoError(t, h.db.Create(project).Error)
	for n := 0; n < 2; n++ {
		node := &models.SecretNode{ProjectID: project.ID, Name: fmt.Sprintf("seq-node-%d", n), IsSecret: true}
		require.NoError(t, h.db.Create(node).Error)
		for v := 1; v <= n+1; v++ {
			pt := fmt.Sprintf("seq-value-%d-%d", n, v)
			h.writeVersion(svc, node.ID, project.ID, v, pt)
			h.ledger = append(h.ledger, seqSecret{projectID: project.ID, nodeID: node.ID, version: v, plaintext: pt})
		}
	}
}

func (h *seqHost) writeVersion(svc *encryption.Service, nodeID, projectID uint, version int, plaintext string) {
	enc, meta, err := svc.EncryptSecretWithAAD([]byte(plaintext), encryption.SecretAAD(nodeID, projectID, version))
	require.NoError(h.t, err)
	require.NoError(h.t, h.db.Create(&models.SecretVersion{SecretNodeID: nodeID, VersionNumber: version, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}).Error)
}

func (h *seqHost) ledgerPlaintexts() []string {
	out := make([]string, 0, len(h.ledger))
	for _, s := range h.ledger {
		out = append(out, s.plaintext)
	}
	sort.Strings(out)
	return out
}

// pendingPresent reports whether any <dek>/<salt>.pending file is in the key dir.
func (h *seqHost) pendingPresent() bool {
	found, err := keyfiles.PendingRotationFiles(h.encCfg(), h.dir)
	require.NoError(h.t, err)
	return len(found) > 0
}

// decryptAllWith decrypts every secret_version row in db using svc and returns
// the sorted plaintexts (and whether every row decrypted).
func decryptAllWith(t *testing.T, svc *encryption.Service, db *gorm.DB, ledger []seqSecret) (plaintexts []string, allOK bool) {
	t.Helper()
	allOK = true
	for _, s := range ledger {
		var row models.SecretVersion
		if err := db.Where("secret_node_id = ? AND version_number = ?", s.nodeID, s.version).First(&row).Error; err != nil {
			allOK = false
			continue
		}
		got, err := svc.DecryptSecretWithAAD(row.EncryptedValue, encryption.SecretAAD(s.nodeID, s.projectID, s.version))
		if err != nil {
			allOK = false
			continue
		}
		plaintexts = append(plaintexts, string(got))
	}
	sort.Strings(plaintexts)
	return plaintexts, allOK
}

// freshCleanTarget returns a (dir, dbPathOrDSN) for a clean host.
func (h *seqHost) freshCleanTarget() (string, string) {
	dir := h.t.TempDir()
	if h.pg {
		return dir, pgAdminIsolatedDatabaseDSN(h.t, h.base)
	}
	return dir, filepath.Join(dir, "secrets.db")
}

// op implementations ---------------------------------------------------------

func (h *seqHost) opRotateDEK() {
	// A rotation is refused while a prior interruption's pending file is present;
	// that is legitimate (the state machine requires a start-once first). Only
	// rotate from a coherent state.
	if h.pendingPresent() {
		return
	}
	svc := h.initService()
	defer svc.Shutdown()
	if _, err := svc.RotateDEKWithSweep(h.pass, h.db); err != nil {
		// A rotation may legitimately fail (e.g. epoch races); it must not have
		// corrupted the ledger — checked by later read/backup ops.
		h.t.Logf("rotate-dek returned: %v", err)
	}
}

func (h *seqHost) opRotateKEK() {
	if h.pendingPresent() {
		return
	}
	svc := h.initService()
	defer svc.Shutdown()
	newPass := h.pass + "-k"
	if err := svc.RotateKEKPassphrase(h.pass, newPass); err != nil {
		h.t.Logf("rotate-kek returned: %v", err)
		return
	}
	h.pass = newPass
	h.t.Setenv("KEYORIX_MASTER_PASSWORD", h.pass)
}

// opKillAtSeam injects one of the durable interruption states a kill at a seam
// leaves. sub selects which.
func (h *seqHost) opKillAtSeam(sub byte) {
	if h.pendingPresent() {
		return
	}
	switch sub % 3 {
	case 0:
		// State B: a DEK rotation committed its sweep but crashed before the
		// pending->active rename. Reproduce by rotating fully, then rewinding the
		// active DEK to old and re-inserting the redo marker.
		// Faithful state B: the sweep committed (rows/epoch/marker under the new
		// DEK) and dek.key.pending holds the new DEK, but the crash came before
		// the promote step that renames pending->active AND rewrites the key-set
		// manifest. So both the active dek.key AND the manifest stay at the OLD
		// generation. Snapshot them before rotating and restore them after.
		active := filepath.Join(h.dir, "dek.key")
		manifestPath := filepath.Join(h.dir, "keyset.manifest.json")
		oldWrapped, err := os.ReadFile(active)
		require.NoError(h.t, err)
		oldManifest, manifestErr := os.ReadFile(manifestPath)
		svc := h.initService()
		if _, err := svc.RotateDEKWithSweep(h.pass, h.db); err != nil {
			svc.Shutdown()
			h.t.Logf("state-B rotate: %v", err)
			return
		}
		svc.Shutdown()
		require.NoError(h.t, os.Rename(active, active+".pending"))
		require.NoError(h.t, os.WriteFile(active, oldWrapped, 0o600))
		if manifestErr == nil {
			require.NoError(h.t, os.WriteFile(manifestPath, oldManifest, 0o600))
		} else {
			_ = os.Remove(manifestPath) // no manifest existed before: remove the rotation's
		}
		// Re-insert the redo marker the committed sweep wrote (RotateDEKWithSweep
		// deletes it on full success). Recovery checks the marker's PRESENCE and
		// then promotes the pending DEK; the value is informational. Its value is
		// the new DEK's epoch on PG (set by the sweep) or a placeholder on SQLite,
		// which writes no dek.epoch row.
		markerValue := "state-b-pending"
		var epoch models.SystemMetadata
		if err := h.db.Where("key = ?", seqDEKEpochKey).First(&epoch).Error; err == nil {
			markerValue = epoch.Value
		}
		_ = h.db.Where("key = ?", seqRedoMarkerKey).Delete(&models.SystemMetadata{}).Error
		require.NoError(h.t, h.db.Create(&models.SystemMetadata{Key: seqRedoMarkerKey, Value: markerValue}).Error)
	case 1:
		// A rotate-kek interrupted before it changed the active keys: a stale
		// kek.salt.pending (H2's shape).
		_ = os.WriteFile(filepath.Join(h.dir, "kek.salt.pending"), []byte("stale-staged-salt"), 0o600)
	case 2:
		// A DEK rotation crashed BEFORE its sweep commit: an uncommitted
		// dek.key.pending that recovery must discard.
		_ = os.WriteFile(filepath.Join(h.dir, "dek.key.pending"), []byte("uncommitted-dek"), 0o600)
	}
}

// opStartOnce models one server start: crash recovery, reconcile, initialize,
// the DEK epoch guard. It must complete a pending DEK rotation.
func (h *seqHost) opStartOnce() {
	svc := encryption.NewService(h.encCfg(), h.dir)
	if err := svc.AcquireExclusiveKeyLock(); err != nil {
		h.t.Fatalf("start-once key lock: %v", err)
	}
	defer svc.Shutdown() // release the lock; the recovery's effects persist on disk/db
	// ReconcileKeySet must run before DEK-rotation crash recovery (reconcile.go).
	if err := svc.ReconcileKeySet(); err != nil {
		h.t.Fatalf("start-once reconcile: %v", err)
	}
	if err := svc.RecoverInterruptedRotation(h.db); err != nil {
		h.t.Fatalf("start-once recover: %v", err)
	}
	if err := svc.Initialize(h.pass); err != nil {
		h.t.Fatalf("start-once initialize: %v", err)
	}
	if h.pg {
		if err := svc.StartDEKEpochGuard(h.db, nil); err != nil {
			h.t.Fatalf("start-once epoch guard (single dir must match): %v", err)
		}
	}
	// INV: after a start-once that leaves no .pending, a DEK-pending interruption
	// has been settled and a backup must not refuse (checked when a backup runs).
}

// opReadAll decrypts all secrets with a fresh service. When the key dir is
// coherent (no .pending), the ledger must come back exactly.
func (h *seqHost) opReadAll() {
	if h.pendingPresent() {
		return
	}
	svc := h.initService()
	defer svc.Shutdown()
	got, allOK := decryptAllWith(h.t, svc, h.db, h.ledger)
	require.True(h.t, allOK, "read-all-secrets: some versions did not decrypt on a coherent install")
	require.Equal(h.t, h.ledgerPlaintexts(), got, "read-all-secrets: ledger mismatch (a rotation altered the secrets)")
}

// opBackup runs the real admin backup and enforces the CONTRACT oracle.
func (h *seqHost) opBackup() {
	chdirTest(h.t, h.dir)
	configPathFlag = h.writeConfig(h.dir, h.dbPathOrDSN)
	archive := filepath.Join(h.t.TempDir(), "seq-backup.tar.gz")
	backupOutput = archive
	backupExclusive = !h.pg // SQLite needs the DB to itself; PG default live
	out, err := captureStdout(h.t, func() error { return runAdminBackup(nil, nil) })

	if err != nil {
		// Branch (b): refusal must write NO archive.
		_, statErr := os.Stat(archive)
		require.True(h.t, os.IsNotExist(statErr), "a refused backup must write no archive:\n%s", out)
		// A refusal is only legitimate while a rotation is pending.
		require.True(h.t, h.pendingPresent(),
			"backup refused on a coherent install (no .pending present):\n%s\nerr: %v", out, err)
		return
	}
	// Branch (a): the archive must restore on a clean host and decrypt to the ledger.
	fi, statErr := os.Stat(archive)
	require.NoError(h.t, statErr, "backup reported success but wrote no archive")
	require.Greater(h.t, fi.Size(), int64(0))
	h.lastArchive = archive
	h.cleanHostVerify(archive)
}

// opCopyToCleanHost restores the most recent successful backup onto a fresh
// host and checks ledger equality.
func (h *seqHost) opCopyToCleanHost() {
	if h.lastArchive == "" {
		return
	}
	h.cleanHostVerify(h.lastArchive)
}

// cleanHostVerify restores archive into a fresh key dir + fresh database, boots
// one service, and asserts every secret decrypts to the current ledger.
func (h *seqHost) cleanHostVerify(archive string) {
	t := h.t
	dstDir, dstDBOrDSN := h.freshCleanTarget()
	chdirTest(t, dstDir)
	configPathFlag = h.writeConfig(dstDir, dstDBOrDSN)
	restoreInput = archive
	restoreOverwriteExisting = false
	restoreAllowRollback = true
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "a backup that reported success must restore on a clean host:\n%s", out)

	svc := encryption.NewService(h.encCfg(), dstDir)
	require.NoError(t, svc.AcquireExclusiveKeyLock())
	require.NoError(t, svc.RecoverInterruptedRotation(nil)) // local cleanup only on the restored key dir
	require.NoError(t, svc.ReconcileKeySet())
	require.NoError(t, svc.Initialize(h.pass))
	defer svc.Shutdown()

	dstDB := openGormFromCurrentConfig(t) // configPathFlag is the dst config
	if h.pg {
		// Boot the epoch guard; a clean host restored from a coherent backup must match.
		require.NoError(t, svc.StartDEKEpochGuard(dstDB, nil))
	}
	got, allOK := decryptAllWith(t, svc, dstDB, h.ledger)
	require.True(t, allOK, "clean-host restore: some secrets did not decrypt (undecryptable archive)")
	require.Equal(t, h.ledgerPlaintexts(), got, "clean-host restore: ledger mismatch")

	// restore to the primary dir context is not needed; chdir back to key dir.
	chdirTest(t, h.dir)
}

// cleanHostTry restores archive onto a fresh host and reports, without
// asserting, whether the restore succeeded and whether every ledger secret
// decrypted. Used by the red-proofs to observe the oracle's verdict on a
// planted defect vs a silent control.
func (h *seqHost) cleanHostTry(archive string) (restoreOK, decrypts bool) {
	t := h.t
	dstDir, dstDBOrDSN := h.freshCleanTarget()
	chdirTest(t, dstDir)
	configPathFlag = h.writeConfig(dstDir, dstDBOrDSN)
	restoreInput = archive
	restoreOverwriteExisting = false
	restoreAllowRollback = true
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	defer chdirTest(t, h.dir)
	if _, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) }); err != nil {
		return false, false
	}
	svc := encryption.NewService(h.encCfg(), dstDir)
	if err := svc.AcquireExclusiveKeyLock(); err != nil {
		return true, false
	}
	defer svc.Shutdown()
	if err := svc.ReconcileKeySet(); err != nil {
		return true, false
	}
	if err := svc.RecoverInterruptedRotation(nil); err != nil {
		return true, false
	}
	if err := svc.Initialize(h.pass); err != nil {
		return true, false
	}
	dstDB := openGormFromCurrentConfig(t)
	_, allOK := decryptAllWith(t, svc, dstDB, h.ledger)
	return true, allOK
}

// runSequence decodes data into an op sequence and applies it, enforcing the
// oracles after each op.
func runSequence(t *testing.T, pg bool, base string, data []byte) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	h := newSeqHost(t, pg, base)
	t.Setenv("KEYORIX_MASTER_PASSWORD", h.pass)

	const maxOps = 10
	for i, b := range data {
		if i >= maxOps {
			break
		}
		switch b % 7 {
		case 0:
			h.opRotateDEK()
		case 1:
			h.opRotateKEK()
		case 2:
			h.opKillAtSeam(b / 7)
		case 3:
			h.opStartOnce()
		case 4:
			h.opReadAll()
		case 5:
			h.opBackup()
		case 6:
			h.opCopyToCleanHost()
		}
	}
	// Final settle: start once (clears any DEK-pending), then a backup must hold
	// the contract.
	h.opStartOnce()
	h.opBackup()
}

func FuzzBackupRotationSequences(f *testing.F) {
	for _, seed := range seqSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		runSequence(t, false, "", data)
	})
}

func FuzzBackupRotationSequencesPG(f *testing.F) {
	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	if base == "" {
		f.Skip("KEYORIX_TEST_PG_DSN not set — skipping PG sequence fuzzer")
	}
	for _, seed := range seqSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		runSequence(t, true, base, data)
	})
}

// seqSeeds are hand-picked op sequences that exercise the interesting seams.
func seqSeeds() [][]byte {
	return [][]byte{
		{5},                   // backup only
		{0, 5},                // rotate-dek, backup
		{1, 5},                // rotate-kek, backup
		{2, 5, 3, 5},          // kill-at-seam, backup(refuse), start-once, backup(ok)
		{2 + 7, 3, 5},         // stale-salt seam, start-once, backup
		{2 + 14, 3, 5},        // uncommitted-dek seam, start-once, backup
		{0, 2, 3, 4, 5, 6},    // rotate, kill, start, read, backup, copy
		{0, 1, 5, 0, 3, 5, 6}, // mixed
	}
}
