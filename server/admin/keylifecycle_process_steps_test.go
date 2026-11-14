// keylifecycle_process_steps_test.go — the step handlers, oracles and program
// driver for the process-level key-lifecycle harness (see
// keylifecycle_process_harness_test.go for the design and the child protocol).
package admin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// klBackup records a backup archive together with the passphrase and the
// acknowledged-write snapshot in effect WHEN IT WAS TAKEN — a later KEK rotation
// changes the live passphrase but not this archive's, so a restore must use these.
type klBackup struct {
	path       string
	passphrase string
	known      []knownVersion
}

// ---------------------------------------------------------------------------
// Oracle (a)+(b): the store opens (or a documented typed error) and every
// acknowledged write decrypts to exactly its recorded plaintext.
// ---------------------------------------------------------------------------

// klOracleReopenAndDecrypt opens the store at dir/cfg in-process (the parent holds
// no handle between steps) and verifies:
//
//	(a) encryption Initialize succeeds, OR fails with a DOCUMENTED typed error
//	    (never a panic / unexpected error); and
//	(b) every known write still present in secret_versions decrypts to its exact
//	    recorded plaintext under `passphrase`.
//
// It does NOT verify: versions this harness never created; versions whose secret
// was deleted/purged (their row may be gone — oracle (b) only covers surviving
// rows); the audit chain (covered by the restore's own verify-audit, oracle 3);
// on-disk physical layout; or any property of a store that legitimately refused to
// open with a documented error (it classifies and returns, it cannot decrypt a
// store that will not open).
func klOracleReopenAndDecrypt(t *testing.T, dir string, cfg *config.Config, passphrase string, known []knownVersion, label string) {
	t.Helper()
	enc := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := enc.Initialize(passphrase); err != nil {
		kind := klClassifyErr(err)
		require.Truef(t, klDocumentedKinds[kind] && kind != "",
			"%s: oracle(a) store failed to open with an UNDOCUMENTED error (kind=%q): %v", label, kind, err)
		t.Logf("%s: oracle(a) store opened with documented typed error kind=%q (acceptable)", label, kind)
		return
	}
	defer enc.Shutdown()
	gdb, err := storage.OpenGormDB(cfg)
	require.NoErrorf(t, err, "%s: oracle(a) open DB over restored store", label)
	defer func() {
		if sqlDB, derr := gdb.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()
	require.NoErrorf(t, klDecryptKnownWith(enc, gdb, known), "%s: oracle(b)", label)
}

// klDecryptKnownWith is the pure, error-returning core of oracle (b): every known
// write still present in secret_versions must decrypt to its exact recorded
// plaintext. Returns the first violation as an error (so a red-proof can WATCH it
// fire), nil when every surviving known write decrypts correctly. A row that no
// longer survives (deleted/purged/unacknowledged) is skipped, not a violation.
func klDecryptKnownWith(enc *encryption.Service, gdb *gorm.DB, known []knownVersion) error {
	for _, kv := range known {
		var row models.SecretVersion
		if gdb.Where("secret_node_id = ? AND version_number = ?", kv.nodeID, kv.version).First(&row).Error != nil {
			continue
		}
		aad := encryption.SecretAAD(kv.nodeID, kv.projectID, kv.version)
		got, derr := enc.DecryptSecretWithAAD(row.EncryptedValue, aad)
		if derr != nil {
			return fmt.Errorf("node=%d ver=%d failed to decrypt: %w", kv.nodeID, kv.version, derr)
		}
		if !bytesEqualConst(got, kv.plaintext) {
			return fmt.Errorf("node=%d ver=%d plaintext mismatch (got %d bytes sha=%s, want %d bytes sha=%s)",
				kv.nodeID, kv.version, len(got), shortSHA(got), len(kv.plaintext), shortSHA(kv.plaintext))
		}
	}
	return nil
}

// klVerifySource runs the oracle over the live source store (chdir'd there).
func (w *klWorld) klVerifySource(label string) {
	chdirTest(w.t, w.dir)
	configPathFlag = w.cfgPath
	cfg, err := loadConfig()
	require.NoError(w.t, err)
	klOracleReopenAndDecrypt(w.t, w.dir, cfg, w.passphrase, w.known, "["+w.backend+"] "+label+" source")
}

// klRequireDocumented asserts a child result is either success or a documented
// refusal — never an UNEXPECTED error, a missing result file (a crash/panic that
// could not even write its outcome), or a non-zero exit. This is the oracle-(a)
// "never a panic" check applied to a child step.
func (w *klWorld) klRequireDocumented(op string, res klResult, childOut string, waitErr error, label string) {
	w.t.Helper()
	require.NotEqualf(w.t, klNoResult, res.ErrKind,
		"%s: %s produced NO result file (crash/panic?) exitErr=%v; output:\n%s", label, op, waitErr, childOut)
	require.NotEqualf(w.t, "UNEXPECTED", res.ErrKind,
		"%s: %s returned an UNDOCUMENTED error: %s; output:\n%s", label, op, res.ErrMsg, childOut)
	require.Truef(w.t, klDocumentedKinds[res.ErrKind],
		"%s: %s returned an unrecognised error kind %q: %s", label, op, res.ErrKind, res.ErrMsg)
	require.NoErrorf(w.t, waitErr, "%s: %s exited non-zero despite a documented result; output:\n%s", label, op, childOut)
}

// ---------------------------------------------------------------------------
// Step handlers
// ---------------------------------------------------------------------------

func (w *klWorld) klStepCreate(arg byte) {
	n := w.next()
	pt := []byte(fmt.Sprintf("kl-plaintext-%d-%d", n, arg))
	vf := filepath.Join(w.t.TempDir(), "val")
	require.NoError(w.t, os.WriteFile(vf, pt, 0600))
	res, out, werr := w.klRunChild("create", map[string]string{
		klEnvProjID: fmt.Sprintf("%d", w.projID), klEnvEnvID: fmt.Sprintf("%d", w.envID),
		klEnvName: fmt.Sprintf("secret-%d", n), klEnvValueFile: vf,
	})
	w.klRequireDocumented("create", res, out, werr, "create")
	if res.OK && res.NodeID != 0 {
		w.known = append(w.known, knownVersion{nodeID: res.NodeID, projectID: w.projID, version: 1, plaintext: pt})
	}
}

func (w *klWorld) klStepUpdate(arg byte) {
	nid := w.pickKnownNode(arg)
	if nid == 0 {
		return
	}
	n := w.next()
	pt := []byte(fmt.Sprintf("kl-plaintext-v-%d-%d", n, arg))
	vf := filepath.Join(w.t.TempDir(), "val")
	require.NoError(w.t, os.WriteFile(vf, pt, 0600))
	res, out, werr := w.klRunChild("update", map[string]string{klEnvNodeID: fmt.Sprintf("%d", nid), klEnvValueFile: vf})
	w.klRequireDocumented("update", res, out, werr, "update")
	if res.OK {
		w.known = append(w.known, knownVersion{nodeID: nid, projectID: w.projID, version: w.highestVersion(nid) + 1, plaintext: pt})
	}
}

func (w *klWorld) klStepDelete(arg byte) {
	nid := w.pickKnownNode(arg)
	if nid == 0 {
		return
	}
	res, out, werr := w.klRunChild("delete", map[string]string{klEnvNodeID: fmt.Sprintf("%d", nid)})
	w.klRequireDocumented("delete", res, out, werr, "delete")
	// Leave known entries: oracle (b) skips a row that no longer survives.
}

func (w *klWorld) klStepRotateDEK() {
	res, out, werr := w.klRunChild("rotate_dek", nil)
	w.klRequireDocumented("rotate_dek", res, out, werr, "rotate_dek")
}

func (w *klWorld) klStepRotateKEK() {
	newPass := fmt.Sprintf("kl-pass-%d-rotated", w.next())
	res, out, werr := w.klRunChild("rotate_kek", map[string]string{"KEYORIX_NEW_MASTER_PASSWORD": newPass})
	w.klRequireDocumented("rotate_kek", res, out, werr, "rotate_kek")
	if res.OK {
		w.passphrase = newPass // key files now open ONLY under the new passphrase
	}
}

// klStepBackup takes a real backup child and records it with the passphrase +
// known-snapshot in effect now (a later KEK rotation must not strand this archive).
func (w *klWorld) klStepBackup() {
	archive := filepath.Join(w.t.TempDir(), fmt.Sprintf("backup-%d.tar.gz", w.next()))
	res, out, werr := w.klRunChild("backup", map[string]string{klEnvArchive: archive})
	w.klRequireDocumented("backup", res, out, werr, "backup")
	if res.OK {
		snap := make([]knownVersion, len(w.known))
		copy(snap, w.known)
		w.lastBackup = &klBackup{path: archive, passphrase: w.passphrase, known: snap}
	}
}

// klStepRestore (oracle c): restore the last backup into a FRESH store and assert
// it either starts and decrypts every acknowledged secret, or refuses with a
// documented error — never a store with undecryptable secrets.
func (w *klWorld) klStepRestore() {
	if w.lastBackup == nil {
		return
	}
	restoreDir := w.t.TempDir()
	restoreCfg := klConfigureBackend(w.t, w.backend, restoreDir, w.pgBaseDSN)
	res, out, werr := w.klRunChildIn("restore", restoreDir, restoreCfg, map[string]string{
		klEnvArchive:    w.lastBackup.path,
		klMasterPassEnv: w.lastBackup.passphrase, // archive-time passphrase
	})
	w.klRequireDocumented("restore", res, out, werr, "restore")
	if !res.OK {
		w.t.Logf("[%s] oracle(c) restore refused with documented kind=%q (acceptable): %s", w.backend, res.ErrKind, res.ErrMsg)
		return
	}
	require.Containsf(w.t, res.Stdout, "verify-audit on the restored database: VALID",
		"[%s] oracle(c) restore must verify the audit chain", w.backend)
	// In-process decrypt over the restored store (oracle c: never undecryptable).
	cfg := klLoadConfigAt(w.t, restoreDir, restoreCfg)
	klOracleReopenAndDecrypt(w.t, restoreDir, cfg, w.lastBackup.passphrase, w.lastBackup.known, "["+w.backend+"] oracle(c) restored")
	chdirTest(w.t, w.dir) // restore chdir'd the parent; return to source
}

// klStepKillRotate (oracles d,a,b): start a DEK rotation child, SIGKILL it at a
// fuzz-controlled delay (sometimes before, during, or after the sweep — a
// process-granularity crash), then run the DOCUMENTED recovery command and assert
// the store is fully usable with no manual repair.
func (w *klWorld) klStepKillRotate(delayArg byte) {
	resultFile := filepath.Join(w.t.TempDir(), "res.json")
	cmd := w.klStartChild("rotate_dek", w.dir, w.cfgPath, resultFile, nil)
	require.NoError(w.t, cmd.Start())
	delay := time.Duration(1+int(delayArg)%40) * time.Millisecond
	time.Sleep(delay)
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait() // reap; killed child leaves no (or a partial) result — expected

	// Documented recovery command (runbook §6): finishes an interrupted rotation.
	res, out, werr := w.klRunChild("recover", nil)
	w.klRequireDocumented("recover", res, out, werr, "kill_rotate->recover (oracle d)")
	// After recovery the store must be fully usable — no manual hand-repair (#4105).
	w.klVerifySource("kill_rotate->recover (oracle d)")
}

// klStepConcurrentRotate (oracle e, part 1): while a child holds the exclusive key
// lock, a second rotation must be REFUSED (lock-held) — the two never both proceed.
func (w *klWorld) klStepConcurrentRotate() {
	holdResult := filepath.Join(w.t.TempDir(), "hold.json")
	hold := w.klStartChild("holdlock", w.dir, w.cfgPath, holdResult, map[string]string{klEnvHoldMS: "1200"})
	require.NoError(w.t, hold.Start())
	defer func() { _ = hold.Wait() }()
	w.klWaitLockAcquired(holdResult, hold)

	// A real rotation now must refuse with the documented lock-held error.
	res, out, werr := w.klRunChild("rotate_dek", nil)
	w.klRequireDocumented("rotate_dek(concurrent)", res, out, werr, "concurrent_rotate (oracle e)")
	require.Falsef(w.t, res.OK,
		"[%s] oracle(e) VIOLATION: a second rotation PROCEEDED while another process held the exclusive lock; output:\n%s", w.backend, out)
	require.Equalf(w.t, "lock-held", res.ErrKind,
		"[%s] oracle(e) concurrent rotation must refuse with lock-held, got kind=%q: %s", w.backend, res.ErrKind, res.ErrMsg)
}

// klStepKillLockHolder (oracle e, part 2): SIGKILL a process holding the exclusive
// lock; a subsequent rotation must SUCCEED — a killed holder never blocks forever
// (flock releases on process exit).
func (w *klWorld) klStepKillLockHolder() {
	holdResult := filepath.Join(w.t.TempDir(), "hold.json")
	hold := w.klStartChild("holdlock", w.dir, w.cfgPath, holdResult, map[string]string{klEnvHoldMS: "4000"})
	require.NoError(w.t, hold.Start())
	w.klWaitLockAcquired(holdResult, hold)
	_ = hold.Process.Signal(syscall.SIGKILL)
	_ = hold.Wait()

	res, out, werr := w.klRunChild("rotate_dek", nil)
	w.klRequireDocumented("rotate_dek(after-kill-holder)", res, out, werr, "kill_lockholder (oracle e)")
	require.Truef(w.t, res.OK,
		"[%s] oracle(e) VIOLATION: a killed lock holder blocked a later rotation forever (kind=%q): %s; output:\n%s",
		w.backend, res.ErrKind, res.ErrMsg, out)
}

// klStepReopen (oracle a,b): just reopen+decrypt the source, no mutation.
func (w *klWorld) klStepReopen() { w.klVerifySource("reopen") }

// klWaitLockAcquired polls for the holdlock child's readiness file (written AFTER
// it acquired the lock, BEFORE it sleeps), failing if the child dies first.
func (w *klWorld) klWaitLockAcquired(resultFile string, cmd *exec.Cmd) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(resultFile); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	w.t.Fatalf("[%s] lock holder did not acquire the lock within 10s", w.backend)
}

// ---------------------------------------------------------------------------
// Model helpers
// ---------------------------------------------------------------------------

func (w *klWorld) pickKnownNode(b byte) uint {
	nodes := w.distinctNodes()
	if len(nodes) == 0 {
		return 0
	}
	return nodes[int(b)%len(nodes)]
}

func (w *klWorld) distinctNodes() []uint {
	seen := map[uint]bool{}
	var out []uint
	for _, kv := range w.known {
		if !seen[kv.nodeID] {
			seen[kv.nodeID] = true
			out = append(out, kv.nodeID)
		}
	}
	return out
}

func (w *klWorld) highestVersion(nid uint) int {
	h := 0
	for _, kv := range w.known {
		if kv.nodeID == nid && kv.version > h {
			h = kv.version
		}
	}
	return h
}

func klLoadConfigAt(t *testing.T, dir, cfgPath string) *config.Config {
	t.Helper()
	chdirTest(t, dir)
	configPathFlag = cfgPath
	cfg, err := loadConfig()
	require.NoError(t, err)
	return cfg
}

// ---------------------------------------------------------------------------
// Program driver
// ---------------------------------------------------------------------------

// klMaxSteps bounds a program so one fuzz input's child-process count stays sane.
// Each step forks a REAL child (storage + migration + 600k-iteration PBKDF2), so
// a single exec's wall time is ~klMaxSteps child spawns. On the loaded shared host
// a 14-step program occasionally exceeded Go fuzzing's worker-liveness window and
// the coordinator killed the worker ("exit status 2") — a false crasher that
// replayed green 4/4 in isolation (see the report's triage, KL-1/ARTIFACT). 10
// keeps worst-case exec time well under that window without weakening any oracle.
const klMaxSteps = 10

// klRunProgram sets up a fresh world for backend and drives program as a sequence
// of lifecycle steps, running the per-step oracle after each. 3 bytes/step:
// op, arg0, arg1.
func klRunProgram(t *testing.T, backend, pgBaseDSN string, program []byte) {
	resetBackupRestoreFlags(t)
	w := klSetupWorld(t, backend, pgBaseDSN)
	w.klVerifySource("initial")

	steps := 0
	for i := 0; i+2 < len(program) && steps < klMaxSteps; i += 3 {
		op, a0, a1 := program[i], program[i+1], program[i+2]
		w.klStep(op, a0, a1)
		if !klStepSkipsOracle(op) {
			w.klVerifySource(fmt.Sprintf("after step %d (op=%d)", steps, op%klNumOps))
		}
		steps++
	}
}

const klNumOps = 11

// klStepSkipsOracle: steps that already run the oracle themselves (kill_rotate,
// restore, reopen) or that verify internally don't need the generic post-step
// oracle repeated.
func klStepSkipsOracle(op byte) bool {
	switch op % klNumOps {
	case 6, 7, 10: // restore, kill_rotate, reopen
		return true
	}
	return false
}

func (w *klWorld) klStep(op, a0, a1 byte) {
	switch op % klNumOps {
	case 0:
		w.klStepCreate(a0)
	case 1:
		w.klStepUpdate(a0)
	case 2:
		w.klStepDelete(a0)
	case 3:
		w.klStepRotateDEK()
	case 4:
		w.klStepRotateKEK()
	case 5:
		w.klStepBackup()
	case 6:
		w.klStepRestore()
	case 7:
		w.klStepKillRotate(a1)
	case 8:
		w.klStepConcurrentRotate()
	case 9:
		w.klStepKillLockHolder()
	case 10:
		w.klStepReopen()
	}
}
