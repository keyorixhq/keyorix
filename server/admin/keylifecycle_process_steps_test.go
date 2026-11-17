// keylifecycle_process_steps_test.go — the step handlers, oracles and program
// driver for the process-level key-lifecycle harness (see
// keylifecycle_process_harness_test.go for the design and the child protocol).
package admin

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
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
// acknowledged-write snapshot (known writes + deleted secrets) in effect WHEN IT
// WAS TAKEN: a later KEK rotation changes the live passphrase but not this
// archive's, and a later delete does not make the archive's copy deletable.
type klBackup struct {
	path       string
	passphrase string
	known      []knownVersion
	deleted    map[uint]bool
}

// ---------------------------------------------------------------------------
// Oracle (a)+(b): the store opens and every acknowledged write still exists and
// decrypts to exactly its recorded plaintext.
// ---------------------------------------------------------------------------

// klOracleReopenAndDecrypt opens the store at dir/cfg in-process (the parent holds
// no handle between steps) and verifies:
//
//	(a) encryption Initialize succeeds. Only a RESTORED store (allowRefusal) may
//	    instead fail with a DOCUMENTED typed error; the source store, which every
//	    step and the recovery command must leave usable, may not. Never a panic or
//	    an undocumented error; and
//	(b) klDecryptKnownWith: every known write exists and decrypts under
//	    `passphrase`.
//
// It does NOT verify: versions this harness never created; the audit chain
// (covered by the restore's own verify-audit, oracle c); on-disk physical layout;
// or any property of a restored store that refused to open with a documented
// error (it classifies and returns, it cannot decrypt a store that will not open).
func klOracleReopenAndDecrypt(t *testing.T, dir string, cfg *config.Config, passphrase string,
	known []knownVersion, deleted map[uint]bool, allowRefusal bool, label string) {
	t.Helper()
	enc := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := enc.Initialize(passphrase); err != nil {
		kind := klClassifyErr(err)
		require.Truef(t, allowRefusal && klDocumentedKinds[kind] && kind != "",
			"%s: oracle(a) store failed to open (kind=%q, refusal allowed=%v): %v", label, kind, allowRefusal, err)
		t.Logf("%s: oracle(a) restored store refused to open with documented typed error kind=%q (acceptable)", label, kind)
		return
	}
	defer enc.Shutdown()
	gdb, err := storage.OpenGormDB(cfg)
	require.NoErrorf(t, err, "%s: oracle(a) open DB", label)
	defer func() {
		if sqlDB, derr := gdb.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()
	require.NoErrorf(t, klDecryptKnownWith(enc, gdb, known, deleted), "%s: oracle(b)", label)
}

// klDecryptKnownWith is the pure, error-returning core of oracle (b): every known
// write must still be in secret_versions and decrypt to its exact recorded
// plaintext. A missing row is a violation (a lost acknowledged write) unless its
// secret's delete was acknowledged; any other read error is a violation. Returns
// the first violation (so a red-proof can WATCH it fire), nil when every known
// write is present and correct. (Delete is a soft delete today, so a deleted
// secret's versions normally survive and are checked too.)
func klDecryptKnownWith(enc *encryption.Service, gdb *gorm.DB, known []knownVersion, deleted map[uint]bool) error {
	for _, kv := range known {
		var row models.SecretVersion
		err := gdb.Where("secret_node_id = ? AND version_number = ?", kv.nodeID, kv.version).First(&row).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			if deleted[kv.nodeID] {
				continue
			}
			return fmt.Errorf("node=%d ver=%d: acknowledged write is MISSING (its secret was never deleted)", kv.nodeID, kv.version)
		case err != nil:
			return fmt.Errorf("node=%d ver=%d: read failed: %w", kv.nodeID, kv.version, err)
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

// klVerifySource runs the oracle over the live source store (chdir'd there). The
// source store must open: no documented refusal is accepted here.
func (w *klWorld) klVerifySource(label string) {
	chdirTest(w.t, w.dir)
	configPathFlag = w.cfgPath
	cfg, err := loadConfig()
	require.NoError(w.t, err)
	klOracleReopenAndDecrypt(w.t, w.dir, cfg, w.passphrase, w.known, w.deleted, false, "["+w.backend+"] "+label+" source")
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

// klStepUpdate updates a LIVE (not deleted) secret; a no-op when there is none.
func (w *klWorld) klStepUpdate(arg byte) {
	nid := w.pickLiveNode(arg)
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

// klStepDelete deletes a LIVE secret; a no-op when there is none. Its known
// versions stay in the model: oracle (b) lets them be missing from then on.
func (w *klWorld) klStepDelete(arg byte) {
	nid := w.pickLiveNode(arg)
	if nid == 0 {
		return
	}
	res, out, werr := w.klRunChild("delete", map[string]string{klEnvNodeID: fmt.Sprintf("%d", nid)})
	w.klRequireDocumented("delete", res, out, werr, "delete")
	if res.OK {
		w.deleted[nid] = true
	}
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
// known/deleted snapshot in effect now (a later KEK rotation must not strand this
// archive).
func (w *klWorld) klStepBackup() {
	archive := filepath.Join(w.t.TempDir(), fmt.Sprintf("backup-%d.tar.gz", w.next()))
	res, out, werr := w.klRunChild("backup", map[string]string{klEnvArchive: archive})
	w.klRequireDocumented("backup", res, out, werr, "backup")
	if res.OK {
		w.lastBackup = &klBackup{path: archive, passphrase: w.passphrase,
			known: slices.Clone(w.known), deleted: maps.Clone(w.deleted)}
	}
}

// klStepRestore (oracle c): restore the last backup into a FRESH store and assert
// it either starts and decrypts every acknowledged secret, or refuses with a
// documented error — never a store with undecryptable or missing secrets.
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
	klOracleReopenAndDecrypt(w.t, restoreDir, cfg, w.lastBackup.passphrase, w.lastBackup.known, w.lastBackup.deleted, true,
		"["+w.backend+"] oracle(c) restored")
	chdirTest(w.t, w.dir) // restore chdir'd the parent; return to source
}

// Kill phases klStepKillRotate observes (with the child SIGSTOPped, so the files
// cannot change between the look and the SIGKILL). An "exited:" prefix means the
// child had already exited when the parent stopped it.
const (
	klPhasePrePending         = "pre-pending"         // no dek.key.pending yet, dek.key unchanged
	klPhasePendingUncommitted = "pending-uncommitted" // pending DEK present, sweep not committed
	klPhasePendingCommitted   = "pending-committed"   // sweep + redo marker committed, not promoted
	klPhasePromoted           = "promoted"            // dek.key is the new DEK
)

// klStepKillRotate (oracles d,a,b): SIGKILL a DEK rotation child at a phase chosen
// by arg, then run the DOCUMENTED recovery command and assert the store is fully
// usable with no manual repair. arg%4 picks how the kill point is reached:
//
//	0: a wall-clock delay of 1..40 ms after the start (arg/4): before the child
//	   has written anything (start-up and key derivation take far longer).
//	1: as soon as dek.key.pending appears, plus 0..2.8 ms (arg/4): inside the
//	   pending window (a few ms), usually before the sweep commits.
//	2: the rotate_dek_pause child, parked right after the sweep's COMMIT: the
//	   only copy of the new DEK is dek.key.pending (deterministic).
//	3: the rotate_dek_pause child, parked after the promote, before the redo
//	   marker is cleared (deterministic).
//
// Returns the observed phase (also appended to w.killPhases). After the recovery
// command: no dek.key.pending is left; dek.key is the NEW DEK exactly when the
// sweep had committed (recovery promoted it) or the promote had happened, and the
// old one otherwise; and oracle (b) holds over the source.
func (w *klWorld) klStepKillRotate(arg byte) string {
	dekPath := filepath.Join(w.dir, "dek.key")
	pendingPath := dekPath + ".pending"
	orig, err := os.ReadFile(dekPath) // #nosec G304 -- test-controlled path
	require.NoError(w.t, err)
	resultFile := filepath.Join(w.t.TempDir(), "res.json")
	mode, sub := arg%4, int(arg/4)

	var p *klProc
	switch mode {
	case 0:
		p = w.klSpawn("rotate_dek", resultFile, nil)
		time.Sleep(time.Duration(1+sub%40) * time.Millisecond)
	case 1:
		p = w.klSpawn("rotate_dek", resultFile, nil)
		w.klWaitPath(p, pendingPath)
		time.Sleep(time.Duration(sub%8) * 400 * time.Microsecond)
	default:
		pause := klPauseAfterCommit
		if mode == 3 {
			pause = klPauseBeforeMarkerClear
		}
		ready := filepath.Join(w.t.TempDir(), "ready")
		p = w.klSpawn("rotate_dek_pause", resultFile, map[string]string{klEnvPause: pause, klEnvReady: ready})
		w.klWaitReady(p, ready, resultFile)
	}
	exited := p.exited()
	if !exited {
		_ = p.cmd.Process.Signal(syscall.SIGSTOP)
	}
	pendingAtKill := klFileExists(pendingPath)
	atKill, err := os.ReadFile(dekPath) // #nosec G304 -- test-controlled path
	require.NoError(w.t, err)
	p.kill()
	committed := w.klRedoMarkerCommitted()

	promotedAtKill := !bytes.Equal(atKill, orig)
	var phase string
	switch {
	case promotedAtKill:
		phase = klPhasePromoted
	case pendingAtKill && committed:
		phase = klPhasePendingCommitted
	case pendingAtKill:
		phase = klPhasePendingUncommitted
	default:
		phase = klPhasePrePending
	}
	if exited {
		phase = "exited:" + phase
	}
	switch mode {
	case 2:
		require.Equalf(w.t, klPhasePendingCommitted, phase, "[%s] kill after the sweep commit landed in the wrong phase", w.backend)
	case 3:
		require.Equalf(w.t, klPhasePromoted, phase, "[%s] kill before the marker clear landed in the wrong phase", w.backend)
		require.Truef(w.t, committed, "[%s] kill before the marker clear: the redo marker must still be committed", w.backend)
	}
	w.killPhases = append(w.killPhases, phase)
	w.t.Logf("[%s] kill_rotate mode=%d: killed in phase %s", w.backend, mode, phase)

	// Documented recovery command (runbook §6): finishes an interrupted rotation.
	label := "kill_rotate(" + phase + ")->recover (oracle d)"
	res, out, werr := w.klRunChild("recover", nil)
	w.klRequireDocumented("recover", res, out, werr, label)
	require.Truef(w.t, res.OK, "[%s] %s: the recovery command must succeed, got kind=%q: %s; output:\n%s",
		w.backend, label, res.ErrKind, res.ErrMsg, out)
	require.Falsef(w.t, klFileExists(pendingPath), "[%s] %s: dek.key.pending left after recovery", w.backend, label)
	after, err := os.ReadFile(dekPath) // #nosec G304 -- test-controlled path
	require.NoError(w.t, err)
	wantNew := promotedAtKill || (pendingAtKill && committed)
	require.Equalf(w.t, wantNew, !bytes.Equal(after, orig),
		"[%s] %s: after recovery dek.key must be the new DEK exactly when the sweep had committed (want new=%v)", w.backend, label, wantNew)
	// After recovery the store must be fully usable — no manual hand-repair (#4105).
	w.klVerifySource(label)
	return phase
}

// klWaitPath busy-polls until path exists or the child exits (the pending window
// is a few ms, so no sleep between polls).
func (w *klWorld) klWaitPath(p *klProc, path string) {
	w.t.Helper()
	deadline := time.Now().Add(klChildTimeout)
	for time.Now().Before(deadline) && !p.exited() {
		if klFileExists(path) {
			return
		}
	}
}

func klFileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// klRedoMarkerCommitted reports whether the source DB holds the DEK-rotation redo
// marker. Called only with no child running.
func (w *klWorld) klRedoMarkerCommitted() bool {
	cfg := klLoadConfigAt(w.t, w.dir, w.cfgPath)
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(w.t, err)
	defer func() {
		if sqlDB, derr := gdb.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()
	if !gdb.Migrator().HasTable(&models.SystemMetadata{}) {
		return false
	}
	var n int64
	require.NoError(w.t, gdb.Model(&models.SystemMetadata{}).Where("key = ?", klRedoMarkerKey).Count(&n).Error)
	return n > 0
}

// klSpawnLockHolder starts a holdlock child and waits until it HOLDS the lock.
// Create the returned release file to let it go.
func (w *klWorld) klSpawnLockHolder() (p *klProc, resultFile, release string) {
	dir := w.t.TempDir()
	resultFile = filepath.Join(dir, "hold.json")
	ready := filepath.Join(dir, "ready")
	release = filepath.Join(dir, "release")
	p = w.klSpawn("holdlock", resultFile, map[string]string{
		klEnvHoldMS: fmt.Sprintf("%d", klChildTimeout.Milliseconds()), klEnvReady: ready, klEnvRelease: release,
	})
	w.klWaitReady(p, ready, resultFile)
	return p, resultFile, release
}

// klStepConcurrentRotate (oracle e, part 1): while a child holds the exclusive key
// lock, a second rotation must be REFUSED (lock-held) — the two never both proceed.
// The holder keeps the lock until the parent releases it, so a slow rotation child
// cannot outlast a fixed hold.
func (w *klWorld) klStepConcurrentRotate() {
	hold, holdResult, release := w.klSpawnLockHolder()

	// A real rotation now must refuse with the documented lock-held error.
	res, out, werr := w.klRunChild("rotate_dek", nil)
	require.NoError(w.t, os.WriteFile(release, nil, 0600))
	hwerr := hold.wait(w.t)
	w.klRequireDocumented("rotate_dek(concurrent)", res, out, werr, "concurrent_rotate (oracle e)")
	require.Falsef(w.t, res.OK,
		"[%s] oracle(e) VIOLATION: a second rotation PROCEEDED while another process held the exclusive lock; output:\n%s", w.backend, out)
	require.Equalf(w.t, "lock-held", res.ErrKind,
		"[%s] oracle(e) concurrent rotation must refuse with lock-held, got kind=%q: %s", w.backend, res.ErrKind, res.ErrMsg)
	hres, rerr := klReadResult(holdResult)
	require.NoError(w.t, rerr)
	require.Truef(w.t, hres.OK && hwerr == nil, "[%s] lock holder did not finish cleanly: %+v exitErr=%v", w.backend, hres, hwerr)
}

// klStepKillLockHolder (oracle e, part 2): SIGKILL a process holding the exclusive
// lock; a subsequent rotation must SUCCEED — a killed holder never blocks forever
// (flock releases on process exit).
func (w *klWorld) klStepKillLockHolder() {
	hold, _, _ := w.klSpawnLockHolder()
	hold.kill()

	res, out, werr := w.klRunChild("rotate_dek", nil)
	w.klRequireDocumented("rotate_dek(after-kill-holder)", res, out, werr, "kill_lockholder (oracle e)")
	require.Truef(w.t, res.OK,
		"[%s] oracle(e) VIOLATION: a killed lock holder blocked a later rotation forever (kind=%q): %s; output:\n%s",
		w.backend, res.ErrKind, res.ErrMsg, out)
}

// klStepReopen (oracle a,b): just reopen+decrypt the source, no mutation.
func (w *klWorld) klStepReopen() { w.klVerifySource("reopen") }

// ---------------------------------------------------------------------------
// Model helpers
// ---------------------------------------------------------------------------

// pickLiveNode picks a known secret whose delete has not been acknowledged (0
// when there is none): update and delete of a deleted secret are refused by
// design, which would read as an undocumented error.
func (w *klWorld) pickLiveNode(b byte) uint {
	nodes := w.liveNodes()
	if len(nodes) == 0 {
		return 0
	}
	return nodes[int(b)%len(nodes)]
}

func (w *klWorld) liveNodes() []uint {
	seen := map[uint]bool{}
	var out []uint
	for _, kv := range w.known {
		if !seen[kv.nodeID] && !w.deleted[kv.nodeID] {
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
// a single exec's wall time is ~klMaxSteps child spawns. On a loaded shared host
// a 14-step program occasionally exceeded Go fuzzing's worker-liveness window and
// the coordinator killed the worker ("exit status 2"), a false crasher that
// replayed green in isolation (PR #4142). 10 keeps worst-case exec time well
// under that window without weakening any oracle.
const klMaxSteps = 10

// klRunProgram sets up a fresh world for backend and drives program as a sequence
// of lifecycle steps, running the per-step oracle after each. 3 bytes/step:
// op, arg0, arg1. Returns the world so a replay can assert on what it reached.
func klRunProgram(t *testing.T, backend, pgBaseDSN string, program []byte) *klWorld {
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
	return w
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
		_ = w.klStepKillRotate(a1)
	case 8:
		w.klStepConcurrentRotate()
	case 9:
		w.klStepKillLockHolder()
	case 10:
		w.klStepReopen()
	}
}
