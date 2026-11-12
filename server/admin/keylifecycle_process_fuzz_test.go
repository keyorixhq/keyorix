// keylifecycle_process_fuzz_test.go — the fuzz target, the deterministic replay
// matrix (step-2 self-tests) and the watched red/green oracle proofs for the
// process-level key-lifecycle harness (design: keylifecycle_process_harness_test.go).
package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// klBackends returns the backends to exercise: SQLite always, Postgres when
// KEYORIX_TEST_PG_DSN is set. The base DSN is returned for the postgres entry.
func klBackends(t *testing.T) []struct{ name, pgBase string } {
	out := []struct{ name, pgBase string }{{"sqlite", ""}}
	if dsn := os.Getenv("KEYORIX_TEST_PG_DSN"); dsn != "" {
		out = append(out, struct{ name, pgBase string }{"postgres", dsn})
	}
	return out
}

// FuzzKeyLifecycleProcess drives a fuzz-byte-encoded program of lifecycle steps
// (3 bytes/step: op, arg0, arg1) as REAL child processes against a fresh encrypted
// store, asserting oracles (a)-(e) after each step. SQLite always; Postgres when
// KEYORIX_TEST_PG_DSN is set (one program -> both backends per exec).
//
// This is a process-heavy PROPERTY fuzzer, not a coverage-expanding byte fuzzer:
// each step forks a real child (storage + migration + encryption init), so exec
// counts are low and the value is depth-per-exec (arbitrary lifecycle interleavings
// driven through the real cross-process lock), exactly what the in-process backup
// fuzzer could not reach.
//
// SQLite-ONLY by design. A full 10-step program forks ~10 PBKDF2-heavy children;
// on SQLite that is ~4 s/exec (safely inside Go fuzzing's worker-liveness window),
// but on Postgres each exec costs ~2x and a single exec was measured at ~103 s
// (deterministic replay, GREEN), which exceeds that window and makes the fuzz
// coordinator kill the worker ("exit status 2") — a false crasher, not an oracle
// failure (report triage KL-1/KL-2, ARTIFACT). Postgres is therefore covered by
// TestKeyLifecycleProcessReplay (both backends, under the package timeout, not the
// coordinator) and TestKeyLifecycleProcessCorpusPostgres, NOT by this live fuzz
// target. The seed-corpus pass under a plain `go test` is unaffected (it runs
// without the coordinator); it stays SQLite-only here for parity with the fuzzer.
func FuzzKeyLifecycleProcess(f *testing.F) {
	for _, seed := range klSeedPrograms() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, program []byte) {
		if os.Getenv(klEnvChild) == "1" {
			t.Skip("child process must not re-enter the fuzzer")
		}
		require.NoError(t, i18n.InitializeForTesting())
		klRunProgram(t, "sqlite", "", program)
	})
}

// klSeedPrograms are compact programs covering every op at least once. Kept small
// so the seed-corpus run under a plain `go test` stays bounded (each step forks a
// child); the thorough fixed matrix is TestKeyLifecycleProcessReplay.
func klSeedPrograms() [][]byte {
	return [][]byte{
		{0, 0, 0, 5, 0, 0, 6, 0, 0},          // create, backup, restore
		{0, 0, 0, 3, 0, 0, 10, 0, 0},         // create, rotate_dek, reopen
		{0, 0, 0, 4, 0, 0, 5, 0, 0, 6, 0, 0}, // create, rotate_kek, backup, restore
		{0, 0, 0, 7, 0, 5, 10, 0, 0},         // create, kill_rotate(+recover), reopen
		{0, 0, 0, 8, 0, 0},                   // create, concurrent_rotate
		{0, 0, 0, 9, 0, 0},                   // create, kill_lockholder
		{},
		{255, 255, 255},
	}
}

// TestKeyLifecycleProcessReplay is the deterministic replay matrix (step 2): a
// fixed set of named programs run through the full harness on every backend. It is
// the committed green self-test that proves the harness and every oracle run
// clean over the real child-process lifecycle. Postgres is included when the DSN
// is set.
func TestKeyLifecycleProcessReplay(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	cases := []struct {
		name    string
		program []byte
	}{
		{"create_backup_restore", []byte{0, 0, 0, 5, 0, 0, 6, 0, 0}},
		{"create_rotatedek_reopen", []byte{0, 0, 0, 3, 0, 0, 10, 0, 0}},
		{"create_rotatekek_backup_restore", []byte{0, 0, 0, 4, 0, 0, 5, 0, 0, 6, 0, 0}},
		{"create_kill_rotate_recover_reopen", []byte{0, 0, 0, 7, 0, 7, 10, 0, 0}},
		{"concurrent_rotate_refused", []byte{0, 0, 0, 8, 0, 0}},
		{"killed_lockholder_unblocks", []byte{0, 0, 0, 9, 0, 0}},
		{"update_then_delete", []byte{0, 0, 0, 1, 0, 0, 0, 1, 0, 2, 0, 0}},
		{"rotate_backup_then_rotate_restore", []byte{0, 0, 0, 5, 0, 0, 3, 0, 0, 6, 0, 0}},
	}
	for _, b := range klBackends(t) {
		for _, tc := range cases {
			t.Run(b.name+"/"+tc.name, func(t *testing.T) {
				klRunProgram(t, b.name, b.pgBase, tc.program)
			})
		}
	}
}

// TestKeyLifecycleProcessCorpusPostgres replays representative lifecycle programs
// — including a long, rotation-and-kill-heavy one the SQLite fuzzer explores — on
// Postgres (skipped without KEYORIX_TEST_PG_DSN). It runs under the package test
// timeout, NOT Go fuzzing's per-exec worker-liveness window, so the ~100 s/exec
// cost of a full program on Postgres cannot produce a coordinator-kill false
// crasher (see FuzzKeyLifecycleProcess's doc comment). This is the honest Postgres
// depth coverage the SQLite-only fuzz target does not provide. Runs with -timeout
// 20m in CI's pg leg.
func TestKeyLifecycleProcessCorpusPostgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set")
	}
	require.NoError(t, i18n.InitializeForTesting())
	programs := []struct {
		name    string
		program []byte
	}{
		// create, kill_rotate(+recover), reopen, update, delete, rotate_kek, backup, restore
		{"kill_rotate_then_mixed", []byte{0, 0, 0, 7, 0, 7, 10, 0, 0, 1, 0, 0, 2, 0, 0, 4, 0, 0, 5, 0, 0, 6, 0, 0}},
		// create, concurrent_rotate, create, kill_lockholder, rotate_dek, backup, restore
		{"lock_contention_then_rotate", []byte{0, 0, 0, 8, 0, 0, 0, 1, 0, 9, 0, 0, 3, 0, 0, 5, 0, 0, 6, 0, 0}},
	}
	for _, tc := range programs {
		t.Run(tc.name, func(t *testing.T) {
			klRunProgram(t, "postgres", dsn, tc.program)
		})
	}
}

// ---------------------------------------------------------------------------
// RED/GREEN oracle proofs (a guard nobody has watched fail is not a guard)
// ---------------------------------------------------------------------------

// TestKLRedProof_OracleB_Decrypt plants a realistic defect — a corrupted
// ciphertext in the store — and watches oracle (b)'s decrypt checker FIRE, with
// the uncorrupted control GREEN. Proves oracle (b) is load-bearing, not vacuous.
func TestKLRedProof_OracleB_Decrypt(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	resetBackupRestoreFlags(t)
	w := klSetupWorld(t, "sqlite", "")

	// Create a real secret via a child, record its acknowledged write.
	n := w.next()
	pt := []byte("red-green-plaintext")
	vf := filepath.Join(t.TempDir(), "val")
	require.NoError(t, os.WriteFile(vf, pt, 0600))
	res, out, werr := w.klRunChild("create", map[string]string{
		klEnvProjID: fmt.Sprintf("%d", w.projID), klEnvEnvID: fmt.Sprintf("%d", w.envID),
		klEnvName: fmt.Sprintf("secret-%d", n), klEnvValueFile: vf,
	})
	w.klRequireDocumented("create", res, out, werr, "redproof-b")
	require.True(t, res.OK && res.NodeID != 0)
	known := []knownVersion{{nodeID: res.NodeID, projectID: w.projID, version: 1, plaintext: pt}}

	// Open encryption + DB over the source.
	chdirTest(t, w.dir)
	configPathFlag = w.cfgPath
	cfg, err := loadConfig()
	require.NoError(t, err)
	enc := encryption.NewService(&cfg.Storage.Encryption, w.dir)
	require.NoError(t, enc.Initialize(w.passphrase))
	defer enc.Shutdown()
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)

	// GREEN: the acknowledged write decrypts to exactly its recorded plaintext.
	require.NoError(t, klDecryptKnownWith(enc, gdb, known), "control (green) must pass before the defect is planted")

	// RED: corrupt the on-disk ciphertext; the checker must now return an error.
	var row models.SecretVersion
	require.NoError(t, gdb.Where("secret_node_id = ? AND version_number = ?", res.NodeID, 1).First(&row).Error)
	corrupt := append([]byte(nil), row.EncryptedValue...)
	for i := range corrupt {
		corrupt[i] ^= 0xFF // corrupt the whole stored ciphertext envelope -> AEAD auth must fail
	}
	require.NoError(t, gdb.Model(&models.SecretVersion{}).
		Where("secret_node_id = ? AND version_number = ?", res.NodeID, 1).
		Update("encrypted_value", corrupt).Error)
	require.Error(t, klDecryptKnownWith(enc, gdb, known),
		"oracle(b) must FIRE on a corrupted ciphertext (watched red proof)")
}

// TestKLRedProof_ViolationGate proves the oracle-(a)/(c)/(d) "never a panic or an
// undocumented error" gate is load-bearing: the documented sentinels classify to
// accepted kinds (green) and an arbitrary error classifies to "UNEXPECTED", which
// klDocumentedKinds rejects (red). A regression that silently widened the accept
// list or mis-wrapped a sentinel would be caught here.
func TestKLRedProof_ViolationGate(t *testing.T) {
	// GREEN: every documented sentinel maps to an accepted kind.
	green := map[string]error{
		"":                      nil,
		"lock-held":             fmt.Errorf("refusing to rotate: %w", syscall.EWOULDBLOCK),
		"epoch-mismatch":        fmt.Errorf("x: %w", encryption.ErrDEKEpochMismatch),
		"write-fenced":          fmt.Errorf("x: %w", encryption.ErrDEKWriteFenced),
		"sweep-verify":          fmt.Errorf("x: %w", encryption.ErrSweepVerification),
		"protocol-too-old":      fmt.Errorf("x: %w", encryption.ErrRotationProtocolTooOld),
		"key-dir-missing":       fmt.Errorf("x: %w", &encryption.KeyDirMissingError{Dir: "/nope"}),
		"sweep-outcome-unknown": errors.New("DEK rotation failed: the re-encryption sweep may have committed"),
	}
	for wantKind, err := range green {
		got := klClassifyErr(err)
		require.Equalf(t, wantKind, got, "classify(%v)", err)
		require.Truef(t, klDocumentedKinds[got], "kind %q must be documented/accepted", got)
	}
	// RED: an arbitrary error is UNEXPECTED, which the gate must REJECT.
	got := klClassifyErr(errors.New("database is corrupt: short read on page 7"))
	require.Equal(t, "UNEXPECTED", got)
	require.Falsef(t, klDocumentedKinds[got], "UNEXPECTED must NOT be accepted (watched red proof)")
	require.Falsef(t, klDocumentedKinds[klNoResult], "a missing result file (crash) must NOT be accepted")
}

// TestKLRedProof_OracleE_Lock proves oracle (e) is load-bearing on the REAL
// cross-process flock, without disabling production:
//   - control (green): with NO holder, a rotation SUCCEEDS;
//   - fire: while a child holds the exclusive lock, a concurrent rotation is
//     REFUSED with lock-held (the two never both proceed);
//   - release: after the holder is SIGKILLed, a rotation SUCCEEDS again (a killed
//     holder never blocks forever).
//
// The free-vs-held contrast is the watched proof the lock-held assertion is not
// vacuous: a regression making the exclusive lock a no-op would make the held-case
// rotation succeed, which the fire-case assertion would catch.
func TestKLRedProof_OracleE_Lock(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	resetBackupRestoreFlags(t)
	w := klSetupWorld(t, "sqlite", "")

	// control (green): lock free -> rotation succeeds.
	res, out, werr := w.klRunChild("rotate_dek", nil)
	w.klRequireDocumented("rotate_dek", res, out, werr, "redproof-e/free")
	require.Truef(t, res.OK, "control: a rotation with a FREE lock must succeed; out:\n%s", out)

	// fire: a concurrent holder makes a rotation refuse with lock-held.
	holdResult := filepath.Join(t.TempDir(), "hold.json")
	hold := w.klStartChild("holdlock", w.dir, w.cfgPath, holdResult, map[string]string{klEnvHoldMS: "3000"})
	require.NoError(t, hold.Start())
	w.klWaitLockAcquired(holdResult, hold)
	res2, out2, werr2 := w.klRunChild("rotate_dek", nil)
	w.klRequireDocumented("rotate_dek", res2, out2, werr2, "redproof-e/held")
	require.Falsef(t, res2.OK, "oracle(e) FIRE: a rotation must NOT proceed while the lock is held; out:\n%s", out2)
	require.Equal(t, "lock-held", res2.ErrKind)
	_ = hold.Wait()

	// release: a SIGKILLed holder frees the lock; a later rotation succeeds.
	holdResult2 := filepath.Join(t.TempDir(), "hold2.json")
	hold2 := w.klStartChild("holdlock", w.dir, w.cfgPath, holdResult2, map[string]string{klEnvHoldMS: "10000"})
	require.NoError(t, hold2.Start())
	w.klWaitLockAcquired(holdResult2, hold2)
	require.NoError(t, hold2.Process.Signal(syscall.SIGKILL))
	_ = hold2.Wait()
	res3, out3, werr3 := w.klRunChild("rotate_dek", nil)
	w.klRequireDocumented("rotate_dek", res3, out3, werr3, "redproof-e/released")
	require.Truef(t, res3.OK, "a killed holder must not block a later rotation forever; out:\n%s", out3)
}

// TestKLRedProof_OracleD_Recovery proves oracle (d): after a rotation child is
// SIGKILLed at a process-granularity point, the DOCUMENTED recovery command
// (encryption upgrade-aad / UpgradeAADWithConfig) makes the store fully usable
// with no manual hand-repair, and every acknowledged write still decrypts (green).
// The deterministic in-rotation post-sweep-pre-promote recovery red/green is owned
// by internal/encryption (TestRotateDEKWithSweep_KillAfterSweepCommitBeforePromote_
// RecoversCleanly, FuzzDEKSweepCrashConsistency) — cited, not duplicated here.
func TestKLRedProof_OracleD_Recovery(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	resetBackupRestoreFlags(t)
	w := klSetupWorld(t, "sqlite", "")

	// Acknowledge a secret, then kill a rotation and recover.
	w.klStepCreate(0)
	require.NotEmpty(t, w.known, "a secret must be acknowledged before the kill")
	w.klStepKillRotate(7) // kills the rotation, runs recover, and verifies the source
	// klStepKillRotate already asserts oracle (d)+(a)+(b); reaching here green is the proof.
}
