// keylifecycle_process_fuzz_test.go — the fuzz target, the deterministic replay
// matrix (step-2 self-tests) and the watched red/green oracle proofs for the
// process-level key-lifecycle harness (design: keylifecycle_process_harness_test.go).
package admin

import (
	"bytes"
	"errors"
	"flag"
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
// SQLite-ONLY by design. A full 10-step program forks ~10 PBKDF2-heavy children.
// On SQLite one exec stays inside Go fuzzing's worker-liveness window; on Postgres
// a full program can exceed it, and the fuzz coordinator then kills the worker
// ("exit status 2"): a false crasher, not an oracle failure (seen while building
// PR #4142; the program replayed green). Postgres is therefore covered by
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
		// A plain `go test` runs every seed as a regression test. Eleven of the
		// thirteen seeds are programs TestKeyLifecycleProcessReplay already runs
		// through the same klRunProgram on SQLite (and with stricter assertions), at
		// about 190 s under -race: the duplicate alone pushed the admin-2 CI leg
		// to 1515 s of its 1800 s budget. Skip only that duplicate, and only
		// outside fuzzing: a live `-fuzz` run, and its baseline pass over the seed
		// corpus, still executes every seed.
		if !klFuzzing() && klReplayCovers(program) {
			t.Skip("program is a case of TestKeyLifecycleProcessReplay (same klRunProgram, same sqlite backend)")
		}
		require.NoError(t, i18n.InitializeForTesting())
		_ = klRunProgram(t, "sqlite", "", program)
	})
}

// klFuzzing reports whether this test binary was started to fuzz (-fuzz) or is a
// fuzz worker, as opposed to a plain run that only replays the seed corpus.
func klFuzzing() bool {
	for _, name := range []string{"test.fuzz", "test.fuzzworker"} {
		if fl := flag.Lookup(name); fl != nil && fl.Value.String() != "" && fl.Value.String() != "false" {
			return true
		}
	}
	return false
}

// klReplayCovers reports whether program is one of the replay matrix's programs.
func klReplayCovers(program []byte) bool {
	for _, tc := range klReplayCases() {
		if bytes.Equal(tc.program, program) {
			return true
		}
	}
	return false
}

// klSeedPrograms are compact programs covering every op at least once. Kept small
// so the seed-corpus run under a plain `go test` stays bounded (each step forks a
// child); the thorough fixed matrix is TestKeyLifecycleProcessReplay.
func klSeedPrograms() [][]byte {
	return [][]byte{
		{0, 0, 0, 5, 0, 0, 6, 0, 0},          // create, backup, restore
		{0, 0, 0, 3, 0, 0, 10, 0, 0},         // create, rotate_dek, reopen
		{0, 0, 0, 4, 0, 0, 5, 0, 0, 6, 0, 0}, // create, rotate_kek, backup, restore
		{0, 0, 0, 7, 0, 28, 10, 0, 0},        // create, kill_rotate(early, 8 ms), reopen
		{0, 0, 0, 7, 0, 1, 10, 0, 0},         // create, kill_rotate(pending observed), reopen
		{0, 0, 0, 7, 0, 2, 10, 0, 0},         // create, kill_rotate(after sweep commit), reopen
		{0, 0, 0, 7, 0, 3, 10, 0, 0},         // create, kill_rotate(before marker clear), reopen
		{0, 0, 0, 8, 0, 0},                   // create, concurrent_rotate
		{0, 0, 0, 9, 0, 0},                   // create, kill_lockholder
		{0, 0, 0, 2, 0, 0, 1, 0, 0},          // create, delete, update (no live secret: no-op)
		{0, 0, 0, 2, 0, 0, 2, 0, 0},          // create, delete, delete (no live secret: no-op)
		{},
		{255, 255, 255},
	}
}

// klReplayCase is one named program of the replay matrix.
type klReplayCase struct {
	name       string
	program    []byte
	wantPhases [][]string // per kill step: the accepted phases
}

// klReplayCases is the replay matrix. wantPhases: the phase each kill_rotate step
// must report, in order. A kill that lands before the rotation wrote anything
// cannot test recovery, so the kill cases assert where their kill landed (M1 in
// the PR #4142 review).
func klReplayCases() []klReplayCase {
	pendingOrLater := []string{klPhasePendingUncommitted, klPhasePendingCommitted, klPhasePromoted}
	return []klReplayCase{
		{"create_backup_restore", []byte{0, 0, 0, 5, 0, 0, 6, 0, 0}, nil},
		{"create_rotatedek_reopen", []byte{0, 0, 0, 3, 0, 0, 10, 0, 0}, nil},
		{"create_rotatekek_backup_restore", []byte{0, 0, 0, 4, 0, 0, 5, 0, 0, 6, 0, 0}, nil},
		{"create_kill_rotate_early_recover_reopen", []byte{0, 0, 0, 7, 0, 28, 10, 0, 0},
			[][]string{{klPhasePrePending}}},
		{"create_kill_rotate_pending_recover_reopen", []byte{0, 0, 0, 7, 0, 1, 10, 0, 0},
			[][]string{pendingOrLater}},
		{"create_kill_rotate_after_commit_recover_reopen", []byte{0, 0, 0, 7, 0, 2, 10, 0, 0},
			[][]string{{klPhasePendingCommitted}}},
		{"create_kill_rotate_before_marker_clear_recover_reopen", []byte{0, 0, 0, 7, 0, 3, 10, 0, 0},
			[][]string{{klPhasePromoted}}},
		{"concurrent_rotate_refused", []byte{0, 0, 0, 8, 0, 0}, nil},
		{"killed_lockholder_unblocks", []byte{0, 0, 0, 9, 0, 0}, nil},
		{"update_then_delete", []byte{0, 0, 0, 1, 0, 0, 0, 1, 0, 2, 0, 0}, nil},
		{"delete_then_update_is_noop", []byte{0, 0, 0, 2, 0, 0, 1, 0, 0}, nil},
		{"delete_then_delete_is_noop", []byte{0, 0, 0, 2, 0, 0, 2, 0, 0}, nil},
		{"rotate_backup_then_rotate_restore", []byte{0, 0, 0, 5, 0, 0, 3, 0, 0, 6, 0, 0}, nil},
	}
}

// TestKeyLifecycleProcessReplay is the deterministic replay matrix (step 2): a
// fixed set of named programs run through the full harness. It is the committed
// green self-test that proves the harness and every oracle run clean over the real
// child-process lifecycle. This is the SQLite half; the Postgres half is
// TestKeyLifecycleProcessReplay_Postgres. They are two top-level tests because the
// CI legs shard a package by top-level test name: as one test the matrix was
// 546 s under -race locally (232 s SQLite + 314 s Postgres), more than any shard
// target, so no weight could balance the admin legs.
func TestKeyLifecycleProcessReplay(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	klReplayOn(t, "sqlite", "")
}

// TestKeyLifecycleProcessReplay_Postgres is the Postgres half of the replay matrix
// (skipped without KEYORIX_TEST_PG_DSN).
func TestKeyLifecycleProcessReplay_Postgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set")
	}
	require.NoError(t, i18n.InitializeForTesting())
	klReplayOn(t, "postgres", dsn)
}

func klReplayOn(t *testing.T, backend, pgBase string) {
	t.Helper()
	for _, tc := range klReplayCases() {
		t.Run(backend+"/"+tc.name, func(t *testing.T) {
			w := klRunProgram(t, backend, pgBase, tc.program)
			require.Lenf(t, w.killPhases, len(tc.wantPhases), "kill steps run: %v", w.killPhases)
			for i, accepted := range tc.wantPhases {
				require.Containsf(t, accepted, w.killPhases[i], "kill step %d landed in phase %q", i, w.killPhases[i])
			}
		})
	}
}

// TestKeyLifecycleProcessCorpusPostgres replays representative lifecycle programs
// — including a long, rotation-and-kill-heavy one the SQLite fuzzer explores — on
// Postgres (skipped without KEYORIX_TEST_PG_DSN). It runs under the package test
// timeout, NOT Go fuzzing's per-exec worker-liveness window, so the cost of a
// full program on Postgres cannot produce a coordinator-kill false crasher (see
// FuzzKeyLifecycleProcess's doc comment). This is the honest Postgres
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
		// create, kill_rotate(after sweep commit, +recover), reopen, update, delete, rotate_kek, backup, restore
		{"kill_rotate_then_mixed", []byte{0, 0, 0, 7, 0, 2, 10, 0, 0, 1, 0, 0, 2, 0, 0, 4, 0, 0, 5, 0, 0, 6, 0, 0}},
		// create, kill_rotate(pending observed), kill_rotate(before marker clear), rotate_dek, reopen
		{"kill_rotate_phases", []byte{0, 0, 0, 7, 0, 1, 7, 0, 3, 3, 0, 0, 10, 0, 0}},
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

// TestKLRedProof_OracleB_Decrypt plants two realistic defects and watches oracle
// (b)'s checker FIRE on each, with the untouched control GREEN: a corrupted
// ciphertext, and a LOST acknowledged write (its secret_versions row removed
// although the secret was never deleted). It also shows the one allowed miss: the
// same lost row is accepted once the secret's delete is in the model.
func TestKLRedProof_OracleB_Decrypt(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	resetBackupRestoreFlags(t)
	w := klSetupWorld(t, "sqlite", "")

	// Create two real secrets via children, record their acknowledged writes.
	w.klStepCreate(0)
	w.klStepCreate(1)
	require.Len(t, w.known, 2)
	corrupted, lost := w.known[0], w.known[1]

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

	// GREEN: every acknowledged write decrypts to exactly its recorded plaintext.
	require.NoError(t, klDecryptKnownWith(enc, gdb, w.known, w.deleted), "control (green) must pass before a defect is planted")

	// RED 1: corrupt one stored ciphertext; the checker must now return an error.
	var row models.SecretVersion
	require.NoError(t, gdb.Where("secret_node_id = ? AND version_number = ?", corrupted.nodeID, 1).First(&row).Error)
	corrupt := append([]byte(nil), row.EncryptedValue...)
	for i := range corrupt {
		corrupt[i] ^= 0xFF // corrupt the whole stored ciphertext envelope -> AEAD auth must fail
	}
	require.NoError(t, gdb.Model(&models.SecretVersion{}).
		Where("secret_node_id = ? AND version_number = ?", corrupted.nodeID, 1).
		Update("encrypted_value", corrupt).Error)
	require.Error(t, klDecryptKnownWith(enc, gdb, []knownVersion{corrupted}, w.deleted),
		"oracle(b) must FIRE on a corrupted ciphertext (watched red proof)")

	// RED 2: lose the other acknowledged write (simulated data loss).
	only := []knownVersion{lost}
	require.NoError(t, klDecryptKnownWith(enc, gdb, only, w.deleted), "control: the second write is intact")
	require.NoError(t, gdb.Where("secret_node_id = ? AND version_number = ?", lost.nodeID, 1).
		Delete(&models.SecretVersion{}).Error)
	err = klDecryptKnownWith(enc, gdb, only, w.deleted)
	require.ErrorContains(t, err, "MISSING", "oracle(b) must FIRE on a lost acknowledged write (watched red proof)")
	// The model's one allowed miss: a secret whose delete was acknowledged.
	require.NoError(t, klDecryptKnownWith(enc, gdb, only, map[uint]bool{lost.nodeID: true}),
		"a missing version of a DELETED secret is not a violation")
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
		"sweep-outcome-unknown": errors.New("DEK rotation failed: " + klSweepOutcomeUnknownMsg),
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

// TestKLSweepOutcomeUnknownMessageMatchesSource pins klClassifyErr's string match
// to internal/encryption's unexported errSweepOutcomeUnknown: if its wording
// changes, this fails instead of the harness quietly classifying that documented
// outcome as UNEXPECTED.
func TestKLSweepOutcomeUnknownMessageMatchesSource(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "encryption", "keymanager_rotation.go"))
	require.NoError(t, err)
	require.Contains(t, string(src), `errSweepOutcomeUnknown = errors.New("`+klSweepOutcomeUnknownMsg+`")`)
}

// TestKLRedProof_OracleE_Lock exercises oracle (e) on the REAL cross-process
// flock, without disabling production code:
//   - control (green): with NO holder, a rotation SUCCEEDS;
//   - fire: while a child holds the exclusive lock, a concurrent rotation is
//     REFUSED with lock-held (the two never both proceed);
//   - release: after the holder is SIGKILLed, a rotation SUCCEEDS again (a killed
//     holder never blocks forever).
//
// This is a free-vs-held CONTRAST, not a mutation red: the production lock is
// never disabled. A regression making the exclusive lock a no-op would make the
// held-case rotation succeed, which the fire-case assertion would catch.
func TestKLRedProof_OracleE_Lock(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	resetBackupRestoreFlags(t)
	w := klSetupWorld(t, "sqlite", "")

	// control (green): lock free -> rotation succeeds.
	res, out, werr := w.klRunChild("rotate_dek", nil)
	w.klRequireDocumented("rotate_dek", res, out, werr, "redproof-e/free")
	require.Truef(t, res.OK, "control: a rotation with a FREE lock must succeed; out:\n%s", out)

	// fire: a concurrent holder makes a rotation refuse with lock-held.
	hold, _, release := w.klSpawnLockHolder()
	res2, out2, werr2 := w.klRunChild("rotate_dek", nil)
	require.NoError(t, os.WriteFile(release, nil, 0600))
	require.NoError(t, hold.wait(t))
	w.klRequireDocumented("rotate_dek", res2, out2, werr2, "redproof-e/held")
	require.Falsef(t, res2.OK, "oracle(e) FIRE: a rotation must NOT proceed while the lock is held; out:\n%s", out2)
	require.Equal(t, "lock-held", res2.ErrKind)

	// release: a SIGKILLed holder frees the lock; a later rotation succeeds.
	hold2, _, _ := w.klSpawnLockHolder()
	hold2.kill()
	res3, out3, werr3 := w.klRunChild("rotate_dek", nil)
	w.klRequireDocumented("rotate_dek", res3, out3, werr3, "redproof-e/released")
	require.Truef(t, res3.OK, "a killed holder must not block a later rotation forever; out:\n%s", out3)
}

// TestKLRedProof_OracleD_Recovery proves oracle (d) is load-bearing. A real DEK
// rotation child is SIGKILLed right after its sweep transaction COMMITTED and
// before dek.key.pending was promoted (the rotate_dek_pause child; the kill phase
// is asserted, not assumed). Then:
//
//   - RED: the store opened WITHOUT the recovery step (Initialize on the key
//     files as the kill left them, which is what skipping
//     RecoverInterruptedRotation leaves) cannot decrypt the acknowledged write:
//     the rows are under the new DEK and dek.key is still the old one;
//   - GREEN: after the documented recovery command (encryption upgrade-aad /
//     UpgradeAADWithConfig) the new DEK is promoted, no pending file is left, and
//     every acknowledged write decrypts (klStepKillRotate's own assertions plus
//     klVerifySource).
//
// The in-process numbered-checkpoint red/green of the same window is owned by
// internal/encryption (TestRotateDEKWithSweep_KillAfterSweepCommitBeforePromote_
// RecoversCleanly, FuzzDEKSweepCrashConsistency); this one crosses the process
// boundary.
func TestKLRedProof_OracleD_Recovery(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	resetBackupRestoreFlags(t)
	w := klSetupWorld(t, "sqlite", "")
	w.klStepCreate(0)
	require.NotEmpty(t, w.known, "a secret must be acknowledged before the kill")

	dekPath := filepath.Join(w.dir, "dek.key")
	orig, err := os.ReadFile(dekPath)
	require.NoError(t, err)

	// Kill after the sweep commit, before the promote.
	resultFile := filepath.Join(t.TempDir(), "res.json")
	ready := filepath.Join(t.TempDir(), "ready")
	p := w.klSpawn("rotate_dek_pause", resultFile, map[string]string{klEnvPause: klPauseAfterCommit, klEnvReady: ready})
	w.klWaitReady(p, ready, resultFile)
	p.kill()
	require.FileExists(t, dekPath+".pending", "the kill must leave the pending DEK (the phase under test)")
	atKill, err := os.ReadFile(dekPath)
	require.NoError(t, err)
	require.Equal(t, orig, atKill, "the kill must land before the promote")
	require.True(t, w.klRedoMarkerCommitted(), "the kill must land after the sweep committed its redo marker")

	// RED: no recovery -> the acknowledged write does not decrypt.
	cfg := klLoadConfigAt(t, w.dir, w.cfgPath)
	enc := encryption.NewService(&cfg.Storage.Encryption, w.dir)
	if ierr := enc.Initialize(w.passphrase); ierr == nil {
		gdb, gerr := storage.OpenGormDB(cfg)
		require.NoError(t, gerr)
		derr := klDecryptKnownWith(enc, gdb, w.known, w.deleted)
		if sqlDB, e := gdb.DB(); e == nil {
			_ = sqlDB.Close()
		}
		enc.Shutdown()
		require.Error(t, derr, "oracle(b) must FIRE on the killed rotation's store when recovery is skipped (watched red proof)")
		t.Logf("red (no recovery): %v", derr)
	} else {
		enc.Shutdown()
		t.Logf("red (no recovery): the store does not even open: %v", ierr)
	}

	// GREEN: the documented recovery command promotes the new DEK.
	res, out, werr := w.klRunChild("recover", nil)
	w.klRequireDocumented("recover", res, out, werr, "redproof-d/recover")
	require.Truef(t, res.OK, "recovery must succeed: %s; output:\n%s", res.ErrMsg, out)
	require.NoFileExists(t, dekPath+".pending")
	after, err := os.ReadFile(dekPath)
	require.NoError(t, err)
	require.NotEqual(t, orig, after, "recovery must promote the committed rotation's new DEK")
	w.klVerifySource("redproof-d/after-recover")
}
