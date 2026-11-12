// keylifecycle_process_harness_test.go — PROCESS-LEVEL key-lifecycle harness
// (task V3). Key loss is permanent data loss and is least visible at the process
// boundary. The committed metamorphic backup fuzzer drives rotation / passphrase
// change / backup / restore IN PROCESS; in production the CLI runs each as a
// SEPARATE OS process, serialised by the cross-process `dek.lock` flock that the
// in-process fuzzer could not drive (the op-9 limitation documented in
// backup_roundtrip_metamorphic_fuzz_test.go and the fk report; issues #4104/#4105).
//
// This harness drives each lifecycle step as a REAL child process — a re-exec of
// the test binary (os.Args[0]) selecting TestKeyLifecycleChild via -test.run, the
// same mechanism backup_roundtrip_rotation_fork_test.go and
// internal/encryption/keymanager_subprocess_crash_test.go already use (reused, not
// duplicated). Steps: create / update / delete a secret; rotate the DEK (full
// re-encryption sweep); rotate the KEK (passphrase change — a re-wrap with no DB
// re-encryption, the "rotate without sweep" shape); take a backup; restore into a
// fresh store; SIGKILL a rotation child at a fuzz-controlled delay; start a second
// writer while the first holds the exclusive lock; SIGKILL a lock holder; run the
// documented recovery command (`encryption upgrade-aad`, UpgradeAADWithConfig);
// reopen the store.
//
// ORACLES (each with what it does NOT verify in its runner's doc comment):
//   (a) after ANY interleaving or kill the store OPENS, or fails with a documented
//       TYPED error — never a panic / non-zero crash.  [klOracleReopenAndDecrypt]
//   (b) every ACKNOWLEDGED write decrypts to exactly its recorded plaintext; an
//       unacknowledged (killed) write may be present or absent but never corrupt.
//       [klModel + klOracleReopenAndDecrypt]
//   (c) a restore of a (possibly pending-rotation) backup either starts or fails
//       with a documented error, and never yields undecryptable acknowledged
//       secrets.  [klStepRestore + klOracleReopenAndDecrypt over the restore dir]
//   (d) no manual hand-repair (#4105): after the documented recovery command the
//       store is fully usable.  [klStepKillRotate -> klStepRecover]
//   (e) the lock: two concurrent rotations never both proceed, and a killed holder
//       never leaves a lock that blocks forever.  [klStepConcurrentRotate,
//       klStepKillLockHolder]
//
// Backends: SQLite always; PostgreSQL when KEYORIX_TEST_PG_DSN is set (databases
// named v3_*, dropped on cleanup).
//
// Not t.Parallel(): mutates package-level cobra flag vars and os.Chdir, matching
// this package's convention. Child processes are bounded by a context timeout.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// ---------------------------------------------------------------------------
// Child-process protocol
// ---------------------------------------------------------------------------

const (
	klEnvChild      = "KL_CHILD"        // "1" => this process is a child helper
	klEnvOp         = "KL_OP"           // the operation to run
	klEnvCfg        = "KL_CFG"          // config path (loadConfig reads configPathFlag)
	klEnvDir        = "KL_DIR"          // world dir (key files resolved relative to CWD)
	klEnvResult     = "KL_RESULT"       // path to write the JSON klResult to
	klEnvProjID     = "KL_PROJ"         // create: target project id
	klEnvEnvID      = "KL_ENV"          // create: target environment id
	klEnvNodeID     = "KL_NODE"         // update/delete: target secret node id
	klEnvName       = "KL_NAME"         // create: secret name
	klEnvValueFile  = "KL_VALUE_FILE"   // create/update: file holding the plaintext bytes
	klEnvArchive    = "KL_ARCHIVE"      // backup/restore: archive path
	klEnvRestoreDir = "KL_RESTORE_DIR"  // restore: target dir
	klEnvHoldMS     = "KL_HOLD_MS"      // holdlock: ms to sleep while holding the lock
	klMasterPassEnv = "KEYORIX_MASTER_PASSWORD"
	klErrExit       = 87 // child exits non-zero only on an UNEXPECTED, un-writable-result crash
)

// klResult is the structured outcome a child writes to KL_RESULT before exiting 0.
// A child that PANICS or cannot even write this file exits non-zero with no file —
// the parent treats that (outside a kill step) as an oracle-(a) violation.
type klResult struct {
	OK      bool   `json:"ok"`
	ErrKind string `json:"errKind"` // "" on success; a documented kind or "UNEXPECTED"
	ErrMsg  string `json:"errMsg"`
	NodeID  uint   `json:"nodeID"`
	ProjID  uint   `json:"projID"`
	Version int    `json:"version"`
	Stdout  string `json:"stdout"`
}

// klClassifyErr maps a child-side error to a documented error KIND (oracle a/c
// accept-list) or "UNEXPECTED". The kinds correspond 1:1 to the exported typed
// errors an open/rotate may legitimately return; anything else is a violation.
func klClassifyErr(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.As(err, new(*encryption.KeyDirMissingError)):
		return "key-dir-missing"
	case errors.Is(err, syscall.EWOULDBLOCK):
		return "lock-held"
	case errors.Is(err, encryption.ErrDEKEpochMismatch):
		return "epoch-mismatch"
	case errors.Is(err, encryption.ErrDEKWriteFenced):
		return "write-fenced"
	case errors.Is(err, encryption.ErrSweepVerification):
		return "sweep-verify"
	case errors.Is(err, encryption.ErrRotationProtocolTooOld):
		return "protocol-too-old"
	case strings.Contains(err.Error(), "the re-encryption sweep may have committed"):
		// errSweepOutcomeUnknown is unexported; match its stable message. This is a
		// documented outcome: the pending DEK is kept and recovery promotes it.
		return "sweep-outcome-unknown"
	default:
		return "UNEXPECTED"
	}
}

// klDocumentedKinds is the set of error kinds a step may surface without being a
// bug. Keyed by kind; the harness only ever asserts a kind is in here (never
// re-asserts the message), so the accept-list is the single source of truth.
var klDocumentedKinds = map[string]bool{
	"":                      true, // success
	"key-dir-missing":       true,
	"lock-held":             true,
	"epoch-mismatch":        true,
	"write-fenced":          true,
	"sweep-verify":          true,
	"protocol-too-old":      true,
	"sweep-outcome-unknown": true,
}

// ---------------------------------------------------------------------------
// Parent-side world + model
// ---------------------------------------------------------------------------

// klWorld is one backend's on-disk source store (key dir + config + DB), kept
// alive ACROSS child steps. The parent owns no live DB/encryption handle between
// steps, so a child can always take the exclusive lock.
type klWorld struct {
	t          *testing.T
	backend    string
	dir        string
	cfgPath    string
	projID     uint
	envID      uint
	passphrase string         // current master passphrase (a KEK rotation changes it)
	known      []knownVersion // the acknowledged-write model (oracle b)
	seq        int
	pgBaseDSN  string
	lastBackup *klBackup // most recent successful backup (archive + its passphrase/known)
}

func (w *klWorld) next() int { w.seq++; return w.seq }

// klSetupWorld builds a fresh encrypted store with one project + environment + a
// pre-created actor user, then closes every handle so children own the key dir.
func klSetupWorld(t *testing.T, backend, pgBaseDSN string) *klWorld {
	t.Helper()
	dir := t.TempDir()
	chdirTest(t, dir)

	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	enc := encryption.NewService(encCfg, dir)
	require.NoError(t, enc.Initialize(roundTripPassphrase))

	cfgPath := klConfigureBackend(t, backend, dir, pgBaseDSN)
	configPathFlag = cfgPath
	cfg, err := loadConfig()
	require.NoError(t, err)
	store, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	c := core.NewKeyorixCore(store)
	c.SetSecretValueEncryptor(enc)
	require.True(t, c.SecretValueEncryptionActive())

	ctx := context.Background()
	// Raw-insert actor so backup's dangling-reference check is satisfied and no
	// audit event of its own is written (matches the metamorphic harness).
	actor := &models.User{Username: "kl-actor", UsernameFolded: "kl-actor"}
	require.NoError(t, gdb.Create(actor).Error)
	p, err := c.CreateProject(ctx, "kl-proj", "key-lifecycle world")
	require.NoError(t, err)
	envs, err := c.ListEnvironmentsByProject(ctx, p.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	// Release everything so the first child can take the exclusive lock.
	enc.Shutdown()
	if sqlDB, derr := gdb.DB(); derr == nil {
		_ = sqlDB.Close()
	}
	if closer, ok := store.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	return &klWorld{
		t: t, backend: backend, dir: dir, cfgPath: cfgPath,
		projID: p.ID, envID: envs[0].ID, passphrase: roundTripPassphrase, pgBaseDSN: pgBaseDSN,
	}
}

// klConfigureBackend writes a config for backend rooted at dir. Postgres databases
// are named v3_<pid>_<n> (task-mandated prefix), dropped on cleanup — distinct
// from the metamorphic fuzzer's bk_ prefix so the two never collide.
func klConfigureBackend(t *testing.T, backend, dir, pgBaseDSN string) string {
	t.Helper()
	switch backend {
	case "sqlite":
		return writeBackupRestoreTestConfig(t, dir, filepath.Join(dir, "secrets.db"))
	case "postgres":
		return writePostgresBackupRestoreTestConfig(t, dir, klPgIsolatedDSN(t, pgBaseDSN))
	default:
		t.Fatalf("unknown backend %q", backend)
		return ""
	}
}

// ---------------------------------------------------------------------------
// Child invocation
// ---------------------------------------------------------------------------

// klChildTimeout bounds a single child so a hang is a failure, not a stall. Set
// generously (timeouts detect hangs, they do not enforce speed) — a rotation sweep
// over a tiny DB is sub-second; 90s leaves ample headroom under a loaded host.
const klChildTimeout = 90 * time.Second

func klChildEnv(op, dir, cfgPath, resultFile, passphrase string, extra map[string]string) []string {
	// Strip any inherited KL_* and the passphrase vars so a child never sees a
	// parent's stale selector or a duplicate (ambiguous) passphrase.
	base := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "KL_") ||
			strings.HasPrefix(kv, klMasterPassEnv+"=") ||
			strings.HasPrefix(kv, encryptionops.NewMasterPassphraseEnvVar+"=") {
			continue
		}
		base = append(base, kv)
	}
	set := map[string]string{
		klEnvChild:      "1",
		klEnvOp:         op,
		klEnvCfg:        cfgPath,
		klEnvDir:        dir,
		klEnvResult:     resultFile,
		klMasterPassEnv: passphrase,
	}
	for k, v := range extra {
		set[k] = v // extra wins (e.g. a restore's archive-time passphrase override)
	}
	for k, v := range set {
		base = append(base, k+"="+v)
	}
	return base
}

// klStartChild builds (does not Start) a child command for op, rooted at workDir
// with cfgPath as its config. The caller Starts it, so kill steps can control its
// lifetime.
func (w *klWorld) klStartChild(op, workDir, cfgPath, resultFile string, extra map[string]string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestKeyLifecycleChild$", "-test.count=1") // #nosec G204 -- the test binary itself
	cmd.Dir = workDir
	cmd.Env = klChildEnv(op, workDir, cfgPath, resultFile, w.passphrase, extra)
	return cmd
}

// klRunChild runs op to completion and returns the parsed result, the child's raw
// combined output (diagnostics) and the process's exit error (nil on exit 0). It
// never fails the test; the caller classifies. A missing result file is signalled
// by a sentinel klResult{ErrKind: klNoResult}.
const klNoResult = "NO-RESULT-FILE"

func (w *klWorld) klRunChild(op string, extra map[string]string) (klResult, string, error) {
	return w.klRunChildIn(op, w.dir, w.cfgPath, extra)
}

// klRunChildIn is klRunChild with an explicit working dir + config (restore runs
// against a fresh target dir, not the source).
func (w *klWorld) klRunChildIn(op, workDir, cfgPath string, extra map[string]string) (klResult, string, error) {
	resultFile := filepath.Join(w.t.TempDir(), "res.json")
	cmd := w.klStartChild(op, workDir, cfgPath, resultFile, extra)
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	ctx, cancel := context.WithTimeout(context.Background(), klChildTimeout)
	defer cancel()
	done := make(chan error, 1)
	require.NoError(w.t, cmd.Start())
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
		waitErr = fmt.Errorf("child %q timed out after %s", op, klChildTimeout)
	case waitErr = <-done:
	}
	res, rerr := klReadResult(resultFile)
	if rerr != nil {
		return klResult{ErrKind: klNoResult}, buf.String(), waitErr
	}
	return res, buf.String(), waitErr
}

func klReadResult(path string) (klResult, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		return klResult{}, err
	}
	var r klResult
	if err := json.Unmarshal(b, &r); err != nil {
		return klResult{}, err
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// The child entry point (runs only when KL_CHILD=1)
// ---------------------------------------------------------------------------

// TestKeyLifecycleChild is NOT a test: re-exec'd by klStartChild with KL_CHILD=1,
// it performs exactly one lifecycle op against the config/dir the parent named and
// writes a klResult to KL_RESULT. It exits 0 on both success AND a documented
// typed error (the parent reads the kind from the result); it exits non-zero only
// on a crash it cannot describe. A parent SIGKILL leaves no result file — expected
// for a kill step.
func TestKeyLifecycleChild(t *testing.T) {
	if os.Getenv(klEnvChild) != "1" {
		t.Skip("child-process helper for the key-lifecycle process harness")
	}
	require.NoError(t, i18n.InitializeForTesting())
	dir := os.Getenv(klEnvDir)
	if dir != "" {
		_ = os.Chdir(dir)
	}
	configPathFlag = os.Getenv(klEnvCfg)
	resultFile := os.Getenv(klEnvResult)
	op := os.Getenv(klEnvOp)

	res := klChildDispatch(t, op)
	b, _ := json.Marshal(res)
	if err := os.WriteFile(resultFile, b, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "child %q: write result: %v\n", op, err)
		os.Exit(klErrExit)
	}
	os.Exit(0)
}

func klChildDispatch(t *testing.T, op string) klResult {
	cfg, err := loadConfig()
	if err != nil {
		return klResult{ErrKind: klClassifyErr(err), ErrMsg: fmt.Sprintf("loadConfig: %v", err)}
	}
	switch op {
	case "create":
		return klChildCreate(t, cfg)
	case "update":
		return klChildUpdate(t, cfg)
	case "delete":
		return klChildDelete(t, cfg)
	case "rotate_dek":
		err := encryptionops.RotateWithConfig(cfg, true, false, crypto.PassphraseSource{})
		return klResultFromErr(err)
	case "rotate_kek":
		err := encryptionops.RotateKEKWithConfig(cfg, true, crypto.PassphraseSource{}, crypto.PassphraseSource{})
		return klResultFromErr(err)
	case "recover":
		// The documented recovery command (runbook §6): a key-writing command that
		// finishes an interrupted rotation first. Does not change the DEK.
		err := encryptionops.UpgradeAADWithConfig(cfg, crypto.PassphraseSource{})
		return klResultFromErr(err)
	case "backup":
		return klChildBackup(t, os.Getenv(klEnvArchive))
	case "restore":
		return klChildRestore(t, os.Getenv(klEnvArchive))
	case "holdlock":
		return klChildHoldLock(t, cfg)
	default:
		return klResult{ErrKind: "UNEXPECTED", ErrMsg: "unknown op " + op}
	}
}

func klResultFromErr(err error) klResult {
	if err == nil {
		return klResult{OK: true}
	}
	return klResult{ErrKind: klClassifyErr(err), ErrMsg: err.Error()}
}

// klChildOpenCore opens storage + core + an initialized encryption service in the
// child for a secret mutation. Caller closes via the returned cleanup.
func klChildOpenCore(cfg *config.Config) (*core.KeyorixCore, func(), error) {
	dir := os.Getenv(klEnvDir)
	enc := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := enc.Initialize(os.Getenv(klMasterPassEnv)); err != nil {
		return nil, func() {}, err
	}
	store, err := storage.NewStorageFactory().CreateStorage(cfg)
	if err != nil {
		enc.Shutdown()
		return nil, func() {}, err
	}
	c := core.NewKeyorixCore(store)
	c.SetSecretValueEncryptor(enc)
	cleanup := func() {
		enc.Shutdown()
		if closer, ok := store.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
	return c, cleanup, nil
}

func klChildCreate(t *testing.T, cfg *config.Config) klResult {
	c, cleanup, err := klChildOpenCore(cfg)
	if err != nil {
		return klResultFromErr(err)
	}
	defer cleanup()
	pt, err := os.ReadFile(os.Getenv(klEnvValueFile)) // #nosec G304 -- test path
	if err != nil {
		return klResult{ErrKind: "UNEXPECTED", ErrMsg: err.Error()}
	}
	pid := klAtoiU(os.Getenv(klEnvProjID))
	eid := klAtoiU(os.Getenv(klEnvEnvID))
	node, err := c.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: os.Getenv(klEnvName), Value: pt, ProjectID: pid, EnvironmentID: eid,
		Type: "password", CreatedBy: "kl",
	})
	if err != nil {
		return klResultFromErr(err)
	}
	return klResult{OK: true, NodeID: node.ID, ProjID: pid, Version: 1}
}

func klChildUpdate(t *testing.T, cfg *config.Config) klResult {
	c, cleanup, err := klChildOpenCore(cfg)
	if err != nil {
		return klResultFromErr(err)
	}
	defer cleanup()
	pt, err := os.ReadFile(os.Getenv(klEnvValueFile)) // #nosec G304 -- test path
	if err != nil {
		return klResult{ErrKind: "UNEXPECTED", ErrMsg: err.Error()}
	}
	nid := klAtoiU(os.Getenv(klEnvNodeID))
	if _, err := c.UpdateSecret(context.Background(), &core.UpdateSecretRequest{ID: nid, Value: pt, UpdatedBy: "kl"}); err != nil {
		return klResultFromErr(err)
	}
	return klResult{OK: true, NodeID: nid}
}

func klChildDelete(t *testing.T, cfg *config.Config) klResult {
	c, cleanup, err := klChildOpenCore(cfg)
	if err != nil {
		return klResultFromErr(err)
	}
	defer cleanup()
	nid := klAtoiU(os.Getenv(klEnvNodeID))
	_ = c.DeleteSecret(context.Background(), nid)
	return klResult{OK: true, NodeID: nid}
}

func klChildBackup(t *testing.T, archive string) klResult {
	backupOutput = archive
	backupExclusive = false
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	if err != nil {
		r := klResultFromErr(err)
		r.Stdout = out
		return r
	}
	return klResult{OK: true, Stdout: out}
}

func klChildRestore(t *testing.T, archive string) klResult {
	// The child is already chdir'd to a FRESH restore dir (cmd.Dir) with its own
	// target config (configPathFlag=KL_CFG), so the restored key files land there.
	restoreInput = archive
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	if err != nil {
		r := klResultFromErr(err)
		r.Stdout = out
		return r
	}
	return klResult{OK: true, Stdout: out}
}

// klChildHoldLock acquires the exclusive key lock (the same lock a rotation holds)
// and sleeps KL_HOLD_MS, to simulate a long-running writer the parent can race or
// kill. It never touches the DB, so it is a clean lock-contention probe.
func klChildHoldLock(t *testing.T, cfg *config.Config) klResult {
	dir := os.Getenv(klEnvDir)
	enc := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := enc.AcquireExclusiveKeyLock(); err != nil {
		return klResultFromErr(err)
	}
	defer enc.Shutdown()
	ms := klAtoiU(os.Getenv(klEnvHoldMS))
	// Signal "lock acquired" by writing the result file BEFORE sleeping, so the
	// parent can wait on readiness. We still hold the lock for the sleep.
	res := klResult{OK: true}
	b, _ := json.Marshal(res)
	_ = os.WriteFile(os.Getenv(klEnvResult), b, 0600)
	time.Sleep(time.Duration(ms) * time.Millisecond)
	return res
}

// klPgCounter + klPgIsolatedDSN create per-run Postgres databases named
// v3_<pid>_<n> (task-mandated prefix), dropped on cleanup.
var klPgCounter atomic.Int64

func klPgIsolatedDSN(t *testing.T, base string) string {
	t.Helper()
	n := klPgCounter.Add(1)
	dbName := fmt.Sprintf("v3_%d_%d", os.Getpid(), n)
	admin := pgAdminRawOpen(t, base)
	require.NoError(t, admin.Exec("CREATE DATABASE "+dbName).Error) //nolint:gosec // pid+counter generated name, not external input
	t.Cleanup(func() {
		cleaner := pgAdminRawOpen(t, base)
		_ = cleaner.Exec("DROP DATABASE IF EXISTS " + dbName + " WITH (FORCE)").Error
	})
	return pgdsn.PGReplaceDBName(base, dbName)
}

func klAtoiU(s string) uint {
	var n uint
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + uint(r-'0')
	}
	return n
}
