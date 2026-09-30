//go:build !windows

package encryption

// keymanager_subprocess_crash_test.go — SESSION-AT AT2's subprocess crash
// harness: proves DEK-rotation file-durability recovery holds under a REAL
// process exit, complementing (not replacing) the existing in-process panic
// fuzz trilogy (FuzzDEKSweepCrashConsistency and siblings), which is strong
// on state-space coverage but never actually terminates the process, so it
// can't catch a bug that only lives in real process-exit semantics (or in
// recovery logic wired at the CLI/main() layer rather than inside the
// function under test).
//
// Technique: the test binary re-execs ITSELF (os.Args[0], the same
// `go test` binary) with `-test.run=^TestCrashHelperProcess$` and an env var
// telling that invocation to act as a crash-test worker instead of running
// the normal test suite -- the standard Go idiom for "a test needs a real
// separate OS process" (used by the Go stdlib itself, e.g. os/exec_test.go).
// This is deliberately NOT a full `keyorix-server` binary/CLI invocation:
// building and driving the real CLI (config file, passphrase prompts,
// server-lock acquisition) would multiply the setup surface for no extra
// proof value at the file-durability layer this harness targets.
//
// Production-safety note (coordinator review on this PR's first version,
// fixed here): the crash-point seam lives ENTIRELY inside this test file.
// TestCrashHelperProcess installs rotationCheckpoint itself (a real
// os.Exit(137) on label match) only when it is invoked as the crash-test
// subprocess -- the exact same nil-in-production seam
// FuzzKEKRotationCrashConsistency already uses to install a panic. The
// first version of this PR instead added a package-level, env-var-gated
// os.Exit(137) directly inside internal/encryption's own
// rotationCheckpointHook (a new internal/crashpoint package with no build
// tag) -- that code had no way to distinguish "a test subprocess set this
// env var on purpose" from "this variable happens to be set in a
// production server's environment for an unrelated reason," and shipped in
// every release binary. Reverted entirely; rotation_crash_hooks.go is back
// to exactly what it was before this PR touched it.
//
// Caveat, stated plainly: os.Exit(137) is a normal process exit, not a
// power-loss simulation -- it skips Go-level deferred cleanup (which is
// what this harness is actually testing: does the NEXT process see a
// recoverable state), but the OS page cache is not dropped the way it
// would be on a real power loss, so this harness says nothing about fsync
// correctness beyond what the code path being exercised already does
// (RotateDEKWithSweep's own securefiles.SyncDir calls, unmodified by this
// test). A real power-loss / fsync-miss scenario is outside what any
// in-process or same-machine-subprocess technique can produce.
//
// Known gap, stated plainly (not fixed in this PR): the "check" step's
// promote/clean decision is supplied directly by the test driver (it
// already knows which checkpoint it crashed at), NOT derived from
// Service.RecoverInterruptedRotation's real DB-backed redo-marker logic
// (service_rotation.go) -- this minimal KeyManager-level harness has no DB
// (see the package-level scope note above). That means the REAL recovery
// decision function is untested by this harness; only the two outcomes it
// can produce (promote a still-present pending file, or discard it) are
// exercised, using KeyManager's own PromotePendingDEK/CleanPendingDEK
// directly. A DB-backed harness that exercises RecoverInterruptedRotation
// itself is real follow-up work.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	envHelper         = "KEYORIX_CRASHTEST_HELPER"
	envKeyDir         = "KEYORIX_CRASHTEST_KEYDIR"
	envPassword       = "KEYORIX_CRASHTEST_PASSPHRASE"
	envAction         = "KEYORIX_CRASHTEST_ACTION"   // "init" | "rotate" | "check"
	envPromote        = "KEYORIX_CRASHTEST_PROMOTE"  // "1" -> check calls PromotePendingDEK; else CleanPendingDEK
	envCrashAt        = "KEYORIX_CRASHTEST_CRASH_AT" // checkpoint label to os.Exit(137) at, or unset
	crashPass         = "crash-harness-static-passphrase-32b"
	canaryPlain       = "AT2-crash-harness-canary-plaintext"
	subprocessTimeout = 15 * time.Second
)

// canaryPath is where the "init" action leaves a DEK-encrypted canary the
// "check" action must be able to decrypt back to canaryPlain. This is the
// property that actually matters: not "some 32-byte DEK loaded" (which a
// silent-regenerate-on-missing-file bug would also satisfy, wrongly passing
// this harness — caught during this session's own red-proof run, see the PR
// body) but "the SAME key material that encrypted this data before the
// crash is still what's active after recovery."
func canaryPath(keyDir string) string { return filepath.Join(keyDir, "canary.enc.json") }

// childEnv builds the subprocess environment from the CURRENT process's own
// environment with every KEYORIX_CRASHTEST_* variable (including envCrashAt)
// stripped first, then this call's own values added back — so a crash var
// inherited from an unrelated outer invocation (e.g. this whole test binary
// itself having been launched with one of these set, however unlikely)
// can never leak into a child that wasn't given it explicitly.
func childEnv(pairs ...string) []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "KEYORIX_CRASHTEST_") || strings.HasPrefix(kv, envCrashAt+"=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, pairs...)
}

// runHelperSubprocess execs this same test binary as a fresh OS process
// running only TestCrashHelperProcess, with the given action and (for the
// "rotate" action) a crash-point label. Returns the process's exit code and
// combined output. Bounded by subprocessTimeout so a hang in the child
// (e.g. a bug that blocks instead of crashing) fails this test instead of
// the whole `go test` run.
func runHelperSubprocess(t *testing.T, keyDir, action, crashLabel string, promote bool) (exitCode int, output string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), subprocessTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashHelperProcess$", "-test.v=false") // #nosec G204 -- os.Args[0] is this test binary itself, not attacker input
	env := []string{
		envHelper + "=1",
		envKeyDir + "=" + keyDir,
		envPassword + "=" + crashPass,
		envAction + "=" + action,
	}
	if crashLabel != "" {
		env = append(env, envCrashAt+"="+crashLabel)
	}
	if promote {
		env = append(env, envPromote+"=1")
	}
	cmd.Env = childEnv(env...)
	out, err := cmd.CombinedOutput()
	output = string(out)
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("subprocess (action=%s) exceeded %s -- possible hang", action, subprocessTimeout)
	}
	if err == nil {
		return 0, output
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), output
	}
	t.Fatalf("subprocess failed to start: %v (output: %s)", err, output)
	return -1, output
}

// TestCrashHelperProcess is not a real test from the top-level test run's
// point of view: it does nothing (returns immediately) unless
// KEYORIX_CRASHTEST_HELPER=1 is set, which only runHelperSubprocess sets.
// When active, it performs exactly one KeyManager action against
// KEYORIX_CRASHTEST_KEYDIR and exits 0 on success. For the "rotate" action,
// if KEYORIX_CRASHTEST_CRASH_AT is set, it installs rotationCheckpoint
// itself (real os.Exit(137) on an exact label match) before calling
// RotateDEKWithSweep — the same nil-in-production seam
// FuzzKEKRotationCrashConsistency already uses, installed from a test, not
// from production code.
func TestCrashHelperProcess(t *testing.T) {
	if os.Getenv(envHelper) != "1" {
		t.Skip("not invoked as a crash-test helper subprocess")
	}
	keyDir := os.Getenv(envKeyDir)
	pass := os.Getenv(envPassword)
	action := os.Getenv(envAction)
	crashAt := os.Getenv(envCrashAt)

	km := NewKeyManager(keyDir, "dek.key", "kek.salt")

	switch action {
	case "init":
		if err := km.Initialize(pass); err != nil {
			fmt.Fprintln(os.Stderr, "init failed:", err)
			os.Exit(1)
		}
		es, err := NewEncryptionService(km.currentDEK)
		if err != nil {
			fmt.Fprintln(os.Stderr, "canary encryption service failed:", err)
			os.Exit(1)
		}
		enc, err := es.Encrypt([]byte(canaryPlain), "v1")
		if err != nil {
			fmt.Fprintln(os.Stderr, "canary encrypt failed:", err)
			os.Exit(1)
		}
		blob, err := json.Marshal(enc)
		if err != nil {
			fmt.Fprintln(os.Stderr, "canary marshal failed:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(canaryPath(keyDir), blob, 0600); err != nil { // #nosec G306 -- test-only scratch fixture, not production key material
			fmt.Fprintln(os.Stderr, "canary write failed:", err)
			os.Exit(1)
		}
	case "rotate":
		if crashAt != "" {
			rotationCheckpoint = func(label string) {
				if label == crashAt {
					os.Exit(137)
				}
			}
		}
		if err := km.Initialize(pass); err != nil {
			fmt.Fprintln(os.Stderr, "pre-rotate init failed:", err)
			os.Exit(1)
		}
		if err := km.RotateDEKWithSweep(pass, func(oldSvc, newSvc *EncryptionService, newKeyVersion string) error {
			// Mirrors what a real production sweepFn does to every DB row (re-encrypt
			// old-DEK ciphertext under the new DEK) applied to the canary file instead of
			// a database -- there is no DB in this minimal file-durability harness (see
			// the package doc's scope note), but the canary must still go through a real
			// decrypt-under-old/encrypt-under-new step for the post-rotation continuity
			// check below to mean anything.
			raw, err := os.ReadFile(canaryPath(keyDir)) // #nosec G304 -- fixed path under this test's own TempDir
			if err != nil {
				return fmt.Errorf("sweepFn: read canary: %w", err)
			}
			var enc EncryptedData
			if err := json.Unmarshal(raw, &enc); err != nil {
				return fmt.Errorf("sweepFn: unmarshal canary: %w", err)
			}
			plain, err := oldSvc.Decrypt(&enc)
			if err != nil {
				return fmt.Errorf("sweepFn: decrypt canary under old DEK: %w", err)
			}
			reenc, err := newSvc.Encrypt(plain, newKeyVersion)
			if err != nil {
				return fmt.Errorf("sweepFn: re-encrypt canary under new DEK: %w", err)
			}
			blob, merr := json.Marshal(reenc)
			if merr != nil {
				return fmt.Errorf("sweepFn: marshal re-encrypted canary: %w", merr)
			}
			return os.WriteFile(canaryPath(keyDir), blob, 0600) // #nosec G306 -- test-only scratch fixture
		}); err != nil {
			fmt.Fprintln(os.Stderr, "rotate failed:", err)
			os.Exit(1)
		}
	case "check":
		// Mirrors Service.RecoverInterruptedRotation's decision (service_rotation.go):
		// in production this branches on a DB "redo marker" written in the SAME
		// transaction as the sweep commit, so it can tell "sweepFn committed, promote
		// the still-present pending file" apart from "sweepFn never ran, discard it".
		// This minimal harness has no DB (see the file doc's known-gap note), so the
		// test driver passes the equivalent decision directly via KEYORIX_CRASHTEST_PROMOTE
		// -- it already knows which checkpoint it crashed at, which is exactly the
		// same fact the DB marker would encode; the REAL RecoverInterruptedRotation
		// decision logic is NOT exercised by this harness. PromotePendingDEK/
		// CleanPendingDEK are both real, unmodified, and safe to call unconditionally
		// when the pending file they'd act on isn't present (both documented as
		// no-ops in that case).
		if os.Getenv(envPromote) == "1" {
			if err := km.PromotePendingDEK(); err != nil {
				fmt.Fprintln(os.Stderr, "check: PromotePendingDEK failed:", err)
				os.Exit(1)
			}
		} else {
			km.CleanPendingDEK()
		}
		if _, err := os.Stat(filepath.Join(keyDir, "dek.key.pending")); err == nil {
			fmt.Fprintln(os.Stderr, "check: dek.key.pending still present after recovery -- a real restart's CleanPendingDEK/PromotePendingDEK pass should always leave zero pending files behind")
			os.Exit(1)
		}
		// A fresh KeyManager instance, as a real restart would create, must be able
		// to load and unwrap whatever dek.key is currently on disk -- the invariant
		// that must hold no matter which checkpoint a prior run was crashed at.
		if err := km.Initialize(pass); err != nil {
			fmt.Fprintln(os.Stderr, "check (post-crash reload) failed:", err)
			os.Exit(1)
		}
		if km.currentDEK == nil || len(km.currentDEK) != 32 {
			fmt.Fprintln(os.Stderr, "check: DEK did not load correctly")
			os.Exit(1)
		}
		es, err := NewEncryptionService(km.currentDEK)
		if err != nil {
			fmt.Fprintln(os.Stderr, "check: encryption service from recovered DEK failed:", err)
			os.Exit(1)
		}
		raw, err := os.ReadFile(canaryPath(keyDir)) // #nosec G304 -- fixed path under this test's own TempDir
		if err != nil {
			fmt.Fprintln(os.Stderr, "check: read canary failed:", err)
			os.Exit(1)
		}
		var enc EncryptedData
		if err := json.Unmarshal(raw, &enc); err != nil {
			fmt.Fprintln(os.Stderr, "check: unmarshal canary failed:", err)
			os.Exit(1)
		}
		plain, err := es.Decrypt(&enc)
		if err != nil {
			fmt.Fprintln(os.Stderr, "check: canary does not decrypt under the recovered DEK -- data would be UNRECOVERABLE:", err)
			os.Exit(1)
		}
		if string(plain) != canaryPlain {
			fmt.Fprintln(os.Stderr, "check: canary decrypted to the WRONG plaintext:", string(plain))
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown action:", action)
		os.Exit(2)
	}
	os.Exit(0)
}

// sweepCheckpointCallRe finds every rotationCheckpointHook("sweep:...") call
// site in keymanager_rotation.go, so TestSweepCheckpointLabelsAreComplete
// can fail if a checkpoint is added/removed/renamed there without this
// file's own `cases` table being updated to match — the same "derive it,
// don't hand-type it and hope" discipline the rest of this codebase's
// generated/checked TSVs follow.
var sweepCheckpointCallRe = regexp.MustCompile(`rotationCheckpointHook\("(sweep:[^"]+)"\)`)

func realSweepCheckpointLabels(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("keymanager_rotation.go")
	if err != nil {
		t.Fatalf("reading keymanager_rotation.go: %v", err)
	}
	var labels []string
	for _, m := range sweepCheckpointCallRe.FindAllStringSubmatch(string(data), -1) {
		labels = append(labels, m[1])
	}
	return labels
}

// TestSweepCheckpointLabelsAreComplete fails if TestDEKRotationSubprocessCrashRecovery's
// own `cases` table (hand-typed) has drifted from the REAL checkpoint labels
// RotateDEKWithSweep emits — a checkpoint added, removed, or renamed in
// keymanager_rotation.go without updating this file's cases table would
// otherwise silently under-test (or reference a label that can never fire).
func TestSweepCheckpointLabelsAreComplete(t *testing.T) {
	real := realSweepCheckpointLabels(t)
	if len(real) == 0 {
		t.Fatal("found zero rotationCheckpointHook(\"sweep:...\") call sites in keymanager_rotation.go -- regex or file path broke")
	}
	tested := make(map[string]bool, len(sweepCheckpointCases))
	for _, c := range sweepCheckpointCases {
		tested[c.label] = true
	}
	for _, label := range real {
		if !tested[label] {
			t.Errorf("keymanager_rotation.go emits checkpoint %q but TestDEKRotationSubprocessCrashRecovery's cases table does not test it", label)
		}
	}
	if len(real) != len(sweepCheckpointCases) {
		t.Errorf("keymanager_rotation.go has %d sweep: checkpoints but the cases table has %d entries -- counts should match 1:1", len(real), len(sweepCheckpointCases))
	}
}

// sweepCheckpointCases mirrors RotateDEKWithSweep's real checkpoints, in
// order, with each one's correct recovery decision (see the "check" case's
// own comment on what promote means and its known-gap caveat).
// TestSweepCheckpointLabelsAreComplete keeps this in sync with
// keymanager_rotation.go's actual rotationCheckpointHook call sites.
var sweepCheckpointCases = []struct {
	label   string
	promote bool
}{
	{"sweep:after-write-dek-pending", false},
	{"sweep:after-sweep-commit", true},
	{"sweep:after-rename-dek", true},
	{"sweep:after-syncdir", true},
}

// TestDEKRotationSubprocessCrashRecovery is the actual AT2 harness test.
// For each of RotateDEKWithSweep's real checkpoints, it: (1) seeds a DEK via
// a clean "init" subprocess, (2) runs a "rotate" subprocess with
// KEYORIX_CRASHTEST_CRASH_AT set to that checkpoint, asserting it dies with
// exit 137 (proves the checkpoint is actually reachable, not silently
// skipped), (3) runs a "check" subprocess (a THIRD, entirely fresh process)
// that must recover a DEK able to decrypt a canary back to its original
// plaintext, and leave no dek.key.pending behind.
func TestDEKRotationSubprocessCrashRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real subprocesses per checkpoint; skipped under -short")
	}
	for _, tc := range sweepCheckpointCases {
		t.Run(tc.label, func(t *testing.T) {
			keyDir := t.TempDir()

			if code, out := runHelperSubprocess(t, keyDir, "init", "", false); code != 0 {
				t.Fatalf("seed init subprocess failed (exit %d): %s", code, out)
			}

			code, out := runHelperSubprocess(t, keyDir, "rotate", tc.label, false)
			if code != 137 {
				t.Fatalf("rotate subprocess at checkpoint %q: expected exit 137, got %d (output: %s)", tc.label, code, out)
			}

			if code, out := runHelperSubprocess(t, keyDir, "check", "", tc.promote); code != 0 {
				t.Fatalf("post-crash check subprocess at checkpoint %q FAILED (exit %d) -- the install is bricked (or data unrecoverable) after a crash at this step: %s", tc.label, code, out)
			}
		})
	}
}
