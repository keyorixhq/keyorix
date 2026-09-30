//go:build !windows

package encryption

// keymanager_subprocess_crash_test.go — SESSION-AT AT2's subprocess crash
// harness: proves DEK-rotation file-durability recovery holds under a REAL
// process exit, complementing (not replacing) the existing in-process panic
// fuzz trilogy (FuzzDEKSweepCrashConsistency and siblings), which is strong
// on state-space coverage but never actually exits the process, so it can't
// catch a bug that only lives in real process-exit/OS-buffer-flush
// semantics.
//
// Technique: the test binary re-execs ITSELF (os.Args[0], the same
// `go test` binary) with `-test.run=^TestCrashHelperProcess$` and an env var
// telling that invocation to act as a crash-test worker instead of running
// the normal test suite -- the standard Go idiom for "a test needs a real
// separate OS process" (used by the Go stdlib itself, e.g. os/exec_test.go).
// This is deliberately NOT a full `keyorix-server` binary/CLI invocation:
// building and driving the real CLI (config file, passphrase prompts,
// server-lock acquisition) would multiply the setup surface for no extra
// proof value at the file-durability layer this harness targets. Stated as
// a scope choice, not an oversight -- see the PR body / SESSION-AT report
// for the same note.
//
// TestCrashHelperProcess IS the "makes the process exit(137)-equivalent at
// a named step" hook's CONSUMER: it calls the real, unmodified
// KeyManager.Initialize / RotateDEKWithSweep, and crashpoint.Hit (wired into
// rotationCheckpointHook, see rotation_crash_hooks.go) does the actual
// os.Exit(137) when KEYORIX_TEST_CRASH_AT_STEP matches the current
// checkpoint label.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const (
	envHelper   = "KEYORIX_CRASHTEST_HELPER"
	envKeyDir   = "KEYORIX_CRASHTEST_KEYDIR"
	envPassword = "KEYORIX_CRASHTEST_PASSPHRASE"
	envAction   = "KEYORIX_CRASHTEST_ACTION" // "init" | "rotate" | "check"
	envPromote  = "KEYORIX_CRASHTEST_PROMOTE"
	crashPass   = "crash-harness-static-passphrase-32b"
	canaryPlain = "AT2-crash-harness-canary-plaintext"
)

// canaryPath is where the "init" action leaves a DEK-encrypted canary the
// "check" action must be able to decrypt back to canaryPlain. This is the
// property that actually matters: not "some 32-byte DEK loaded" (which a
// silent-regenerate-on-missing-file bug would also satisfy, wrongly passing
// this harness — caught during this session's own red-proof run, see the PR
// body) but "the SAME key material that encrypted this data before the
// crash is still what's active after recovery."
func canaryPath(keyDir string) string { return filepath.Join(keyDir, "canary.enc.json") }

// runHelperSubprocess execs this same test binary as a fresh OS process
// running only TestCrashHelperProcess, with the given action and (for the
// "rotate" action) a crash-point label. Returns the process's exit code and
// combined output.
func runHelperSubprocess(t *testing.T, keyDir, action, crashLabel string, promote bool) (exitCode int, output string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelperProcess$", "-test.v=false") // #nosec G204 -- os.Args[0] is this test binary itself, not attacker input
	cmd.Env = append(os.Environ(),
		envHelper+"=1",
		envKeyDir+"="+keyDir,
		envPassword+"="+crashPass,
		envAction+"="+action,
	)
	if crashLabel != "" {
		cmd.Env = append(cmd.Env, "KEYORIX_TEST_CRASH_AT_STEP="+crashLabel)
	}
	if promote {
		cmd.Env = append(cmd.Env, envPromote+"=1")
	}
	out, err := cmd.CombinedOutput()
	output = string(out)
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
// KEYORIX_CRASHTEST_KEYDIR and exits 0 on success -- crashpoint.Hit (inside
// rotationCheckpointHook) may terminate it with exit 137 first, mid-action,
// if KEYORIX_TEST_CRASH_AT_STEP matches a checkpoint this action passes
// through.
func TestCrashHelperProcess(t *testing.T) {
	if os.Getenv(envHelper) != "1" {
		t.Skip("not invoked as a crash-test helper subprocess")
	}
	keyDir := os.Getenv(envKeyDir)
	pass := os.Getenv(envPassword)
	action := os.Getenv(envAction)

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
		blob, _ := json.Marshal(enc)
		if err := os.WriteFile(canaryPath(keyDir), blob, 0600); err != nil { // #nosec G306 -- test-only scratch fixture, not production key material
			fmt.Fprintln(os.Stderr, "canary write failed:", err)
			os.Exit(1)
		}
	case "rotate":
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
			blob, _ := json.Marshal(reenc)
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
		// This minimal harness has no DB (see the package doc's scope note), so the
		// test driver passes the equivalent decision directly via KEYORIX_CRASHTEST_PROMOTE
		// -- it already knows which checkpoint it crashed at, which is exactly the
		// same fact the DB marker would encode. PromotePendingDEK/CleanPendingDEK are
		// both real, unmodified, and safe to call unconditionally when the pending
		// file they'd act on isn't present (both documented as no-ops in that case).
		if os.Getenv(envPromote) == "1" {
			if err := km.PromotePendingDEK(); err != nil {
				fmt.Fprintln(os.Stderr, "check: PromotePendingDEK failed:", err)
				os.Exit(1)
			}
		} else {
			km.CleanPendingDEK()
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

// TestDEKRotationSubprocessCrashRecovery is the actual AT2 harness test.
// For each of RotateDEKWithSweep's real checkpoints, it: (1) seeds a DEK via
// a clean "init" subprocess, (2) runs a "rotate" subprocess with
// KEYORIX_TEST_CRASH_AT_STEP set to that checkpoint, asserting it dies with
// exit 137 (crashpoint.Hit fired -- proves the crash point is actually
// reachable and this harness is really exercising it, not silently passing
// because the label never matched), (3) runs a "check" subprocess (a THIRD,
// entirely fresh process/KeyManager instance, simulating a real restart)
// and asserts it can load a valid DEK -- the install must never be bricked,
// no matter which of the four checkpoints the crash landed on.
func TestDEKRotationSubprocessCrashRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real subprocesses per checkpoint; skipped under -short")
	}
	// promote mirrors the real redo-marker decision (see the "check" case's own
	// comment): once sweepFn has returned successfully ("after-sweep-commit" and
	// later), the pending DEK must be PROMOTED on recovery, not discarded --
	// discarding it after the canary has already been re-encrypted under the new
	// DEK (which happens inside sweepFn, before this checkpoint fires) would
	// itself brick the data, the mirror-image bug to promoting too early.
	cases := []struct {
		label   string
		promote bool
	}{
		{"sweep:after-write-dek-pending", false},
		{"sweep:after-sweep-commit", true},
		{"sweep:after-rename-dek", true},
		{"sweep:after-syncdir", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			keyDir := t.TempDir()

			if code, out := runHelperSubprocess(t, keyDir, "init", "", false); code != 0 {
				t.Fatalf("seed init subprocess failed (exit %d): %s", code, out)
			}

			code, out := runHelperSubprocess(t, keyDir, "rotate", tc.label, false)
			if code != 137 {
				t.Fatalf("rotate subprocess at checkpoint %q: expected exit 137 (crashpoint.Hit fired), got %d (output: %s)", tc.label, code, out)
			}

			if code, out := runHelperSubprocess(t, keyDir, "check", "", tc.promote); code != 0 {
				t.Fatalf("post-crash check subprocess at checkpoint %q FAILED (exit %d) -- the install is bricked (or data unrecoverable) after a crash at this step: %s", tc.label, code, out)
			}
		})
	}
}
