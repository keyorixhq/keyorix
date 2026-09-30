// Package crashpoint is a test-only process-crash simulation seam (SESSION-AT,
// AT2). It exists so a crash-consistency test can kill the REAL process at a
// named durability checkpoint -- simulating kill -9 / power loss -- with a
// genuine os.Exit from a genuine separate OS process, and then verify the
// next run recovers correctly. That is a different, complementary proof to
// an in-process panic-based crash simulator (e.g.
// internal/encryption/rotation_crash_hooks.go's rotationCheckpoint, used by
// this repo's existing FuzzDEKSweepCrashConsistency/FuzzKEKRotationCrashConsistency
// trilogy): a panic never exits the process, so it cannot catch a bug that
// only lives in actual process-exit / OS-buffer-flush semantics, or in
// recovery logic wired at the CLI/main() layer rather than inside the
// function under test.
//
// Activation is entirely env-var driven and read ONCE at process start
// (package init), never via a CLI flag or anything an operator could
// stumble into -- mirroring server/admin/testhook.go's existing
// hidden-and-undocumented pattern for the same "test-only, never a
// production surface" property. A production binary run without
// KEYORIX_TEST_CRASH_AT_STEP set behaves identically to one built without
// this package at all: Hit is a single string-compare-and-branch, always a
// no-op unless a test explicitly set the env var before spawning the
// process.
package crashpoint

import "os"

// step is the checkpoint label to crash at for this process's lifetime, or
// "" if crash-testing is not active. Read once at package init, not on
// every Hit call, so a test cannot accidentally change it mid-run by
// mutating its own environment after the process it's testing already
// started (env vars are inherited at exec time, not polled).
var step = os.Getenv("KEYORIX_TEST_CRASH_AT_STEP")

// osExit is overridden by tests that need to observe Hit firing without
// actually killing the test process.
var osExit = os.Exit

// Active reports whether crash-point simulation is enabled for this
// process at all (any label). Callers may use this to skip cheap
// diagnostic logging around a Hit call in a hot path, though Hit itself is
// already a single comparison and safe to call unconditionally.
func Active() bool { return step != "" }

// Hit crashes the process immediately with exit code 137 (128 + SIGKILL(9),
// the same status a `kill -9`'d process reports to its parent) if label
// matches the process's configured KEYORIX_TEST_CRASH_AT_STEP. Otherwise a
// no-op. Call sites name a stable, meaningful label at each durability
// checkpoint they want a crash test to be able to interrupt.
func Hit(label string) {
	if step != "" && step == label {
		osExit(137)
	}
}
