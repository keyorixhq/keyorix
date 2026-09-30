// rotation_crash_hooks.go — a nil-in-production seam for crash-consistency testing.
//
// Key rotation persists multiple coupled files (dek.key, kek.salt) via a
// write-pending → rename → fsync sequence. A process crash (power loss, SIGKILL,
// OOM) between any two of those steps leaves the key material in an intermediate
// on-disk state, and the correctness question is whether EVERY such state is
// still recoverable to the original DEK (no data loss) without leaving the retired
// KEK able to unwrap it (no stale-key exposure).
//
// Real power loss cannot be produced in-process, so FuzzKEKRotationCrashConsistency
// simulates it: it sets rotationCheckpoint to a function that panics from the exact
// step it wants to interrupt, then runs the REAL rotation. Panicking (rather than
// returning an error) is deliberate — it models an abrupt crash that skips the
// inline cleanup the error-return paths perform, which is precisely the state a
// real crash leaves behind.
//
// In production rotationCheckpoint is nil and rotationCheckpointHook is a no-op, so
// this adds nothing to the hot path and changes no behavior.
//
// SESSION-AT AT2 adds a second, complementary probe at the exact same named
// checkpoints: internal/crashpoint.Hit, a real os.Exit(137) gated on an env
// var, for a subprocess-level crash-consistency harness (see
// keymanager_subprocess_crash_test.go) that proves recovery holds under an
// actual process exit, not just an in-process panic. Reusing these same
// labels rather than inventing a second checkpoint scheme, matching this
// session's own "don't invent a second error-injection helper" discipline
// for F1 (failOnceStorage) applied here to F2.
package encryption

import "github.com/keyorixhq/keyorix/internal/crashpoint"

// rotationCheckpoint, when non-nil, is invoked at each durability checkpoint during
// KEK-passphrase rotation (see commitNewKEKFiles, labels "kek:..."), KEK-provider
// migration (see RewrapDEK, labels "rewrap:...") and DEK rotation with full
// re-encryption sweep (see RotateDEKWithSweep, labels "sweep:...") with a stable label.
// It is set only by crash-consistency tests; it is nil in every production build.
var rotationCheckpoint func(label string)

// rotationCheckpointHook invokes rotationCheckpoint if one is installed (a test's
// hook may panic to simulate a crash at `label`; production passes through), then
// crashpoint.Hit (a genuine os.Exit(137) if this process was launched as a
// subprocess crash-test target for this exact label; a no-op otherwise).
func rotationCheckpointHook(label string) {
	if rotationCheckpoint != nil {
		rotationCheckpoint(label)
	}
	crashpoint.Hit(label)
}
