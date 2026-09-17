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
package encryption

// rotationCheckpoint, when non-nil, is invoked at each durability checkpoint during
// KEK-passphrase rotation (see commitNewKEKFiles, labels "kek:..."), KEK-provider
// migration (see RewrapDEK, labels "rewrap:...") and DEK rotation with full
// re-encryption sweep (see RotateDEKWithSweep, labels "sweep:...") with a stable label.
// It is set only by crash-consistency tests; it is nil in every production build.
var rotationCheckpoint func(label string)

// rotationCheckpointHook invokes rotationCheckpoint if one is installed. A test's
// hook may panic to simulate a crash at `label`; production passes through.
func rotationCheckpointHook(label string) {
	if rotationCheckpoint != nil {
		rotationCheckpoint(label)
	}
}
