// rotation_crash_hooks.go — a nil-in-production seam for crash-consistency testing.
//
// Key rotation persists multiple coupled files (dek.key, kek.salt) via a
// write-pending → rename → fsync sequence. A process crash (SIGKILL, OOM,
// or power loss) between any two of those steps leaves the key material in
// an intermediate on-disk state, and the correctness question is whether
// EVERY such state is still recoverable to the original DEK (no data loss)
// without leaving the retired KEK able to unwrap it (no stale-key
// exposure).
//
// Real process termination cannot be produced in-process, so
// FuzzKEKRotationCrashConsistency simulates it: it sets rotationCheckpoint
// to a function that panics from the exact step it wants to interrupt,
// then runs the REAL rotation. Panicking (rather than returning an error)
// is deliberate — it models an abrupt crash that skips the inline cleanup
// the error-return paths perform, which is precisely the state a real
// crash leaves behind. (A panic does not, on its own, prove anything about
// data durability below the process level — e.g. dirty page-cache pages
// the OS hasn't flushed to disk yet — only that recovery logic run AFTER
// the interruption behaves correctly given whatever the filesystem
// actually persisted; see SESSION-AT AT2 below for the complementary real
// process-exit probe, which has the same caveat: os.Exit(137) is a normal
// process exit, not a power-loss simulation — the OS page cache is not
// dropped, so it does not, by itself, prove fsync correctness either.)
//
// In production rotationCheckpoint is nil and rotationCheckpointHook is a
// no-op, so this adds nothing to the hot path and changes no behavior.
//
// A subprocess-level crash harness (keymanager_subprocess_crash_test.go)
// reuses this EXACT seam: TestCrashHelperProcess installs rotationCheckpoint
// itself (a real os.Exit(137) on label match) when it is invoked as the
// crash-test subprocess, the same way FuzzKEKRotationCrashConsistency
// installs one that panics. No production code change for that harness at
// all — the seam already existed and was already nil-in-production.
package encryption

// rotationCheckpoint, when non-nil, is invoked at each durability checkpoint during
// KEK-passphrase rotation (see commitNewKEKFiles, labels "kek:..."), KEK-provider
// migration (see RewrapDEK, labels "rewrap:...") and DEK rotation with full
// re-encryption sweep (see RotateDEKWithSweep, labels "sweep:...") with a stable label.
// It is set only by crash-consistency tests; it is nil in every production build.
var rotationCheckpoint func(label string)

// rotationCheckpointHook invokes rotationCheckpoint if one is installed. A test's
// hook may panic — or, per AT2, os.Exit — to simulate a crash at `label`;
// production passes through untouched.
func rotationCheckpointHook(label string) {
	if rotationCheckpoint != nil {
		rotationCheckpoint(label)
	}
}
