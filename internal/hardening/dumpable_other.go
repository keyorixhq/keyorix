//go:build !linux

package hardening

// setNotDumpableFn is a no-op off Linux: PR_SET_DUMPABLE is a Linux prctl, and the
// piped core_pattern it exists to defeat is a Linux mechanism. RLIMIT_CORE still applies.
var setNotDumpableFn = func() error { return nil }
