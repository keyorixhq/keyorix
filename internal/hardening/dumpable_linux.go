//go:build linux

package hardening

import "golang.org/x/sys/unix"

// setNotDumpableFn marks the process non-dumpable (PR_SET_DUMPABLE=0). An indirection,
// like setrlimitFn, so the failure branch can be tested.
var setNotDumpableFn = func() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }
