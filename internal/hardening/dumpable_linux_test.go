//go:build linux

package hardening

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestApplyMemoryHardening_ProcessNotDumpable checks the real kernel state after
// ApplyMemoryHardening: the process must be non-dumpable, because RLIMIT_CORE=0 is not
// enforced for a piped kernel.core_pattern (core(5)). Running it leaves this test binary
// non-dumpable, which nothing else in the package depends on.
func TestApplyMemoryHardening_ProcessNotDumpable(t *testing.T) {
	if err := ApplyMemoryHardening(); err != nil {
		t.Fatalf("ApplyMemoryHardening: %v", err)
	}
	d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("PR_GET_DUMPABLE: %v", err)
	}
	if d != 0 {
		t.Fatalf("PR_GET_DUMPABLE = %d after ApplyMemoryHardening, want 0: a piped core_pattern would still receive this process's memory", d)
	}
}
