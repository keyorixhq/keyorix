package hardening

import (
	"errors"
	"testing"
)

// TestApplyMemoryHardening_NotDumpableFailureIsFatal: if the prctl fails, startup must
// fail rather than log "core dumps disabled".
func TestApplyMemoryHardening_NotDumpableFailureIsFatal(t *testing.T) {
	orig := setNotDumpableFn
	setNotDumpableFn = func() error { return errors.New("EPERM") }
	t.Cleanup(func() { setNotDumpableFn = orig })
	if err := ApplyMemoryHardening(); err == nil {
		t.Fatal("ApplyMemoryHardening returned nil although marking the process non-dumpable failed")
	}
}
