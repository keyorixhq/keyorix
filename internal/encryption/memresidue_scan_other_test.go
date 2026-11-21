//go:build !linux

package encryption

import (
	"errors"
	"runtime"
)

// memScanSupported: no /proc/PID/mem here. macOS would need mach_vm_read on a
// task port, which a non-root, non-entitled process only gets for itself via
// cgo; the oracle skips cleanly instead of faking a pass.
func memScanSupported() error {
	return errors.New("process-memory scan needs /proc/self/mem (Linux); not available on " + runtime.GOOS)
}

func scanProcessMemory([]memNeedle) ([]memHit, uint64, error) {
	return nil, 0, memScanSupported()
}
