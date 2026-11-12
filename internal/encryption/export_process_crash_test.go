package encryption

// export_process_crash_test.go exposes this package's two nil-in-production
// crash seams to the external-test-package process-death fuzzer
// (process_crash_recovery_fuzz_test.go), which has to live in package
// encryption_test because it drives internal/core and server/admin, and both of
// those import this package.

// SetProcessCrashSeamForTest calls fn at every key-file durability seam:
// rotationCheckpoint's labelled steps and each durableWriteSync, durableRename
// and durableSyncDir call. fn may end the process. Passing nil removes the seam.
func SetProcessCrashSeamForTest(fn func(label string)) {
	if fn == nil {
		rotationCheckpoint, fileFaultHook = nil, nil
		return
	}
	rotationCheckpoint = fn
	fileFaultHook = func(seam string) *fileFault {
		fn("file:" + seam)
		return nil
	}
}
