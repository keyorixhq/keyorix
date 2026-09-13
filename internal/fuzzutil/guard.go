// Package fuzzutil holds small shared helpers for fuzz targets. It is imported
// only from _test.go files. It intentionally does not import "testing" — Guard
// takes a fatalf callback (pass t.Fatalf) — so nothing here can leak the testing
// dependency into a non-test build.
package fuzzutil

import "time"

// GuardTimeout is the per-input wall-clock budget for a guarded call. It is scaled
// up under the race detector (guardTimeoutScale, set in guard_race.go): -race
// instruments every memory access and slows execution ~10-20x, so the native 3s
// budget would false-trip on ordinary inputs during a `go test -race` pass.
var GuardTimeout = 3 * time.Second * time.Duration(guardTimeoutScale)

// Guard runs fn with a wall-clock deadline. If fn exceeds GuardTimeout — a hang,
// or a memory-amplification/decompression bomb that would otherwise balloon
// until the fuzz rig's cgroup OOM-kills the process (see the fuzz units'
// MemoryMax) — Guard reports it via fatalf (pass t.Fatalf) so the fuzzer saves
// the input as a reproducer, instead of the worker stalling or being killed with
// no attribution. A panic in fn propagates and is recorded by the fuzzer
// natively. label names the call under test, e.g. "timestamp.Parse".
//
// On timeout the goroutine running fn is left to finish on its own (it cannot be
// cancelled mid-call); the fuzzer stops at the recorded failure, and the rig's
// memory cap bounds any runaway allocation in the meantime.
func Guard(fatalf func(format string, args ...any), label string, fn func()) {
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(GuardTimeout):
		fatalf("%s exceeded %s — possible amplification or hang", label, GuardTimeout)
	}
}
