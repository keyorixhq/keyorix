//go:build !(linux || darwin)

package boundedwork

// processCPUNanos is unavailable here; measure falls back to best-of-N wall
// time for the time arm (see cpuclock_unix.go for why CPU time is preferred).
func processCPUNanos() (nanos int64, ok bool) { return 0, false }
