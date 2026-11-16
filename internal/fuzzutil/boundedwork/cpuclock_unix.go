//go:build linux || darwin

package boundedwork

import "golang.org/x/sys/unix"

// processCPUNanos returns the CPU time consumed so far by this process (every
// thread, so GC workers and goroutines the call starts are included). Unlike
// wall-clock time it does not advance while the process is descheduled, which
// is what makes the time arm robust to a loaded host: on a busy CI runner a
// longer measurement is preempted more often than a short one, so wall time
// inflates SUPER-linearly with input size and a linear parser looks quadratic.
// Resolution is 1 ns on Linux and 1 us on macOS (see cpuClockMinNanos).
// ok=false if the clock is unavailable.
func processCPUNanos() (nanos int64, ok bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_PROCESS_CPUTIME_ID, &ts); err != nil {
		return 0, false
	}
	return ts.Nano(), true
}
