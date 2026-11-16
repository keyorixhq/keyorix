//go:build linux

package resguard

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// platformName identifies the meter backend in failure messages and docs.
const platformName = "linux"

// readProcStats samples the cheap per-process meters that Linux exposes without
// a stop-the-world: process CPU (getrusage), thread count and open-fd count
// (/proc/self/{status,fd}), and cumulative write bytes (/proc/self/io). ok is
// true when at least CPU could be read.
//
// CAVEAT (documented, not hidden): getrusage(RUSAGE_SELF) and /proc/self are
// PROCESS-wide, not per-goroutine. Under `-parallel >1` other fuzz workers in
// the same process pollute the CPU/fd/thread deltas. The Probe therefore treats
// these as advisory trend meters (drift, cost buckets), never as a hard
// per-input budget on their own; the hard budgets ride on alloc/disk/net, which
// are attributable to one input. See package doc.
func readProcStats() procStats {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return procStats{}
	}
	s := procStats{
		ok:  true,
		cpu: time.Duration(ru.Utime.Nano()) + time.Duration(ru.Stime.Nano()),
	}
	s.threads = readThreads()
	s.openFDs = readOpenFDs()
	s.writeBytes = readWriteBytes()
	return s
}

func readThreads() int {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Threads:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

// readOpenFDs counts entries in /proc/self/fd. ReadDir itself opens one fd for
// the directory, which is closed before this returns, so the count is of fds
// open around the call; it is used as a delta, so the constant self-fd cancels.
func readOpenFDs() int {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return len(ents)
}

func readWriteBytes() uint64 {
	b, err := os.ReadFile("/proc/self/io")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "write_bytes:"); ok {
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}
