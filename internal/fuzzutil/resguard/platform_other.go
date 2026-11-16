//go:build !linux

package resguard

// platformName identifies the meter backend in failure messages and docs.
const platformName = "unsupported"

// readProcStats on non-Linux returns ok=false: the CPU/thread/fd/io meters are
// Linux-only in this first cut (macOS getrusage + ru_oublock is listed as a
// LEFTOVER). Alloc, disk-walk and the application seams (net, clock, log, DB)
// are portable and still work; the Probe simply omits the process meters.
func readProcStats() procStats { return procStats{} }
