package fuzzutil

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// stallStartChildEnv marks the child process of
// TestStallMonitorStartDoesNotBuildMetricTable.
const stallStartChildEnv = "FUZZUTIL_STALLSTART_CHILD"

// TestStallMonitorStartDoesNotBuildMetricTable guards the init() half of
// INV-FUZZUTIL-first-guard-call-allocates-nothing-extra for every Guard caller,
// not only resguard (which also calls Prime): in a FRESH process, starting the
// stall monitor (what the first Guard call does) must not be the process's first
// runtime/metrics read, which builds the runtime's metric table (~10 KiB) inside
// whatever window the caller is measuring. Red without the init(): ~11 KiB.
// It does not cover the monitor's goroutine, ticker and sample slice (~1-2 KiB),
// which only Prime moves out of a measured window.
func TestStallMonitorStartDoesNotBuildMetricTable(t *testing.T) {
	if os.Getenv(stallStartChildEnv) == "1" {
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		startStallMonitor()
		runtime.ReadMemStats(&m1)
		fmt.Printf("STALLSTART alloc=%d\n", m1.TotalAlloc-m0.TotalAlloc)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStallMonitorStartDoesNotBuildMetricTable$", "-test.count=1") // #nosec G204 G702 -- re-executes this test binary
	cmd.Env = append(os.Environ(), stallStartChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child process: %v\n%s", err, out)
	}
	var alloc uint64
	line := ""
	for l := range strings.Lines(string(out)) {
		if strings.HasPrefix(l, "STALLSTART ") {
			line = l
		}
	}
	if _, err := fmt.Sscanf(line, "STALLSTART alloc=%d", &alloc); err != nil {
		t.Fatalf("no STALLSTART line in child output (%v):\n%s", err, out)
	}
	t.Logf("fresh process: starting the stall monitor allocated %d bytes", alloc)
	const limit = 4 << 10 // measured ~0.6-1 KiB; the metric table alone is ~10 KiB
	if alloc > limit {
		t.Fatalf("starting the stall monitor in a fresh process allocated %d bytes (> %d): the first runtime/metrics read (metric table) happens inside the first guarded call", alloc, limit)
	}
}
