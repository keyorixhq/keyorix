package resguard

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// Red/green proof for INV-FUZZUTIL-first-guard-call-allocates-nothing-extra (RESGUARD-PAR-1).

// coldStartChildEnv marks the child process of
// TestFirstMeasuredGuardCallPaysNoHarnessStartup.
const coldStartChildEnv = "RESGUARD_COLDSTART_CHILD"

// TestFirstMeasuredGuardCallPaysNoHarnessStartup reproduces the RESGUARD-PAR-1
// false positive: in a FRESH process (each go test -fuzz worker is one), the first
// measured input's first fuzzutil.Guard call used to allocate the harness's own
// one-time state inside the measured window (the stall monitor's first
// runtime/metrics read, ~10 KiB, plus its goroutine, ticker and the pooled
// runner), so a tiny seed that happened to be a worker's first input failed its
// alloc budget (digitorus_timestamp: 4 bytes, 13912 > 12154). The test runs itself
// in a child process so the "first Guard call" really is the first in the process,
// whatever order the other tests run in.
//
// It does NOT verify first-use costs of the code UNDER TEST (a parser's lazily
// built tables): those are the input's to pay and a target's calibration absorbs
// them.
func TestFirstMeasuredGuardCallPaysNoHarnessStartup(t *testing.T) {
	if os.Getenv(coldStartChildEnv) == "1" {
		p := New(t, Options{SampleEvery: 1})
		noop := func() { fuzzutil.Guard(t.Fatalf, "noop", func() {}) }
		first := p.Measure(0, noop)
		// Re-prime: the two forced GCs since the first call (SampleEvery 1) emptied
		// Guard's runner/timer pool, and the baseline must be a WARM call, or it
		// would already contain the cost Prime removes and hide its absence.
		fuzzutil.Prime()
		second := p.Measure(0, noop)
		fmt.Printf("COLDSTART first=%d second=%d\n", first.AllocBytes, second.AllocBytes)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFirstMeasuredGuardCallPaysNoHarnessStartup$", "-test.count=1") // #nosec G204 G702 -- re-executes this test binary
	cmd.Env = append(os.Environ(), coldStartChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child process: %v\n%s", err, out)
	}
	var first, second uint64
	line := ""
	for l := range strings.Lines(string(out)) {
		if strings.HasPrefix(l, "COLDSTART ") {
			line = l
		}
	}
	if _, err := fmt.Sscanf(line, "COLDSTART first=%d second=%d", &first, &second); err != nil {
		t.Fatalf("no COLDSTART line in child output (%v):\n%s", err, out)
	}
	t.Logf("fresh process: first measured Guard call alloc_bytes=%d, second=%d", first, second)
	if first > second+coldStartSlack {
		t.Fatalf("first measured fuzzutil.Guard call in a fresh process allocated %d bytes vs %d for the next identical call: the harness's one-time setup (+%d) is charged to the first input", first, second, first-second)
	}
}
