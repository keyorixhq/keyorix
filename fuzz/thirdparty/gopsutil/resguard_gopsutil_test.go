package gopsutilhostile

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
)

// PK2: port the gopsutil /proc-parser target onto resguard. The existing no-panic
// + bounded-wall oracle is UNCHANGED; resguard meters the parse's resource cost.
// Fatal meters: alloc_bytes / mallocs / live_heap (per-byte slope). The gopsutil
// /proc/stat and /proc/meminfo parsers are linear scanners; this is a regression
// tripwire for a future super-linear parse. CPU/wall/goroutines advisory. The
// disk write of the fake proc file is NOT metered (TempDir meter is off; the
// write targets the per-process procDir, not a watched dir).

const rgBudgetPath = "testdata/resguard-gopsutil.json"

var rgWrite = flag.Bool("rgwrite", false, "regenerate the committed resguard budget JSON")

func rgRun(sel uint8, data []byte) {
	files := []string{"stat", "meminfo"}
	which := int(sel) % len(files)
	_ = os.WriteFile(filepath.Join(procDir, files[which]), data, 0o644)
	ctx := ctxWithProc()
	switch which {
	case 0:
		_, _ = cpu.TimesWithContext(ctx, true)
		_, _ = cpu.TimesWithContext(ctx, false)
	case 1:
		_, _ = mem.VirtualMemoryWithContext(ctx)
	}
}

type rgSeed struct {
	sel  uint8
	data []byte
}

func rgBenignCorpus() []rgSeed {
	var bigStat strings.Builder
	bigStat.WriteString("cpu  100 0 200 300 0 0 0 0 0 0\n")
	for i := range 256 {
		fmt.Fprintf(&bigStat, "cpu%d 50 0 100 150 0 0 0 0 0 0\n", i)
	}
	var bigMem strings.Builder
	for i := range 200 {
		fmt.Fprintf(&bigMem, "Field%d: %d kB\n", i, i*1024)
	}
	return []rgSeed{
		{0, []byte("cpu  100 0 200 300 0 0 0 0 0 0\ncpu0 50 0 100 150 0 0 0 0 0 0\n")},
		{1, []byte("MemTotal: 2048 kB\nMemFree: 1024 kB\nMemAvailable: 1500 kB\n")},
		{0, []byte(bigStat.String())},
		{1, []byte(bigMem.String())},
	}
}

func rgCalibrate(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, seed := range rgBenignCorpus() {
		for range 4 {
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			s := seed
			costs = append(costs, p.Measure(len(s.data), func() { rgRun(s.sel, s.data) }))
		}
	}
	b := resguard.Calibrate("gopsutil_proc", costs, resguard.DefaultFactor)
	delete(b.Meters, "live_heap") // non-attributable process-heap snapshot (see yaml)
	return b
}

func TestResguardGopsutilCalibrate(t *testing.T) {
	b := rgCalibrate(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes must be calibrated; got %s", b.Summary())
	}
	if *rgWrite {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(rgBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", rgBudgetPath, b.Summary())
	}
}

// TestResguardGopsutilRedGreen proves the oracle. GREEN: a valid /proc/stat
// passes. The parsers are linear (no natural amplifier), so RED is a budget
// self-test (alloc 10× the calibrated ceiling must trip) — a watched regression
// tripwire.
func TestResguardGopsutilRedGreen(t *testing.T) {
	b := rgCalibrate(t)

	benign := rgBenignCorpus()[2].data
	pg := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := pg.Measure(len(benign), func() { rgRun(0, benign) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("benign /proc/stat tripped the budget: alloc=%d", green.AllocBytes)
	}

	mb := b.Meters["alloc_bytes"]
	allowed := b.Factor * (mb.Floor + mb.PerByte*float64(len(benign)))
	red := green
	red.AllocBytes = uint64(allowed*10) + 1
	var msg string
	if !b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red) {
		t.Fatalf("a 10×-ceiling alloc amplification did NOT trip the budget (alloc=%d, ceiling=%.0f)", red.AllocBytes, allowed)
	}
	t.Logf("RED tripped (synthetic alloc=%d > 10× ceiling %.0f): %s", red.AllocBytes, allowed, msg)
}
