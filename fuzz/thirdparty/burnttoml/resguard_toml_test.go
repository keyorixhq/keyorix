package burnttomlhostile

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// PK2: port the BurntSushi/toml hostile target onto resguard. The existing
// oracle (no-panic, bounded wall, canonical re-encode stability) is UNCHANGED;
// resguard is an INDEPENDENT second oracle metering the decode's resource cost.
// Fatal meters: alloc_bytes / mallocs / live_heap (per-byte slope) — a decoder
// that allocates super-linearly in its input (the RAM-spike class, e.g. deep
// nesting that blows the recursion's working set) is caught. CPU/wall/goroutines
// are resguard ADVISORY meters (process-wide, noisy on a shared host): recorded
// and reported, never fatal alone.
//
// What the resguard oracle does NOT verify (beyond the existing oracle's list):
// it meters the first `toml.Unmarshal` only (not the re-marshal), bounds the
// ratio not correctness, and alloc/live-heap are SAMPLED (but any >100 ms input
// is force-sampled, so a real amplifier is always measured).

const rgBudgetPath = "testdata/resguard-toml.json"

var rgWrite = flag.Bool("rgwrite", false, "regenerate the committed resguard budget JSON")

// rgRun drives one input through the SAME per-input work the fuzz body meters:
// the existing `stability` oracle (Unmarshal + canonical re-encode round-trip).
// Metering the identical surface in calibration and in the fuzz body keeps the
// budget and the check comparable.
func rgRun(data []byte) {
	_ = stability(data)
}

// rgBenignCorpus is a spread of LEGITIMATE TOML of varying size/shape so the
// per-byte alloc slope reflects real linear decode cost.
func rgBenignCorpus() [][]byte {
	var manyKeys strings.Builder
	for i := range 1500 {
		fmt.Fprintf(&manyKeys, "key_%d = %d\n", i, i)
	}
	var tables strings.Builder
	for i := range 500 {
		fmt.Fprintf(&tables, "[[arr]]\nx = %d\ny = \"v%d\"\n", i, i)
	}
	var strs strings.Builder
	for i := range 800 {
		fmt.Fprintf(&strs, "s%d = \"a moderately long string value number %d\"\n", i, i)
	}
	return [][]byte{
		[]byte("a = 1\nb = \"x\"\n"),
		[]byte("[t]\nk = true\n[[arr]]\nx = 1\n"),
		[]byte("f = 1.5e10\ni = 0x1F\n"),
		[]byte(manyKeys.String()),
		[]byte(tables.String()),
		[]byte(strs.String()),
	}
}

func rgCalibrate(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, seed := range rgBenignCorpus() {
		for range 4 {
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			s := seed
			costs = append(costs, p.Measure(len(s), func() { rgRun(s) }))
		}
	}
	b := resguard.Calibrate("toml_decode", costs, resguard.DefaultFactor)
	delete(b.Meters, "live_heap") // non-attributable process-heap snapshot (see yaml)
	return b
}


func TestResguardTOMLCalibrate(t *testing.T) {
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

// TestResguardTOMLRedGreen proves the oracle is not vacuous for THIS target's
// calibrated budget. GREEN: a benign medium doc passes. RED: BurntSushi/toml was
// probed for a natural super-linear amplifier (deep inline-array nesting, many
// tables, long keys) and found robustly LINEAR — no input makes it allocate out
// of proportion to its size (a real, if negative, result; recorded in the report).
// So the RED case is a budget self-test: a benign-SIZED input whose measured
// alloc/mallocs are scaled 100× — the RAM-spike shape a future decoder regression
// would produce — must trip this target's calibrated budget. This WATCHES the
// guard fire (not a vacuous green); the amplifier is synthetic because the current
// library has none, which the oracle's role here is a regression tripwire.
func TestResguardTOMLRedGreen(t *testing.T) {
	b := rgCalibrate(t)

	benign := rgBenignCorpus()[3]
	pg := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := pg.Measure(len(benign), func() { rgRun(benign) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("benign doc tripped the budget: alloc=%d for %d bytes", green.AllocBytes, len(benign))
	}

	// RED: same input size, 100× the allocation — a super-linear RAM regression.
	red := green
	red.AllocBytes = green.AllocBytes * 100
	red.Mallocs = green.Mallocs * 100
	var msg string
	fired := b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red)
	if !fired {
		t.Fatalf("a 100× alloc amplification of a %d-byte input did NOT trip the budget (alloc=%d) — budget too loose", len(benign), red.AllocBytes)
	}
	t.Logf("RED tripped (synthetic 100× alloc on a %d-byte input, alloc=%d): %s", len(benign), red.AllocBytes, msg)
}
