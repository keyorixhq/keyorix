package spf13pflaghostile

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// PK2: port the spf13/pflag argv target onto resguard. The existing no-panic +
// bounded-wall oracle is UNCHANGED; resguard meters the parse's resource cost.
// Fatal meters: alloc_bytes / mallocs / live_heap (per-byte slope). pflag's
// tokeniser/assigner is linear in argv; this is a regression tripwire. CPU/wall/
// goroutines advisory.

const rgBudgetPath = "testdata/resguard-pflag.json"

var rgWrite = flag.Bool("rgwrite", false, "regenerate the committed resguard budget JSON")

func rgRun(line string) {
	line = strings.ReplaceAll(line, "\x00", " ")
	args := strings.Fields(line)
	if len(args) > 4096 {
		return
	}
	fs := newFS()
	fs.SetOutput(discard{})
	_ = fs.Parse(args)
}

func rgBenignCorpus() []string {
	seeds := []string{
		"--name=x -o out --count 3 -vvv",
		"--force --tag a --tag b -- positional",
		"-dddd --label k=v --timeout 5s",
	}
	// Longer valid argvs so the slope reflects per-arg parse cost.
	var manyTags strings.Builder
	for i := range 500 {
		fmt.Fprintf(&manyTags, "--tag t%d ", i)
	}
	seeds = append(seeds, manyTags.String())
	var manyLabels strings.Builder
	for i := range 400 {
		fmt.Fprintf(&manyLabels, "--label k%d=v%d ", i, i)
	}
	seeds = append(seeds, manyLabels.String())
	return seeds
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
	return resguard.Calibrate("pflag_parse", costs, resguard.DefaultFactor)
}

func TestResguardPflagCalibrate(t *testing.T) {
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

// TestResguardPflagRedGreen proves the oracle. GREEN: a valid argv passes. pflag
// is linear (no natural amplifier), so RED is a budget self-test (alloc 10× the
// calibrated ceiling must trip) — a watched regression tripwire.
func TestResguardPflagRedGreen(t *testing.T) {
	b := rgCalibrate(t)

	benign := rgBenignCorpus()[3]
	pg := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := pg.Measure(len(benign), func() { rgRun(benign) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("benign argv tripped the budget: alloc=%d for %d bytes", green.AllocBytes, len(benign))
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
