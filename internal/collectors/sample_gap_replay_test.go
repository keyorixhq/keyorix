//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestTwoSampleCollectorsPromptOnReplay is the red/green guard for the replay
// sample-gap fix. The I/O and swap collectors each read their /proc source twice
// with a real-time gap between the samples to compute a rate. On REPLAY both
// reads serve the SAME recorded bytes, so the inter-sample delta is 0 regardless
// of the wait — the wall-clock pause is pure waste and, worse, makes `dsd replay`
// depend on real time (violating the "replay is a pure, prompt function of the
// bundle" property the capture-replay oracles guard). Each such wait costs ~1s
// per replay (2s+ total), which is exactly what made the DRP1 exhaustive sweep
// take hours.
//
// RED without the fix: each Collect() sleeps ~1s on replay, so the elapsed check
// fires. GREEN with sampleGapWait skipping the wait on a replay source.
func TestTwoSampleCollectorsPromptOnReplay(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/proc/diskstats", []byte("   8       0 sda 100 0 2000 50 200 0 4000 80 0 60 130 0 0 0 0 0 0 0\n"))
	b.PutFile("/proc/vmstat", []byte("pswpin 0\npswpout 0\n"))
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	// Well under the 1s live inter-sample gap, comfortably above real replay cost.
	const budget = 300 * time.Millisecond

	start := time.Now()
	if _, err := NewIOCollector().Collect(context.Background()); err != nil {
		t.Fatalf("IOCollector.Collect on replay: %v", err)
	}
	if el := time.Since(start); el > budget {
		t.Errorf("IOCollector replay took %s (> %s) — it waited the live sample gap on replay", el, budget)
	}

	start = time.Now()
	if _, err := NewSwapCollector(platform.ContainerContext{}).Collect(context.Background()); err != nil {
		t.Fatalf("SwapCollector.Collect on replay: %v", err)
	}
	if el := time.Since(start); el > budget {
		t.Errorf("SwapCollector replay took %s (> %s) — it waited the live sample gap on replay", el, budget)
	}
}
