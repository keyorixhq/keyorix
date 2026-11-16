package resguard

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
)

// Budgets are NOT hand-tuned. Calibrate runs a target's seed corpus through a
// Probe, takes the p99 of each meter (and of each meter's per-input-byte ratio),
// multiplies by a documented slack Factor, and writes testdata/resguard.json
// next to the target. Check then fails an input whose measured cost exceeds
// Factor·(Floor + PerByte·N) for any fatal meter — the shape of an amplification
// that calibration never saw. The allocation budget (like every per-byte meter)
// is exactly that floor-plus-slope, so a large input is judged against a larger
// budget and only SUPER-linear growth fails.
//
// Advisory meters (wall, CPU, goroutine/thread/fd deltas) are process-wide and
// noisy on a shared host, so they are reported in a failure message for context
// but never fail an input on their own (CLAUDE.md: wall time false-fires under
// load). The fatal meters are the ones attributable to a single input.

// Budget-check modes (MeterBudget.Mode). The default ("" / ModeSlope) is the
// per-byte slope every RSG1 meter used. ModeAbsolute judges a meter by its
// input-size-INDEPENDENT absolute ceiling (AbsMax) alone — the correct model for
// a DECOMPRESSION or image target, where the compression ratio is scale-invariant
// so a per-byte slope calibrated on small benign inputs false-positives on a
// legitimately-larger one (RSG1 Pilot #1: a 457-byte archive expanding to
// 65 823 bytes, 144×, tripped the slope although it is within the product's own
// cap). See INV-RES-absmax-for-decompression.
const (
	ModeSlope    = "" // per-byte slope: factor·(Floor + PerByte·N)
	ModeAbsolute = "absolute"
)

// MeterBudget is Floor + PerByte·N (the per-byte slope) PLUS AbsMax, an absolute
// ceiling independent of input size. Calibrate derives all three. Mode selects
// which ceiling Check applies (default: the slope).
type MeterBudget struct {
	Floor   float64 `json:"floor"`
	PerByte float64 `json:"per_byte"`
	// AbsMax is the absolute ceiling: p99(value across the corpus)·factor, with
	// NO per-byte term. 0 means "not calibrated" (legacy budgets) and Check then
	// falls back to the slope even in ModeAbsolute, so an old budget never loses
	// its guard. Because it is already multiplied by factor it is applied
	// directly, not re-scaled, at Check time.
	AbsMax float64 `json:"abs_max,omitempty"`
	// Mode is ModeSlope ("") or ModeAbsolute. A target sets it via
	// Budget.UseAbsolute for a decompression-shaped meter.
	Mode string `json:"mode,omitempty"`
}

// slopeAllowed is the per-byte ceiling factor·(Floor + PerByte·N).
func (mb MeterBudget) slopeAllowed(n int, factor float64) float64 {
	return factor * (mb.Floor + mb.PerByte*float64(n))
}

// exceeded reports whether value v for an input of n bytes is over this meter's
// ceiling, and returns the ceiling that was applied (for the failure message).
// ModeAbsolute uses AbsMax alone; it falls back to the slope when AbsMax is 0
// (an uncalibrated/legacy budget), so switching mode never silently disarms a
// meter. ModeSlope uses the per-byte ceiling.
func (mb MeterBudget) exceeded(v float64, n int, factor float64) (bool, float64) {
	if mb.Mode == ModeAbsolute && mb.AbsMax > 0 {
		return v > mb.AbsMax, mb.AbsMax
	}
	allowed := mb.slopeAllowed(n, factor)
	return allowed > 0 && v > allowed, allowed
}

// Budget is a calibrated set of per-meter ceilings for one target.
type Budget struct {
	Target   string                 `json:"target"`
	Platform string                 `json:"platform"`
	Factor   float64                `json:"factor"`
	Seeds    int                    `json:"seeds"`
	Meters   map[string]MeterBudget `json:"meters"`
}

type meterDesc struct {
	name        string
	sampledOnly bool // measured only on sampled inputs
	advisory    bool // reported but never fatal
	get         func(Cost) float64
}

// meterDescs is the single source of truth both Calibrate and Check iterate, so
// a meter cannot be calibrated under one name and checked under another.
var meterDescs = []meterDesc{
	{"alloc_bytes", true, false, func(c Cost) float64 { return float64(c.AllocBytes) }},
	{"mallocs", true, false, func(c Cost) float64 { return float64(c.Mallocs) }},
	{"live_heap", true, false, func(c Cost) float64 { return float64(c.LiveHeap) }},
	// Disk + write-bytes are measured on EVERY input (cheap walk), not sampled.
	{"write_bytes", false, false, func(c Cost) float64 { return float64(c.WriteBytes) }},
	{"disk_bytes", false, false, func(c Cost) float64 { return float64(nonNeg64(c.DiskBytes)) }},
	{"disk_blocks", false, false, func(c Cost) float64 { return float64(nonNeg64(c.DiskBlocks)) }},
	{"disk_files", false, false, func(c Cost) float64 { return float64(nonNeg(c.DiskFiles)) }},
	{"dials", false, false, func(c Cost) float64 { return float64(c.Dials) }},
	{"net_bytes_in", false, false, func(c Cost) float64 { return float64(nonNeg64(c.NetBytesIn)) }},
	{"net_bytes_out", false, false, func(c Cost) float64 { return float64(nonNeg64(c.NetBytesOut)) }},
	{"sleep_ns", false, false, func(c Cost) float64 { return float64(c.Sleep) }},
	{"log_bytes", false, false, func(c Cost) float64 { return float64(nonNeg64(c.LogBytes)) }},
	{"db_queries", false, false, func(c Cost) float64 { return float64(c.DBQueries) }},
	{"db_rows", false, false, func(c Cost) float64 { return float64(nonNeg64(c.DBRows)) }},
	{"wall_ns", false, true, func(c Cost) float64 { return float64(c.Wall) }},
	{"cpu_ns", false, true, func(c Cost) float64 { return float64(c.CPU) }},
	{"goroutines", false, true, func(c Cost) float64 { return float64(nonNeg(c.Goroutines)) }},
}

// DefaultFactor is the slack over p99 a calibrated budget allows before it
// fails an input. 4× leaves generous headroom for GC/scheduling noise while
// still catching order-of-magnitude amplification.
const DefaultFactor = 4.0

// Calibrate derives a Budget from the costs measured over a seed corpus. Pass
// factor <= 0 for DefaultFactor. Meters with no non-zero sample get a zero
// budget, which Check treats as "not metered for this target" (never a
// spurious fail). For a sampledOnly meter, only sampled costs contribute.
func Calibrate(target string, samples []Cost, factor float64) Budget {
	if factor <= 0 {
		factor = DefaultFactor
	}
	b := Budget{
		Target:   target,
		Platform: platformName,
		Factor:   factor,
		Seeds:    len(samples),
		Meters:   map[string]MeterBudget{},
	}
	for _, m := range meterDescs {
		var vals, ratios []float64
		for _, c := range samples {
			if m.sampledOnly && !c.Sampled {
				continue
			}
			v := m.get(c)
			vals = append(vals, v)
			n := c.InputLen
			if n < 1 {
				n = 1
			}
			ratios = append(ratios, v/float64(n))
		}
		floor := p99(vals)
		perByte := p99(ratios)
		if floor == 0 && perByte == 0 {
			continue // meter never fired across the corpus
		}
		// AbsMax is the input-size-INDEPENDENT ceiling: p99(value)·factor. It is
		// only meaningful if the seed corpus contains a representative
		// legitimately-large sample (else it is calibrated too small and a
		// decompression target in ModeAbsolute false-positives exactly as the
		// per-byte slope did). The adopter is responsible for that corpus; the
		// report states the limitation.
		b.Meters[m.name] = MeterBudget{Floor: floor, PerByte: perByte, AbsMax: floor * factor}
	}
	return b
}

// KeepOnly drops every calibrated meter except the named ones, so Check judges
// only them. Use it for a target where some meters are not per-input attributable
// — e.g. a target that drives a live concurrent server (TLS buffers, server
// goroutines, connection pools) makes the process-global memory meters
// (alloc_bytes/mallocs/live_heap, measured by a whole-process ReadMemStats + GC)
// noisy and not the fault of a single input. Air-gap (NonLoopbackDials) is checked
// independently of the meter set and is never dropped by this. Unknown names are
// ignored. State in the target's report which meters were kept and why.
func (b Budget) KeepOnly(meters ...string) {
	keep := make(map[string]bool, len(meters))
	for _, m := range meters {
		keep[m] = true
	}
	for name := range b.Meters {
		if !keep[name] {
			delete(b.Meters, name)
		}
	}
}

// UseAbsolute switches the named meters to ModeAbsolute (AbsMax ceiling only,
// no per-byte slope). Use it for a decompression/image target whose output size
// is bounded by an absolute product cap, not proportional to the input — the
// per-byte slope is the wrong model there (RSG1 Pilot #1). Unknown names are
// ignored so a target can list every candidate meter without caring which the
// corpus actually exercised. See INV-RES-absmax-for-decompression.
func (b Budget) UseAbsolute(meters ...string) {
	for _, name := range meters {
		if mb, ok := b.Meters[name]; ok {
			mb.Mode = ModeAbsolute
			b.Meters[name] = mb
		}
	}
}

// p99 returns the 99th-percentile value (nearest-rank). Empty -> 0.
func p99(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	idx := int(math.Ceil(0.99*float64(len(s)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

// WriteJSON writes b to path (testdata/resguard.json next to the target),
// pretty-printed and stable (map marshals sorted), so it diffs cleanly.
func (b Budget) WriteJSON(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// LoadBudget reads a Budget written by WriteJSON.
func LoadBudget(path string) (Budget, error) {
	var b Budget
	data, err := os.ReadFile(path) // #nosec G304 -- path is a test-file constant
	if err != nil {
		return b, err
	}
	err = json.Unmarshal(data, &b)
	return b, err
}

// Check reports every fatal meter over budget for input c via fatalf (pass
// t.Fatalf) and returns true if any fired. A non-loopback dial is always a
// failure regardless of budget (the air-gap oracle). Advisory meters that are
// also over budget are appended for context but do not by themselves cause a
// failure. The message names the input size, every over-budget meter with its
// value / budget / amplification ratio, and the elapsed wall time.
func (b Budget) Check(fatalf func(format string, args ...any), c Cost) bool {
	var fatal, context []string

	if c.NonLoopbackDials > 0 {
		fatal = append(fatal, fmt.Sprintf("non_loopback_dials=%d (air-gap: any non-loopback dial fails)", c.NonLoopbackDials))
	}

	for _, m := range meterDescs {
		if m.sampledOnly && !c.Sampled {
			continue
		}
		mb, ok := b.Meters[m.name]
		if !ok {
			continue
		}
		v := m.get(c)
		over, allowed := mb.exceeded(v, c.InputLen, b.Factor)
		if !over {
			continue
		}
		mode := ""
		if mb.Mode == ModeAbsolute {
			mode = " abs"
		}
		line := fmt.Sprintf("%s=%.0f budget=%.0f%s amp=%.1fx", m.name, v, allowed, mode, v/allowed)
		if m.advisory {
			context = append(context, line)
		} else {
			fatal = append(fatal, line)
		}
	}

	if len(fatal) == 0 {
		return false
	}
	msg := fmt.Sprintf("RESGUARD %s: input=%d bytes elapsed=%s over budget: %s",
		b.Target, c.InputLen, c.Wall, strings.Join(fatal, "; "))
	if len(context) > 0 {
		msg += " [advisory: " + strings.Join(context, "; ") + "]"
	}
	fatalf("%s", msg)
	return true
}

// Summary is a one-line human description of a Budget, for a target's t.Logf.
func (b Budget) Summary() string {
	var ks []string
	for k := range b.Meters {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return fmt.Sprintf("budget %s (%s, factor %.1f, %d seeds): %s",
		b.Target, b.Platform, b.Factor, b.Seeds, strings.Join(ks, ","))
}
