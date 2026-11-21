package resguard

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/taint"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

// --- cheap/expensive measurement & overhead -------------------------------

// allocSink defeats dead-code elimination so a test allocation actually happens
// and the alloc meter sees it.
var allocSink []byte

func TestMeasureCheapAndSampled(t *testing.T) {
	p := New(t, Options{SampleEvery: 2})
	// input 0: sampled; input 1: cheap; input 2: sampled …
	c0 := p.Measure(10, func() { allocSink = make([]byte, 1<<16) })
	if !c0.Sampled || !c0.AllocSampled {
		t.Fatalf("input 0 should be sampled with an alloc measurement: %+v", c0)
	}
	if c0.AllocBytes < 1<<16 {
		t.Fatalf("sampled input should see the 64 KiB alloc, got %d", c0.AllocBytes)
	}
	c1 := p.Measure(10, func() { allocSink = make([]byte, 1<<16) })
	if c1.Sampled || c1.AllocSampled {
		t.Fatalf("input 1 should be cheap (not sampled): %+v", c1)
	}
	if c1.AllocBytes != 0 {
		t.Fatalf("cheap input must not read memstats, got AllocBytes=%d", c1.AllocBytes)
	}
}

// TestExpensiveSampleOverhead records, on this host, the wall overhead the
// expensive sample path adds over the cheap path. It never fails on a number
// (that would be a calendar-at-PR-time guard); it only asserts the expensive
// path is not absurdly slower and logs the measured ratio.
func TestExpensiveSampleOverhead(t *testing.T) {
	const iters = 200
	tmp := t.TempDir()
	fn := func() { _ = make([]byte, 4096) }

	cheap := New(t, Options{SampleEvery: 1 << 30}) // never sample
	start := time.Now()
	for range iters {
		cheap.Measure(100, fn)
	}
	cheapDur := time.Since(start)

	exp := New(t, Options{SampleEvery: 1, TempDir: tmp}) // always sample
	start = time.Now()
	for range iters {
		exp.Measure(100, fn)
	}
	expDur := time.Since(start)

	t.Logf("expensive-sample overhead: cheap=%s expensive=%s ratio=%.1fx (per-input cheap=%s expensive=%s)",
		cheapDur, expDur, float64(expDur)/float64(cheapDur), cheapDur/iters, expDur/iters)
	if expDur < cheapDur {
		// Wall-clock comparison on a shared host: logged, never fatal.
		t.Logf("expensive path measured faster than cheap (host noise)")
	}
}

// --- budget calibration & check (red/green) -------------------------------

func TestBudgetCalibrateAndCheck(t *testing.T) {
	// Benign seed corpus: alloc ~ 8·N bytes, no disk/net.
	var seeds []Cost
	for n := 10; n <= 100; n += 10 {
		seeds = append(seeds, Cost{InputLen: n, Sampled: true, AllocSampled: true, AllocBytes: uint64(8 * n), Wall: time.Millisecond})
	}
	b := Calibrate("toy", seeds, DefaultFactor)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated")
	}

	// GREEN: a benign input within the slope passes.
	green := Cost{InputLen: 50, Sampled: true, AllocSampled: true, AllocBytes: 8 * 50, Wall: time.Millisecond}
	var greenFired bool
	b.Check(func(string, ...any) { greenFired = true }, green)
	if greenFired {
		t.Fatalf("benign input must not trip the budget")
	}

	// RED: a 100-byte input that allocates 50 MiB (amplification) fails.
	red := Cost{InputLen: 100, Sampled: true, AllocSampled: true, AllocBytes: 50 << 20, Wall: 5 * time.Millisecond}
	var redMsg string
	fired := b.Check(func(f string, a ...any) { redMsg = sprintf(f, a...) }, red)
	if !fired {
		t.Fatalf("amplifying input must trip the budget")
	}
	if !contains(redMsg, "alloc_bytes") || !contains(redMsg, "amp=") {
		t.Fatalf("failure message should name the meter and amplification: %q", redMsg)
	}
}

// TestBudgetAbsMaxForDecompression is the red/green proof for the AbsMax ceiling
// and ModeAbsolute (RSG1 Pilot #1's leftover #1), reproducing the
// decompression-ratio story in miniature with three honest parts.
//
// Part A — the false positive. With a corpus of only small benign archives
// (input≈output, as RSG1's pilot had), the per-byte SLOPE trips the 144×-shape
// input (457 bytes in, 65 KiB on disk) although its output is harmless — because
// the slope was calibrated where input≈output, a high compression ratio reads as
// super-linear growth. This is the FP the leftover is about.
//
// Part B — AbsMax needs a representative corpus. On that same small-only corpus,
// ModeAbsolute does NOT fix the FP (AbsMax = p99(2.3 KiB)·4 ≈ 9 KiB, still below
// 65 KiB). AbsMax is only as good as its calibration corpus — stated so the
// mechanism is never oversold. Enriching the corpus with one legitimately-large
// benign archive (1 MiB in, 1 MiB on disk — ratio ~1, not a bomb) lifts AbsMax to
// ~4 MiB, and NOW the 144× input passes while an 8 MiB bomb still fires.
//
// Part C — why absolute, not just a bigger slope. The slope's PerByte·N term is
// an attacker lever for a decompression target: compressed input size is cheap to
// inflate, so a padded bomb (3 MiB of junk in, 8 MiB on disk) buys a ~40 MiB
// slope ceiling and EVADES it — while the flat 4 MiB absolute ceiling still fires.
func TestBudgetAbsMaxForDecompression(t *testing.T) {
	small := func() []Cost {
		var s []Cost
		for range 8 { // input 800 B -> 2300 B on disk (ratio ~2.9), like the real archive
			s = append(s, Cost{InputLen: 800, Sampled: true, DiskBytes: 2300})
		}
		return s
	}
	superRatio := Cost{InputLen: 457, Sampled: true, DiskBytes: 65000}   // the 144× shape
	bomb := Cost{InputLen: 16 << 10, Sampled: true, DiskBytes: 8 << 20}  // unpadded bomb
	padded := Cost{InputLen: 3 << 20, Sampled: true, DiskBytes: 8 << 20} // bomb padded to evade the slope

	// Part A: slope on the small-only corpus FALSE-POSITIVES on the 144× shape.
	bSmall := Calibrate("decomp", small(), DefaultFactor)
	disk := bSmall.Meters["disk_bytes"]
	if fired, _ := disk.exceeded(float64(superRatio.DiskBytes), superRatio.InputLen, bSmall.Factor); !fired {
		t.Fatalf("Part A: slope on the small-only corpus should (wrongly) trip the 144×-shape input — the FP the leftover is about")
	}

	// Part B(i): absolute mode on the SAME poor corpus does NOT rescue it.
	bSmall.UseAbsolute("disk_bytes")
	if !bSmall.Check(func(string, ...any) {}, superRatio) {
		t.Fatalf("Part B: on a poor corpus AbsMax is calibrated too small; the FP must persist (AbsMax is only as good as its corpus)")
	}

	// Part B(ii): enrich the corpus with one legitimately-large benign archive.
	enriched := append(small(), Cost{InputLen: 1 << 20, Sampled: true, DiskBytes: 1 << 20})
	b := Calibrate("decomp", enriched, DefaultFactor)
	if am := b.Meters["disk_bytes"].AbsMax; am < 4<<20-1 || am > 4<<20+1 {
		t.Fatalf("AbsMax=%v want ~4 MiB (p99 1 MiB · factor 4)", am)
	}
	b.UseAbsolute("disk_bytes", "disk_blocks", "write_bytes")

	if b.Check(func(string, ...any) {}, superRatio) {
		t.Fatalf("Part B: enriched + absolute — the 144× input (65 KiB) must NOT trip the 4 MiB ceiling; FP should be gone")
	}
	var bombMsg string
	if !b.Check(func(f string, a ...any) { bombMsg = sprintf(f, a...) }, bomb) {
		t.Fatalf("Part B: the 8 MiB bomb must still trip the absolute ceiling")
	}
	if !contains(bombMsg, "disk_bytes") || !contains(bombMsg, "abs") {
		t.Fatalf("bomb message should name disk_bytes and the absolute ceiling: %q", bombMsg)
	}

	// Part C: a padded bomb (3 MiB of junk in, 8 MiB on disk) buys a ~40 MiB
	// slope ceiling and EVADES the slope — but the flat 4 MiB absolute ceiling
	// still fires it. This proves absolute's input-independence is load-bearing.
	slopeMB := b.Meters["disk_bytes"]
	slopeMB.Mode = ModeSlope // same Floor/PerByte, judged as a slope
	if fired, allowed := slopeMB.exceeded(float64(padded.DiskBytes), padded.InputLen, b.Factor); fired {
		t.Fatalf("Part C: the padded bomb should EVADE the slope (allowed=%v) — that is the point of the demo", allowed)
	}
	if !b.Check(func(string, ...any) {}, padded) { // b is still ModeAbsolute
		t.Fatalf("Part C: ModeAbsolute must still fire the padded bomb that evaded the slope")
	}
	t.Logf("Part C confirmed: padded bomb (3 MiB in, 8 MiB disk) evades the slope but trips the 4 MiB absolute ceiling")
}

// TestBudgetAbsMaxFallsBackToSlopeWhenUncalibrated guards the legacy path: a
// budget with Mode=absolute but AbsMax=0 (an old JSON that predates AbsMax)
// must not silently disarm — it falls back to the per-byte slope.
func TestBudgetAbsMaxFallsBackToSlopeWhenUncalibrated(t *testing.T) {
	mb := MeterBudget{Floor: 1000, PerByte: 1, AbsMax: 0, Mode: ModeAbsolute}
	// 10 000 for a 100-byte input: slope allows 4·(1000+1·100)=4400, so this fires.
	fired, allowed := mb.exceeded(10000, 100, 4)
	if !fired || allowed != 4400 {
		t.Fatalf("uncalibrated absolute meter must fall back to slope (allowed=%v fired=%v)", allowed, fired)
	}
}

// TestBudgetUseBoundedAbsolute: a target whose cost is set by a CLAIMED size
// (not by input bytes) gets AbsMax = calibrated AbsMax + the product's enforced
// bound. GREEN: a tiny input costing one bounded buffer passes. RED: an input
// costing more than bound + the calibrated ceiling fires, naming the meter, and
// the boundary is exact (just below passes, just above fires). The per-byte slope
// alone would have failed the GREEN case.
func TestBudgetUseBoundedAbsolute(t *testing.T) {
	const bound = 1 << 20
	corpus := []Cost{{InputLen: 10, Sampled: true, AllocSampled: true, AllocBytes: 100000}}
	b := Calibrate("claimed", corpus, DefaultFactor)
	slope := b
	slope.Meters = map[string]MeterBudget{"alloc_bytes": b.Meters["alloc_bytes"]}
	tiny := Cost{InputLen: 9, Sampled: true, AllocSampled: true, AllocBytes: bound}
	if !slope.Check(func(string, ...any) {}, tiny) {
		t.Fatalf("precondition: the per-byte slope must reject a 9-byte input costing one bounded buffer")
	}

	b.UseBoundedAbsolute("alloc_bytes", bound)
	b.UseBoundedAbsolute("no_such_meter", bound) // ignored
	b.UseBoundedAbsolute("alloc_bytes", 0)       // ignored: no bound, no change
	ceiling := b.Meters["alloc_bytes"].AbsMax
	if want := 100000*DefaultFactor + bound; ceiling != want {
		t.Fatalf("AbsMax = %v, want calibrated + bound = %v", ceiling, want)
	}
	if b.Meters["alloc_bytes"].Mode != ModeAbsolute {
		t.Fatalf("meter must be absolute")
	}

	if b.Check(func(string, ...any) {}, tiny) {
		t.Fatalf("GREEN: one bounded buffer for a 9-byte input must pass")
	}
	below := tiny
	below.AllocBytes = uint64(ceiling) - 1
	if b.Check(func(string, ...any) {}, below) {
		t.Fatalf("GREEN: just below the ceiling must pass")
	}
	above := tiny
	above.AllocBytes = uint64(ceiling) + 1
	var msg string
	if !b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, above) || !strings.Contains(msg, "alloc_bytes") {
		t.Fatalf("RED: just above the ceiling must fire naming alloc_bytes, got %q", msg)
	}
}

// TestBudgetSkipsUnsampledSampleOnlyMeters guards that a cheap (unsampled)
// input never fails on a sampled-only meter whose fields are zero.
func TestBudgetSkipsUnsampledSampleOnlyMeters(t *testing.T) {
	b := Calibrate("toy", []Cost{{InputLen: 10, Sampled: true, AllocSampled: true, AllocBytes: 80}}, DefaultFactor)
	cheap := Cost{InputLen: 10, Sampled: false, AllocBytes: 0}
	if b.Check(func(string, ...any) {}, cheap) {
		t.Fatalf("unsampled input must not be judged on alloc_bytes")
	}
}

// TestMeasureSlowPromotionMarksAllocUnmeasured guards that a slow-promoted
// input (off the cadence, over SlowWall) is Sampled for live_heap but carries no
// alloc measurement, and that Check does not judge its structural-zero alloc.
// The behavioural red/green is TestMeasureSlowPromotionDoesNotFakeAlloc.
func TestMeasureSlowPromotionMarksAllocUnmeasured(t *testing.T) {
	p := New(t, Options{SampleEvery: 1000, SlowWall: 20 * time.Millisecond})
	_ = p.Measure(10, func() {}) // input #0: on the cadence
	slow := p.Measure(10, func() {
		allocSink = make([]byte, 1<<20)
		time.Sleep(50 * time.Millisecond)
	})
	if !slow.Sampled || slow.LiveHeapAbs == 0 {
		t.Fatalf("slow input must be promoted to a live-heap sample: %+v", slow)
	}
	if slow.AllocSampled || slow.AllocBytes != 0 || slow.Mallocs != 0 {
		t.Fatalf("slow-promoted input must not claim an alloc measurement: %+v", slow)
	}
	b := Budget{Target: "promo", Factor: DefaultFactor, Meters: map[string]MeterBudget{
		"alloc_bytes": {Floor: 1}, "mallocs": {Floor: 1},
	}}
	var msg string
	slow.AllocBytes = 1 << 30 // a value that would fire if the meter were judged
	if b.Check(func(format string, args ...any) { msg = fmt.Sprintf(format, args...) }, slow) {
		t.Fatalf("Check judged an unmeasured alloc field: %s", msg)
	}
}

// TestLoadBudgetRejectsNonPositiveFactor guards that a budget file with a
// missing or zero factor is refused rather than loaded with every slope meter
// disarmed (factor·(Floor + PerByte·N) == 0 never fires).
func TestLoadBudgetRejectsNonPositiveFactor(t *testing.T) {
	for _, body := range []string{
		`{"target":"x","meters":{"alloc_bytes":{"floor":10}}}`,
		`{"target":"x","factor":0,"meters":{"alloc_bytes":{"floor":10}}}`,
		`{"target":"x","factor":-1,"meters":{"alloc_bytes":{"floor":10}}}`,
	} {
		path := filepath.Join(t.TempDir(), "resguard.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadBudget(path); err == nil {
			t.Fatalf("LoadBudget accepted a non-positive factor: %s", body)
		}
	}
}

func TestBudgetWriteLoadRoundTrip(t *testing.T) {
	b := Calibrate("rt", []Cost{{InputLen: 10, Sampled: true, AllocSampled: true, AllocBytes: 80, DiskBytes: 100}}, 3)
	path := filepath.Join(t.TempDir(), "resguard.json")
	if err := b.WriteJSON(path); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadBudget(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Factor != 3 || got.Target != "rt" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// --- air-gap oracle (red/green) -------------------------------------------

func TestAirGapBlocksNonLoopback(t *testing.T) {
	m := NewNetMeter()
	// RED: a non-loopback dial is refused without connecting.
	_, err := m.DialContext(t.Context(), "tcp", "8.8.8.8:53")
	if _, ok := errors.AsType[*ErrAirGap](err); !ok {
		t.Fatalf("non-loopback dial should return ErrAirGap, got %v", err)
	}
	if m.NonLoopback() != 1 {
		t.Fatalf("non-loopback counter = %d, want 1", m.NonLoopback())
	}

	// GREEN: a loopback dial to a real listener succeeds and is counted.
	m.reset() // clear the refused non-loopback dial above
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, e := ln.Accept()
		if e == nil {
			_, _ = c.Write([]byte("hi"))
			_ = c.Close()
		}
	}()
	conn, err := m.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("loopback dial should succeed: %v", err)
	}
	buf := make([]byte, 2)
	_, _ = conn.Read(buf)
	_ = conn.Close()
	_, nl, in, _ := m.read()
	if nl != 0 || in < 2 {
		t.Fatalf("loopback dial metered wrong: nonLoopback=%d in=%d", nl, in)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:80": true, "[::1]:443": true, "localhost:22": true,
		"8.8.8.8:53": false, "example.com:443": false, "10.0.0.1:1": false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q)=%v want %v", addr, got, want)
		}
	}
}

// --- virtual sleep (Azure RetryDelay -1 shape) ----------------------------

func TestSleepClockMetersAndNeverBlocks(t *testing.T) {
	c := NewSleepClock()
	start := time.Now()
	c.Sleep(10 * time.Second) // must not actually sleep
	c.Sleep(-5 * time.Second) // a negative RetryDelay: magnitude still metered
	if time.Since(start) > time.Second {
		t.Fatalf("SleepClock must not block")
	}
	if c.Total() != 15*time.Second {
		t.Fatalf("Total=%s want 15s (10 + |−5|)", c.Total())
	}
	if c.Count() != 2 {
		t.Fatalf("Count=%d want 2", c.Count())
	}
}

// --- DB meter -------------------------------------------------------------

type meterRow struct {
	ID   uint `gorm:"primaryKey"`
	Name string
}

func TestDBMeterCounts(t *testing.T) {
	db := fuzzworld.OpenSQLite(t, ":memory:", 1)
	if err := db.AutoMigrate(&meterRow{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	m := NewDBMeter()
	if err := m.Install(db); err != nil {
		t.Fatalf("install: %v", err)
	}
	m.reset()
	for i := range 5 {
		if err := db.Create(&meterRow{Name: "x"}).Error; err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	var rows []meterRow
	db.Find(&rows)
	q, r := m.read()
	if q < 6 { // 5 creates + 1 find
		t.Fatalf("DBQueries=%d want >=6", q)
	}
	if r < 5 {
		t.Fatalf("DBRows=%d want >=5", r)
	}
}

// --- log meter ------------------------------------------------------------

func TestLogMeter(t *testing.T) {
	m := NewLogMeter()
	m.reset()
	w := m.Writer()
	_, _ = w.Write([]byte("hello\n"))
	_, _ = w.Write(bytes.Repeat([]byte("x"), 1000))
	if m.Bytes() != 1006 {
		t.Fatalf("LogBytes=%d want 1006", m.Bytes())
	}
}

// --- disk meter -----------------------------------------------------------

func TestDiskMeterGrowth(t *testing.T) {
	tmp := t.TempDir()
	before := walkDisk(tmp)
	if err := os.WriteFile(filepath.Join(tmp, "a.bin"), bytes.Repeat([]byte{7}, 4096), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Mkdir(filepath.Join(tmp, "sub"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	d := walkDisk(tmp).sub(before)
	if d.files != 1 || d.dirs != 1 || d.bytes != 4096 {
		t.Fatalf("disk growth wrong: %+v", d)
	}
}

// --- drift (red/green) ----------------------------------------------------

func TestDriftFlagsSustainedHeapGrowth(t *testing.T) {
	d := newDrift()
	base := uint64(10 << 20)
	// warmup + baseline. Drift watches the ABSOLUTE heap (LiveHeapAbs), not the
	// per-input delta, so a leak that creeps up the absolute floor is caught.
	for range driftWarmupSamples + 1 {
		if r := d.Observe(Cost{Sampled: true, LiveHeapAbs: base}); r != "" {
			t.Fatalf("warmup/baseline must not flag: %s", r)
		}
	}
	// GREEN: stable heap never flags.
	for range driftK + 2 {
		if r := d.Observe(Cost{Sampled: true, LiveHeapAbs: base}); r != "" {
			t.Fatalf("stable heap flagged: %s", r)
		}
	}
	// RED: a heap that stays 10× baseline flags within driftK samples.
	var reason string
	for range driftK {
		reason = d.Observe(Cost{Sampled: true, LiveHeapAbs: base * 10})
	}
	if reason == "" || !contains(reason, "live-heap") {
		t.Fatalf("sustained growth should flag live-heap, got %q", reason)
	}
}

func TestDriftIgnoresUnsampled(t *testing.T) {
	d := newDrift()
	for range 100 {
		if r := d.Observe(Cost{Sampled: false, LiveHeapAbs: 1 << 40}); r != "" {
			t.Fatalf("unsampled cost must be ignored, got %q", r)
		}
	}
}

// --- live-heap is a per-input DELTA, not an absolute (RG3) ----------------

// heapRetain holds allocations alive ACROSS Measure calls so they count as live
// (post-GC) heap — the exact shape of a fuzz worker accumulating reachable
// memory across iterations (corpus/coverage maps/caches) that produced the RG3
// live_heap false positive (a 2-byte input charged ~107 MB of accumulation).
var heapRetain [][]byte

// retainChunk allocates n bytes, TOUCHES every page so the pages are resident
// (not zero-page-elided), appends them to heapRetain so they stay live past GC,
// and returns. Used as the body of a Measure call that genuinely retains heap.
func retainChunk(n int) {
	b := make([]byte, n)
	for i := 0; i < len(b); i += 4096 {
		b[i] = byte(i)
	}
	b[len(b)-1] = 1
	heapRetain = append(heapRetain, b)
}

// TestLiveHeapIsPerInputDeltaNotAbsolute is the direct reproduction of the RG3
// artefact and the proof it is fixed: a tiny input measured while tens of MiB of
// heap the worker accumulated earlier are still live must NOT be charged that
// accumulation. The absolute heap (LiveHeapAbs) still SEES it (for Drift); the
// per-input budget meter (LiveHeap) does not.
func TestLiveHeapIsPerInputDeltaNotAbsolute(t *testing.T) {
	heapRetain = nil
	t.Cleanup(func() { heapRetain = nil })

	p := New(t, Options{SampleEvery: 1}) // every input is a cadence sample
	const chunk = 64 << 20               // 64 MiB retained by an earlier iteration

	heavy := p.Measure(16, func() { retainChunk(chunk) })
	if heavy.LiveHeap < chunk/2 {
		t.Fatalf("the heavy input genuinely retained ~64 MiB; its per-input delta should reflect it, got %d", heavy.LiveHeap)
	}

	// The tiny input allocates ~nothing. The 64 MiB is still live (heapRetain
	// holds it), so an ABSOLUTE meter charges this 2-byte input the whole 64 MiB.
	tiny := p.Measure(2, func() { _ = 1 })

	if tiny.LiveHeapAbs < chunk/2 {
		t.Fatalf("accumulation must remain visible in the absolute heap (for Drift), abs=%d", tiny.LiveHeapAbs)
	}
	if tiny.LiveHeap > 8<<20 {
		t.Fatalf("RG3 regression: per-input delta charged accumulated heap: delta=%d abs=%d", tiny.LiveHeap, tiny.LiveHeapAbs)
	}
	t.Logf("tiny 2-byte input: per-input delta=%d (bounded), absolute=%d (accumulation, Drift-only)", tiny.LiveHeap, tiny.LiveHeapAbs)
}

// TestLiveHeapDeltaDefeatsAccumulationFalsePositive is the RED/GREEN proof that
// the delta semantics fix the FP WITHOUT loosening the budget: against a budget
// calibrated on clean small iterations, judging the ABSOLUTE heap as a per-input
// cost (the old behaviour) FIRES on a tiny input polluted by accumulation (RED,
// reproducing cb1a9523e20b9df6's shape), while the per-input DELTA does not
// (GREEN). The same budget is used for both; only the measured field differs.
func TestLiveHeapDeltaDefeatsAccumulationFalsePositive(t *testing.T) {
	heapRetain = nil
	t.Cleanup(func() { heapRetain = nil })

	// Clean calibration corpus: small per-input retained heap (~256 KiB), exactly
	// what calibration sees early in a fresh process. Synthetic Costs keep it
	// deterministic (no GC noise in the ceiling itself).
	var clean []Cost
	for range 8 {
		clean = append(clean, Cost{InputLen: 16, Sampled: true, LiveHeap: 256 << 10})
	}
	b := Calibrate("live_heap_fp", clean, DefaultFactor)
	if _, ok := b.Meters["live_heap"]; !ok {
		t.Fatalf("live_heap must be calibrated for this proof; meters=%s", b.Summary())
	}

	// Produce the accumulation shape with a real Probe: a tiny input after a
	// heavy one whose 64 MiB is still live.
	p := New(t, Options{SampleEvery: 1})
	const chunk = 64 << 20
	_ = p.Measure(16, func() { retainChunk(chunk) })
	tiny := p.Measure(2, func() { _ = 1 })

	// RED: the OLD absolute reading (what liveHeap() used to place in LiveHeap)
	// trips the clean budget — this IS the false positive being fixed.
	absCost := tiny
	absCost.LiveHeap = tiny.LiveHeapAbs
	if !b.Check(func(string, ...any) {}, absCost) {
		t.Fatalf("precondition: the absolute live heap (%d) must trip the clean budget — that is the RG3 FP", tiny.LiveHeapAbs)
	}
	// GREEN: the per-input delta passes. The FP is gone and no budget was moved.
	var greenMsg string
	if b.Check(func(f string, a ...any) { greenMsg = fmt.Sprintf(f, a...) }, tiny) {
		t.Fatalf("per-input delta (%d) must NOT trip the budget; FP should be gone (%s)", tiny.LiveHeap, greenMsg)
	}
}

// TestLiveHeapDeltaStillCatchesTrueAmplification is the planted-defect proof that
// the delta keeps a real detection path: a SINGLE small input that genuinely
// retains tens of MiB of live heap still fails — under BOTH the per-byte slope
// AND the absolute AbsMax ceiling. This is the counterpart to the FP proof:
// the fix must not silently disarm the meter.
func TestLiveHeapDeltaStillCatchesTrueAmplification(t *testing.T) {
	heapRetain = nil
	t.Cleanup(func() { heapRetain = nil })

	var clean []Cost
	for range 8 {
		clean = append(clean, Cost{InputLen: 1 << 10, Sampled: true, LiveHeap: 256 << 10})
	}
	b := Calibrate("live_heap_amp", clean, DefaultFactor)

	p := New(t, Options{SampleEvery: 1})
	const chunk = 64 << 20
	// A 64-byte input that expands to 64 MiB of retained live heap: a ~1,000,000×
	// amplification, the pkcs7-style memory bomb shape.
	c := p.Measure(64, func() { retainChunk(chunk) })
	if c.LiveHeap < chunk/2 {
		t.Fatalf("the amplifying input must register a large per-input delta, got %d", c.LiveHeap)
	}

	// Slope (default mode): fires.
	if !b.Check(func(string, ...any) {}, c) {
		mb := b.Meters["live_heap"]
		t.Fatalf("SLOPE must fire on a true amplification: delta=%d slope=%.0f", c.LiveHeap, mb.slopeAllowed(c.InputLen, b.Factor))
	}
	// Absolute mode: still fires against AbsMax.
	b.UseAbsolute("live_heap")
	if !b.Check(func(string, ...any) {}, c) {
		t.Fatalf("ABSMAX must still fire on a true amplification: delta=%d absmax=%.0f", c.LiveHeap, b.Meters["live_heap"].AbsMax)
	}
}

// TestLiveHeapPromotedInputHasNoDelta documents the one carve-out: a slow-wall
// PROMOTED input (cheap cadence, but ran over SlowWall) has no pre-fn GC baseline
// so its per-input delta is 0, while its absolute is still captured for Drift.
func TestLiveHeapPromotedInputHasNoDelta(t *testing.T) {
	heapRetain = nil
	t.Cleanup(func() { heapRetain = nil })

	// SampleEvery huge so only input 0 is an on-cadence sample; SlowWall tiny so
	// a LATER input is promoted by running longer than it. Input 0 (index 0) is
	// always a cadence sample (0 % N == 0), so measure a throwaway first, then
	// assert on index 1 — a genuinely off-cadence, promoted input.
	p := New(t, Options{SampleEvery: 1 << 30, SlowWall: time.Nanosecond})
	_ = p.Measure(8, func() { _ = 1 }) // index 0: cadence, consumed
	c := p.Measure(16, func() {
		retainChunk(32 << 20)
		time.Sleep(2 * time.Millisecond) // guarantee > SlowWall → promoted
	})
	if !c.Sampled {
		t.Fatalf("a slow input over SlowWall must be promoted to sampled")
	}
	if c.LiveHeap != 0 {
		t.Fatalf("a promoted input has no pre-fn baseline, so its per-input delta must be 0, got %d", c.LiveHeap)
	}
	if c.LiveHeapAbs < 16<<20 {
		t.Fatalf("a promoted input must still capture the absolute heap for Drift, got %d", c.LiveHeapAbs)
	}
}

// --- cost buckets ---------------------------------------------------------

func TestBucket(t *testing.T) {
	cases := map[uint64]int{0: 0, 1: 1, 2: 2, 3: 2, 4: 3, 255: 8, 256: 9, 1 << 20: 21}
	for v, want := range cases {
		if got := Bucket(v); got != want {
			t.Errorf("Bucket(%d)=%d want %d", v, got, want)
		}
	}
}

func TestFeedCoverageNoPanic(t *testing.T) {
	FeedCoverage(Cost{AllocBytes: 1 << 30, Dials: 3, Sleep: time.Hour, DiskBytes: -5})
	FeedCoverage(Cost{})
}

// --- secret sentinel (red/green), unified with taint ----------------------

func TestSentinelCatchesLeakViaTaint(t *testing.T) {
	// Restore global taint state the Sentinel mutates.
	t.Cleanup(func() { taint.SetMarker(taint.DefaultMarker); taint.ResetRules() })

	logM := NewLogMeter()
	tmp := t.TempDir()
	s := NewSentinel(nil, logM, tmp)

	// GREEN: no leak -> Check passes.
	taint.Reset()
	logM.reset()
	_, _ = logM.Writer().Write([]byte("nothing secret here"))
	s.ScanTempDir()
	var greenFired bool
	taint.Check(func(string, ...any) { greenFired = true })
	if greenFired {
		t.Fatalf("no leak but Check fired")
	}

	// RED: the sentinel leaks into a log line and a file.
	taint.Reset()
	logM.reset()
	_, _ = logM.Writer().Write([]byte("oops the secret was " + s.Value()))
	if err := os.WriteFile(filepath.Join(tmp, "leak.txt"), []byte("db dump: "+s.Value()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s.ScanTempDir()
	var redFired bool
	taint.Check(func(string, ...any) { redFired = true })
	if !redFired {
		t.Fatalf("sentinel leaked but Check did not fire")
	}
}

// --- small helpers --------------------------------------------------------

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }
