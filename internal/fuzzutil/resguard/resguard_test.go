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
	if !c0.Sampled {
		t.Fatalf("input 0 should be sampled")
	}
	if c0.AllocBytes < 1<<16 {
		t.Fatalf("sampled input should see the 64 KiB alloc, got %d", c0.AllocBytes)
	}
	c1 := p.Measure(10, func() { allocSink = make([]byte, 1<<16) })
	if c1.Sampled {
		t.Fatalf("input 1 should be cheap (not sampled)")
	}
	if c1.AllocBytes != 0 {
		t.Fatalf("cheap input must not read memstats, got AllocBytes=%d", c1.AllocBytes)
	}
}

// TestExpensiveSampleOverhead records, on this host, the wall overhead the
// expensive sample path adds over the cheap path. It never fails on a number
// (that would be a calendar-at-PR-time guard); it only asserts the expensive
// path is not absurdly slower and logs the measured ratio for the report.
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
		t.Fatalf("expensive path should cost at least as much as cheap")
	}
}

// --- budget calibration & check (red/green) -------------------------------

func TestBudgetCalibrateAndCheck(t *testing.T) {
	// Benign seed corpus: alloc ~ 8·N bytes, no disk/net.
	var seeds []Cost
	for n := 10; n <= 100; n += 10 {
		seeds = append(seeds, Cost{InputLen: n, Sampled: true, AllocBytes: uint64(8 * n), Wall: time.Millisecond})
	}
	b := Calibrate("toy", seeds, DefaultFactor)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated")
	}

	// GREEN: a benign input within the slope passes.
	green := Cost{InputLen: 50, Sampled: true, AllocBytes: 8 * 50, Wall: time.Millisecond}
	var greenFired bool
	b.Check(func(string, ...any) { greenFired = true }, green)
	if greenFired {
		t.Fatalf("benign input must not trip the budget")
	}

	// RED: a 100-byte input that allocates 50 MiB (amplification) fails.
	red := Cost{InputLen: 100, Sampled: true, AllocBytes: 50 << 20, Wall: 5 * time.Millisecond}
	var redMsg string
	fired := b.Check(func(f string, a ...any) { redMsg = sprintf(f, a...) }, red)
	if !fired {
		t.Fatalf("amplifying input must trip the budget")
	}
	if !contains(redMsg, "alloc_bytes") || !contains(redMsg, "amp=") {
		t.Fatalf("failure message should name the meter and amplification: %q", redMsg)
	}
}

// TestBudgetSkipsUnsampledSampleOnlyMeters guards that a cheap (unsampled)
// input never fails on a sampled-only meter whose fields are zero.
func TestBudgetSkipsUnsampledSampleOnlyMeters(t *testing.T) {
	b := Calibrate("toy", []Cost{{InputLen: 10, Sampled: true, AllocBytes: 80}}, DefaultFactor)
	cheap := Cost{InputLen: 10, Sampled: false, AllocBytes: 0}
	if b.Check(func(string, ...any) {}, cheap) {
		t.Fatalf("unsampled input must not be judged on alloc_bytes")
	}
}

func TestBudgetWriteLoadRoundTrip(t *testing.T) {
	b := Calibrate("rt", []Cost{{InputLen: 10, Sampled: true, AllocBytes: 80, DiskBytes: 100}}, 3)
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
	var ag *ErrAirGap
	if !errors.As(err, &ag) {
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
	// warmup + baseline
	for range driftWarmupSamples + 1 {
		if r := d.Observe(Cost{Sampled: true, LiveHeap: base}); r != "" {
			t.Fatalf("warmup/baseline must not flag: %s", r)
		}
	}
	// GREEN: stable heap never flags.
	for range driftK + 2 {
		if r := d.Observe(Cost{Sampled: true, LiveHeap: base}); r != "" {
			t.Fatalf("stable heap flagged: %s", r)
		}
	}
	// RED: a heap that stays 10× baseline flags within driftK samples.
	var reason string
	for range driftK {
		reason = d.Observe(Cost{Sampled: true, LiveHeap: base * 10})
	}
	if reason == "" || !contains(reason, "live-heap") {
		t.Fatalf("sustained growth should flag live-heap, got %q", reason)
	}
}

func TestDriftIgnoresUnsampled(t *testing.T) {
	d := newDrift()
	for range 100 {
		if r := d.Observe(Cost{Sampled: false, LiveHeap: 1 << 40}); r != "" {
			t.Fatalf("unsampled cost must be ignored, got %q", r)
		}
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
