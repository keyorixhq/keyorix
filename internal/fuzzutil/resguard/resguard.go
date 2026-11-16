// Package resguard is the shared resource-measurement layer for the repo's fuzz
// targets. It wraps one fuzz input and returns a Cost vector covering the
// resources that real Keyorix defects actually blew — RAM and CPU spikes
// (pkcs7 130 B→1.8 GB, the connector gzip bomb, Azure RetryDelay -1, the bcrypt
// hang) — plus the ones nothing previously metered at all: disk, inodes, fds,
// goroutines, threads, network dials, virtual-time sleeps, log volume and DB
// query cost.
//
// # Why a new package and not an extension of internal/fuzzutil/complexity
//
// complexity is deliberately a pure leaf: it imports only runtime and time so
// it adds nothing to a fuzz binary's coverage map beyond the standard library,
// and it answers exactly one question — did allocation per input byte stay
// bounded. resguard needs testing.TB, syscalls, /proc, http.RoundTripper and
// gorm seams; folding that into complexity would bloat the leaf every alloc
// fuzzer links. So resguard COMPOSES complexity (it calls complexity.Measure
// for the alloc delta rather than re-deriving ReadMemStats — there is no second
// copy of that logic) and adds the environment meters around it. complexity
// stays the thing you reach for when all you want is the alloc ratio.
//
// # Cheap vs expensive meters, and the sampling rate
//
// Cheap meters run on EVERY input: wall clock, process CPU (getrusage),
// goroutines, OS threads, open fds. They cost a getrusage and two small /proc
// reads (~microseconds) and are read as deltas.
//
// Expensive meters run on a SAMPLE: runtime.ReadMemStats (a stop-the-world),
// live-heap-after-GC (a full GC), and the TempDir walk. They fire when
// (input index % SampleEvery == 0) OR the cheap wall clock already showed the
// input was slow (over SlowWall) — a slow or large input is exactly the one
// worth paying to measure. The stock `go test -fuzz` engine does not expose
// "this input found new coverage" to the target, so that third trigger from the
// task is approximated by the slow-wall trigger (documented, not silently
// dropped). Measured overhead of the expensive path on this host is recorded in
// the package test (TestExpensiveSampleOverhead) and the RSG1 report.
//
// # Application meters are seams, not magic
//
// Network, virtual-sleep, log-byte and DB meters can only see what the harness
// routes through the seam this package hands it (NetMeter's Transport/Dialer,
// SleepClock, LogMeter's Writer, the gorm DB plugin). Code that bypasses the
// seam is invisible — which is itself the point of the air-gap oracle: the
// NetMeter's dialer FAILS any non-loopback dial, so code that reaches for the
// real network instead of the hardened client (ADR #1949) is caught.
//
// Test-only: nothing outside *_test.go may import this package (enforced by
// TestResguardImportedOnlyFromTests).
package resguard

import (
	"runtime"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/complexity"
)

// procStats is one sample of the cheap per-process meters (see platform_*.go).
type procStats struct {
	ok         bool
	cpu        time.Duration
	threads    int
	openFDs    int
	writeBytes uint64
}

// Cost is the measured cost of a single fuzz input. Fields measured only on a
// sampled input (see package doc) are zero on an unsampled input; Sampled says
// which it was, so a budget never compares an unsampled zero against a ceiling.
type Cost struct {
	InputLen int
	Sampled  bool

	// Cheap meters (every input). CPU/Threads/OpenFDs are process-wide deltas
	// and advisory under -parallel>1 (see platform_linux.go caveat).
	Wall       time.Duration
	CPU        time.Duration
	Goroutines int
	Threads    int
	OpenFDs    int

	// Expensive meters (sampled): alloc/live-heap force a ReadMemStats/GC.
	AllocBytes uint64
	Mallocs    uint64
	LiveHeap   uint64 // HeapAlloc after a forced GC

	// Cheap every-input meters. WriteBytes is /proc/self/io write_bytes delta
	// (Linux) and reads ~0 on a tmpfs TMPDIR; the disk fields are the TempDir
	// walk growth and are the reliable disk meter there.
	WriteBytes uint64

	// Disk: growth of the TempDir tree across the input (every input).
	DiskFiles    int
	DiskDirs     int
	DiskSymlinks int
	DiskBytes    int64
	DiskBlocks   int64

	// Application meters (every input, but only count what the seams saw).
	Dials            int
	NonLoopbackDials int
	NetBytesIn       int64
	NetBytesOut      int64
	Sleep            time.Duration
	LogBytes         int64
	DBQueries        int
	DBRows           int64
}

// Options configures a Probe. The zero value is usable: SampleEvery defaults to
// defaultSampleEvery and SlowWall to defaultSlowWall.
type Options struct {
	// TempDir is the directory whose growth the disk meter watches. Pass
	// t.TempDir() (or the staging root a target writes under). "" disables the
	// disk meter.
	TempDir string
	// SampleEvery N means the expensive meters fire on inputs 0, N, 2N, …
	// 0 selects defaultSampleEvery.
	SampleEvery int
	// SlowWall forces an expensive sample on any input slower than this even if
	// it is not on the sampling cadence. 0 selects defaultSlowWall.
	SlowWall time.Duration
	// Net, Clock, Log, DB are the application-meter seams. Leave any nil to
	// skip that meter; the Probe reads and resets whichever are set.
	Net   *NetMeter
	Clock *SleepClock
	Log   *LogMeter
	DB    *DBMeter
}

const (
	defaultSampleEvery = 64
	defaultSlowWall    = 100 * time.Millisecond
)

// Probe is created once per testing.F (before f.Fuzz) and measures each input.
// It is NOT safe for concurrent use across workers; create one per worker if
// the harness runs the body on multiple goroutines (the stock engine runs one
// body at a time per process, so one Probe per F is correct for -parallel too —
// -parallel forks processes, not goroutines, for the body).
type Probe struct {
	opts  Options
	n     int64
	drift *Drift
}

// New builds a Probe. tb is used only to default TempDir to tb-independent
// values and for symmetry with the rest of the fuzz helpers; the Probe does not
// retain tb.
func New(tb testing.TB, opts Options) *Probe {
	tb.Helper()
	if opts.SampleEvery <= 0 {
		opts.SampleEvery = defaultSampleEvery
	}
	if opts.SlowWall <= 0 {
		opts.SlowWall = defaultSlowWall
	}
	return &Probe{opts: opts, drift: newDrift()}
}

// Measure runs fn once and returns its Cost. inputLen is the size in bytes of
// the attacker-controlled input the ratios are measured against — NOT the size
// of any decoded/expanded form, which is exactly what an amplification inflates.
//
// fn must drive exactly one input through the code under test. The seams
// (Options.Net/Clock/Log/DB) are read and reset around fn, so their counts are
// this input's alone.
func (p *Probe) Measure(inputLen int, fn func()) Cost {
	n := p.n
	p.n++
	expensive := n%int64(p.opts.SampleEvery) == 0

	p.resetSeams()

	before := readProcStats()
	g0 := runtime.NumGoroutine()
	// The disk-walk is a CHEAP meter (every input): a fresh per-input TempDir is
	// a small tree, and on a tmpfs TMPDIR /proc/self/io write_bytes reads ~0 (no
	// block-layer writes), so the walk is the only reliable disk meter there.
	var diskBefore diskSnap
	watch := p.opts.TempDir != ""
	if watch {
		diskBefore = walkDisk(p.opts.TempDir)
	}

	c := Cost{InputLen: inputLen}
	if expensive {
		cc := complexity.Measure(fn) // reuses complexity's exact ReadMemStats delta
		c.Wall = cc.Wall
		c.AllocBytes = cc.AllocBytes
		c.Mallocs = cc.AllocObjects
	} else {
		start := time.Now()
		fn()
		c.Wall = time.Since(start)
		// A cheap input that turned out slow earns the expensive (alloc) sample.
		if c.Wall > p.opts.SlowWall {
			expensive = true
		}
	}

	after := readProcStats()
	g1 := runtime.NumGoroutine()
	c.Goroutines = g1 - g0
	if before.ok && after.ok {
		c.CPU = after.cpu - before.cpu
		c.Threads = after.threads - before.threads
		c.OpenFDs = after.openFDs - before.openFDs
		c.WriteBytes = after.writeBytes - before.writeBytes
	}
	if watch {
		d := walkDisk(p.opts.TempDir).sub(diskBefore)
		c.DiskFiles, c.DiskDirs, c.DiskSymlinks = d.files, d.dirs, d.symlinks
		c.DiskBytes, c.DiskBlocks = d.bytes, d.blocks
	}

	c.Sampled = expensive
	if expensive {
		c.LiveHeap = liveHeap()
	}

	p.readSeams(&c)
	return c
}

func (p *Probe) resetSeams() {
	if p.opts.Net != nil {
		p.opts.Net.reset()
	}
	if p.opts.Clock != nil {
		p.opts.Clock.reset()
	}
	if p.opts.Log != nil {
		p.opts.Log.reset()
	}
	if p.opts.DB != nil {
		p.opts.DB.reset()
	}
}

func (p *Probe) readSeams(c *Cost) {
	if p.opts.Net != nil {
		c.Dials, c.NonLoopbackDials, c.NetBytesIn, c.NetBytesOut = p.opts.Net.read()
	}
	if p.opts.Clock != nil {
		c.Sleep = p.opts.Clock.Total()
	}
	if p.opts.Log != nil {
		c.LogBytes = p.opts.Log.Bytes()
	}
	if p.opts.DB != nil {
		c.DBQueries, c.DBRows = p.opts.DB.read()
	}
}

// liveHeap forces a GC and returns the live heap. Expensive; sampled callers
// only. A single GC settles finalizer-reachable garbage from the previous input
// so cross-input drift (see Drift) is measured against truly-live memory.
func liveHeap() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// WatchDir points the disk meter at dir for subsequent Measure calls. Use it
// when the harness creates a fresh t.TempDir() per input (the common shape), so
// one Probe built per testing.F can still watch each input's own staging tree.
func (p *Probe) WatchDir(dir string) { p.opts.TempDir = dir }

// Platform reports the meter backend ("linux" / "unsupported"); handy in a
// target's t.Logf so a run on an unsupported OS is self-documenting.
func Platform() string { return platformName }
