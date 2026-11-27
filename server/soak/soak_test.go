// Package soak is a long-running-server resource-growth harness (SOAK-1).
//
// Every other harness in this repository asserts per-request correctness. None
// asserts that the server does not slowly GROW: goroutines, file descriptors,
// database connections, heap, temp files, rows in bookkeeping tables. A leak of
// one goroutine per request is invisible to a 15-minute fuzz run and fatal to
// an air-gapped on-premise deployment that runs for months unattended. This
// package drives the real server/http router with a seeded mixed workload,
// samples those series at fixed intervals, and applies three oracles (see
// oracles_test.go, which also lists what the soak does NOT verify).
//
// Modes (environment, because go test flags would have to be parsed before
// TestMain):
//
//	KEYORIX_SOAK unset   the default `go test`: oracle and sampler unit tests
//	                     only, no server (fast, deterministic, CI-safe).
//	KEYORIX_SOAK=smoke   about a minute on SQLite: 10000 requests, 2 workers,
//	                     then the idle drain and the hard oracles. Used by the
//	                     red-proof (testdata/redproof/run.sh).
//	KEYORIX_SOAK=long    KEYORIX_SOAK_DURATION (default 30m) of load with
//	                     KEYORIX_SOAK_WORKERS (default 4) workers. SQLite, or
//	                     PostgreSQL when KEYORIX_TEST_PG_DSN is set. Writes the
//	                     series as TSV to KEYORIX_SOAK_SERIES.
//
// See README.md for the commands, the coverage table and the calibration.
package soak

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestMain fails the package when a test leaves a goroutine of this package, an
// httptest server or a database/sql opener behind (the same idea as
// internal/storage/background_job_leak_main_test.go): the harness must not leak
// what it is built to find.
func TestMain(m *testing.M) {
	if os.Getenv("KEYORIX_SOAK_HEAPPROFILE") != "" {
		runtime.MemProfileRate = 4096 // fine enough to name small per-request allocations
	}
	code := m.Run()
	var leaked []string
	deadline := time.Now().Add(10 * time.Second)
	for {
		leaked = leaked[:0]
		for sig, g := range goroutineGroups() {
			if ownStack(sig) {
				continue
			}
			if strings.Contains(sig, "keyorix/server/soak.") || strings.Contains(sig, "httptest.(*Server)") ||
				strings.Contains(sig, "sql.(*DB).connectionOpener") {
				leaked = append(leaked, g.Full)
			}
		}
		if len(leaked) == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(leaked) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d goroutine group(s) of the soak harness outlived every test:\n%s\n", len(leaked), strings.Join(leaked, "\n"))
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

type runConfig struct {
	Name        string
	Seed        int64
	Workers     int
	Requests    int64         // fixed request count (smoke); 0 means use Duration
	Duration    time.Duration // load time (long)
	WarmupRound int
	SampleEvery time.Duration
	Idle        time.Duration // quiet period before the first post-load check
	Drain       time.Duration // how long the post-load checks keep polling
	SeriesPath  string
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

func configFor(mode string) (runConfig, bool) {
	switch mode {
	case "smoke":
		return runConfig{Name: "smoke", Seed: int64(envInt("KEYORIX_SOAK_SEED", 1)), Workers: 2, Requests: 10000, WarmupRound: 2,
			SampleEvery: 2 * time.Second, Idle: 2 * time.Second, Drain: 20 * time.Second,
			SeriesPath: os.Getenv("KEYORIX_SOAK_SERIES")}, true
	case "long":
		d, err := time.ParseDuration(os.Getenv("KEYORIX_SOAK_DURATION"))
		if err != nil || d <= 0 {
			d = 30 * time.Minute
		}
		return runConfig{Name: "long", Seed: int64(envInt("KEYORIX_SOAK_SEED", 1)), Workers: envInt("KEYORIX_SOAK_WORKERS", 4), Duration: d, WarmupRound: 3,
			SampleEvery: 10 * time.Second, Idle: 30 * time.Second, Drain: 2 * time.Minute,
			SeriesPath: os.Getenv("KEYORIX_SOAK_SERIES")}, true
	}
	return runConfig{}, false
}

type runReport struct {
	Base, Final sample
	InLoad      []sample
	Verdicts    []verdict
	Stats       map[string]*kindStats
	Requests    int64
	Elapsed     time.Duration
	Unmet       []string // mix kinds that never did their job
}

// TestSoak is the opt-in entry point; see the package comment.
func TestSoak(t *testing.T) {
	mode := os.Getenv("KEYORIX_SOAK")
	cfg, ok := configFor(mode)
	if !ok {
		t.Skip("soak run is opt-in: set KEYORIX_SOAK=smoke (about a minute) or KEYORIX_SOAK=long (see server/soak/README.md); the default run covers only the oracle unit tests")
	}
	env := newSoakEnv(t)
	t.Logf("SOAK mode=%s backend=%s seed=%d workers=%d requests=%d duration=%s tmpdir=%s", cfg.Name, env.backend, cfg.Seed, cfg.Workers, cfg.Requests, cfg.Duration, env.tmpDir)
	rep := runSoak(t, env, cfg)

	for _, v := range rep.Verdicts {
		t.Logf("SOAK %s", v)
		if v.Hard && v.Status == "FAIL" {
			t.Errorf("hard oracle failed: %s", v)
		}
	}
	for _, k := range rep.Unmet {
		t.Errorf("mix kind %q never did its job (no effective request): the run did not exercise it, so a green result says nothing about it", k)
	}
	t.Logf("SOAK done: %d requests in %s", rep.Requests, rep.Elapsed.Round(time.Millisecond))
}

// runSoak runs warm-up, baseline, load with sampling, idle drain and the oracles.
func runSoak(t *testing.T, env *soakEnv, cfg runConfig) *runReport {
	t.Helper()
	ctx := context.Background()
	budget := &failedLoginBudget{window: 15 * time.Minute, max: 8}
	workers := make([]*worker, cfg.Workers)
	for i := range workers {
		workers[i] = newWorker(ctx, env, i, cfg.Seed, budget)
		if err := workers[i].setup(); err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}

	// Warm-up: every kind of the mix runs, so lazily started workers and caches
	// exist before the baseline.
	var warm atomic.Int64
	for _, w := range workers {
		w.warmup(cfg.WarmupRound, &warm)
	}
	env.tr.CloseIdleConnections()
	time.Sleep(500 * time.Millisecond)
	started := time.Now()
	base := takeSample(env, 0, started, 0, true, false)
	writeHeapProfile(t, "baseline")
	t.Logf("SOAK baseline after %d warm-up requests: goroutines=%d fds=%d db_open=%d temp_files=%d", warm.Load(), base.Goroutines, base.FDs, base.DBOpen, base.TempFiles)

	// Load.
	var load atomic.Int64
	var wg sync.WaitGroup
	deadline := started.Add(cfg.Duration)
	for _, w := range workers {
		wg.Go(func() {
			for {
				if cfg.Requests > 0 {
					if load.Add(1) > cfg.Requests {
						return
					}
				} else {
					if time.Now().After(deadline) {
						return
					}
					load.Add(1)
				}
				w.do(w.next())
			}
		})
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	var inLoad []sample
	tick := time.NewTicker(cfg.SampleEvery)
	seq := 1
sampling:
	for {
		select {
		case <-done:
			break sampling
		case <-tick.C:
			inLoad = append(inLoad, takeSample(env, seq, started, min(load.Load(), cfg.requestsCap()), false, false))
			seq++
		}
	}
	tick.Stop()
	elapsed := time.Since(started)
	requests := min(load.Load(), cfg.requestsCap())
	inLoad = append(inLoad, takeSample(env, seq, started, requests, false, false))

	// Idle drain, then poll the hard oracles until they hold or the deadline passes.
	env.tr.CloseIdleConnections()
	time.Sleep(cfg.Idle)
	var final sample
	var hard []verdict
	drainEnd := time.Now().Add(cfg.Drain)
	for n := 0; ; n++ {
		env.tr.CloseIdleConnections()
		final = takeSample(env, seq+1+n, started, requests, true, true)
		hard = append(checkReturnToBaseline(base, final, defaultTolerances), checkNewStacks(base, final, stackAllowlist)...)
		if !anyHardFail(hard) || time.Now().After(drainEnd) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	writeHeapProfile(t, "final")
	rep := &runReport{Base: base, Final: final, InLoad: inLoad, Requests: requests, Elapsed: elapsed, Stats: mergeStats(workers)}
	rep.Verdicts = append(checkSlopes(inLoad, loadCalibration(filepath.Join("testdata", "calibration.tsv"))), hard...)
	for _, k := range soakMix {
		if s := rep.Stats[k.Name]; s == nil || s.Effective == 0 {
			rep.Unmet = append(rep.Unmet, k.Name)
		}
	}
	logMix(t, rep)
	if cfg.SeriesPath != "" {
		if err := writeSeries(cfg.SeriesPath, base, inLoad, final); err != nil {
			t.Errorf("write series: %v", err)
		} else {
			t.Logf("SOAK series written to %s", cfg.SeriesPath)
		}
	}
	return rep
}

// writeHeapProfile writes the live-heap profile to $KEYORIX_SOAK_HEAPPROFILE/<name>.pb.gz
// (after the sampler's GC), so a heap_inuse slope can be attributed:
//
//	go tool pprof -sample_index=inuse_space -base baseline.pb.gz final.pb.gz
func writeHeapProfile(t *testing.T, name string) {
	t.Helper()
	dir := os.Getenv("KEYORIX_SOAK_HEAPPROFILE")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Errorf("heap profile dir: %v", err)
		return
	}
	runtime.GC()
	f, err := os.Create(filepath.Join(dir, name+".pb.gz")) //nolint:gosec // test-only path from the operator's own env
	if err != nil {
		t.Errorf("heap profile: %v", err)
		return
	}
	defer func() { _ = f.Close() }()
	if err := pprof.Lookup("heap").WriteTo(f, 0); err != nil {
		t.Errorf("heap profile: %v", err)
	}
	t.Logf("SOAK heap profile written to %s", f.Name())
}

func (c runConfig) requestsCap() int64 {
	if c.Requests > 0 {
		return c.Requests
	}
	return 1 << 62
}

func anyHardFail(vs []verdict) bool {
	for _, v := range vs {
		if v.Hard && v.Status == "FAIL" {
			return true
		}
	}
	return false
}

func mergeStats(ws []*worker) map[string]*kindStats {
	out := map[string]*kindStats{}
	for _, w := range ws {
		for name, s := range w.stats {
			o := out[name]
			if o == nil {
				o = &kindStats{Statuses: map[int]int64{}}
				out[name] = o
			}
			o.Count += s.Count
			o.Effective += s.Effective
			o.Errors += s.Errors
			for st, n := range s.Statuses {
				o.Statuses[st] += n
			}
		}
	}
	return out
}

func logMix(t *testing.T, rep *runReport) {
	t.Helper()
	for _, k := range soakMix {
		s := rep.Stats[k.Name]
		if s == nil {
			t.Logf("SOAK mix %-20s never ran", k.Name)
			continue
		}
		var sts []string
		for st, n := range s.Statuses {
			sts = append(sts, fmt.Sprintf("%d:%d", st, n))
		}
		sort.Strings(sts)
		t.Logf("SOAK mix %-20s n=%-5d effective=%-5d transport_err=%-4d statuses=%s", k.Name, s.Count, s.Effective, s.Errors, strings.Join(sts, " "))
	}
}

// writeSeries writes every sample as one TSV row, baseline first.
func writeSeries(path string, base sample, inLoad []sample, final sample) error {
	tables := map[string]bool{}
	for _, s := range append([]sample{base, final}, inLoad...) {
		for t := range s.Rows {
			tables[t] = true
		}
	}
	var names []string
	for t := range tables {
		names = append(names, t)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("phase\tseq\tat_s\trequests\tgoroutines\theap_inuse\theap_objects\tfds\tdb_open\tdb_in_use\tdb_idle\tdb_wait\ttemp_files")
	for _, n := range names {
		b.WriteString("\trows_" + n)
	}
	b.WriteString("\n")
	row := func(phase string, s sample) {
		fmt.Fprintf(&b, "%s\t%d\t%.1f\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d", phase, s.Seq, s.At.Seconds(), s.Requests,
			s.Goroutines, s.HeapInuse, s.HeapObjects, s.FDs, s.DBOpen, s.DBInUse, s.DBIdle, s.DBWaitCount, s.TempFiles)
		for _, n := range names {
			fmt.Fprintf(&b, "\t%d", s.Rows[n])
		}
		b.WriteString("\n")
	}
	row("baseline", base)
	for _, s := range inLoad {
		row("load", s)
	}
	row("final", final)
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
