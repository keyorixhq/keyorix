package soak

// oracles_unit_test.go: each oracle on synthetic samples, both directions. The
// default `go test` runs these (no server). The end-to-end red-proof, with a
// real planted leak in a real server, is testdata/redproof/run.sh.

import (
	"strings"
	"testing"
)

func flatSample() sample {
	return sample{
		Goroutines: 20, FDs: 30, DBOpen: 2, DBInUse: 0, DBIdle: 2,
		Stacks: map[string]stackGroup{
			"runtime.gopark < net/http.(*Server).Serve": {Sig: "runtime.gopark < net/http.(*Server).Serve", Top: "net/http.(*Server).Serve", Count: 1},
		},
	}
}

func hasStatus(vs []verdict, series, status string) bool {
	for _, v := range vs {
		if v.Series == series && v.Status == status {
			return true
		}
	}
	return false
}

func TestOracleBaseline_FlatIsGreen(t *testing.T) {
	b := flatSample()
	f := flatSample()
	f.Goroutines += defaultTolerances.Goroutines // exactly at the tolerance is still green
	for _, v := range checkReturnToBaseline(b, f, defaultTolerances) {
		if v.Status != "PASS" {
			t.Errorf("flat series must pass, got %s", v)
		}
	}
}

func TestOracleBaseline_EachSeriesFiresAndNamesItself(t *testing.T) {
	cases := []struct {
		series string
		mutate func(*sample)
	}{
		{"goroutines", func(s *sample) { s.Goroutines += 50 }},
		{"fds", func(s *sample) { s.FDs += 50 }},
		{"db_in_use", func(s *sample) { s.DBInUse += 3 }},
		{"temp_files", func(s *sample) { s.TempFiles, s.TempNames = 2, []string{"soak-plant-1", "soak-plant-2"} }},
	}
	for _, c := range cases {
		t.Run(c.series, func(t *testing.T) {
			f := flatSample()
			c.mutate(&f)
			vs := checkReturnToBaseline(flatSample(), f, defaultTolerances)
			if !hasStatus(vs, c.series, "FAIL") {
				t.Fatalf("%s growth was not caught: %v", c.series, vs)
			}
			for _, v := range vs {
				if v.Series != c.series && v.Status == "FAIL" {
					t.Errorf("unrelated series %s failed: %s", v.Series, v)
				}
				if !v.Hard {
					t.Errorf("oracle (b) must be hard: %s", v)
				}
			}
		})
	}
}

func TestOracleBaseline_GoroutineFailureNamesTheStack(t *testing.T) {
	b := flatSample()
	f := flatSample()
	f.Goroutines += 10
	f.Stacks["x"] = stackGroup{Sig: "x", Top: "keyorix/server/soak.plantGoroutine.func1", Count: 10}
	vs := checkReturnToBaseline(b, f, defaultTolerances)
	var got string
	for _, v := range vs {
		if v.Series == "goroutines" {
			got = v.Detail
		}
	}
	if !strings.Contains(got, "plantGoroutine") {
		t.Fatalf("failure must name the growing stack, got %q", got)
	}
}

func TestOracleBaseline_MissingFDsIsAnExplicitSkipNotAPass(t *testing.T) {
	b, f := flatSample(), flatSample()
	b.FDs, f.FDs = -1, -1
	vs := checkReturnToBaseline(b, f, defaultTolerances)
	if !hasStatus(vs, "fds", "SKIP") {
		t.Fatalf("an unavailable fd series must say SKIP, got %v", vs)
	}
	for _, v := range vs {
		if v.Series == "fds" && !strings.HasPrefix(v.Detail, "SKIP:") {
			t.Errorf("SKIP line must be explicit: %q", v.Detail)
		}
	}
}

func TestOracleStacks(t *testing.T) {
	b := flatSample()
	t.Run("none new is green", func(t *testing.T) {
		if vs := checkNewStacks(b, flatSample(), nil); !hasStatus(vs, "-", "PASS") {
			t.Fatalf("got %v", vs)
		}
	})
	t.Run("new stack fails and prints the stack", func(t *testing.T) {
		f := flatSample()
		f.Stacks["runtime.gopark < pkg.leaky"] = stackGroup{Sig: "runtime.gopark < pkg.leaky", Top: "pkg.leaky", Count: 7, Full: "7 @ ...\n#\tpkg.leaky+0x1\tleak.go:5\n"}
		vs := checkNewStacks(b, f, nil)
		if !hasStatus(vs, "pkg.leaky", "FAIL") || !strings.Contains(vs[0].Detail, "leak.go:5") {
			t.Fatalf("got %v", vs)
		}
	})
	t.Run("allowlist needs a reason", func(t *testing.T) {
		f := flatSample()
		f.Stacks["runtime.gopark < pkg.leaky"] = stackGroup{Sig: "runtime.gopark < pkg.leaky", Top: "pkg.leaky", Count: 1}
		if vs := checkNewStacks(b, f, []allowEntry{{Contains: "pkg.leaky", Reason: ""}}); !hasStatus(vs, "pkg.leaky", "FAIL") {
			t.Fatalf("an allowlist entry without a reason must not allow: %v", vs)
		}
		if vs := checkNewStacks(b, f, []allowEntry{{Contains: "pkg.leaky", Reason: "started lazily by feature X"}}); hasStatus(vs, "pkg.leaky", "FAIL") {
			t.Fatalf("an allowlisted stack failed: %v", vs)
		}
	})
	t.Run("the sampler's own stack is never a finding", func(t *testing.T) {
		f := flatSample()
		f.Stacks["runtime/pprof.(*Profile).WriteTo < soak.drain"] = stackGroup{Sig: "runtime/pprof.(*Profile).WriteTo < soak.drain", Top: "soak.drain", Count: 1}
		if vs := checkNewStacks(b, f, nil); hasStatus(vs, "soak.drain", "FAIL") {
			t.Fatalf("got %v", vs)
		}
	})
}

func series(n int, f func(i int) sample) []sample {
	out := make([]sample, n)
	for i := range out {
		out[i] = f(i)
		out[i].Requests = int64(i+1) * 500
	}
	return out
}

func TestOracleSlope_ReportOnlyAndCalibrated(t *testing.T) {
	cal := calibration{"goroutines": 0.2, "heap_inuse": 1000, "heap_objects": 50, "db_open": 0, "temp_files": 0, "fds": 0.2}
	t.Run("flat is PASS", func(t *testing.T) {
		vs := checkSlopes(series(8, func(int) sample { return flatSample() }), cal)
		for _, v := range vs {
			if v.Hard {
				t.Errorf("slope must be report-only: %s", v)
			}
			if v.Status == "WARN" {
				t.Errorf("flat series warned: %s", v)
			}
		}
	})
	t.Run("one goroutine per 100 requests warns", func(t *testing.T) {
		vs := checkSlopes(series(8, func(i int) sample { s := flatSample(); s.Goroutines += i * 5; return s }), cal)
		if !hasStatus(vs, "goroutines", "WARN") {
			t.Fatalf("growth not reported: %v", vs)
		}
	})
	t.Run("an uncalibrated series is INFO, never a verdict", func(t *testing.T) {
		vs := checkSlopes(series(8, func(i int) sample { s := flatSample(); s.Rows = map[string]int64{"sessions": int64(i * 100)}; return s }), cal)
		if !hasStatus(vs, "rows_sessions", "INFO") {
			t.Fatalf("got %v", vs)
		}
	})
	t.Run("too few samples is an explicit SKIP", func(t *testing.T) {
		if vs := checkSlopes(series(2, func(int) sample { return flatSample() }), cal); !hasStatus(vs, "-", "SKIP") {
			t.Fatalf("got %v", vs)
		}
	})
}

func TestSlope_LeastSquares(t *testing.T) {
	if got := slope([]float64{0, 1, 2, 3}, []float64{1, 3, 5, 7}); got < 1.999 || got > 2.001 {
		t.Fatalf("slope = %v, want 2", got)
	}
	if got := slope([]float64{1, 1, 1}, []float64{1, 2, 3}); got != 0 {
		t.Fatalf("degenerate x must give 0, got %v", got)
	}
}

func TestParseGoroutineProfile(t *testing.T) {
	text := "goroutine profile: total 3\n" +
		"2 @ 0x100 0x200\n#\t0x100\truntime.gopark+0x1\t/go/proc.go:1\n#\t0x200\tpkg.worker.func1+0x2\t/src/w.go:9\n\n" +
		"1 @ 0x300\n#\t0x300\truntime/pprof.(*Profile).WriteTo+0x3\t/go/pprof.go:2\n"
	g := parseGoroutineProfile(text)
	if len(g) != 2 {
		t.Fatalf("groups = %d, want 2: %v", len(g), g)
	}
	sig := "runtime.gopark < pkg.worker.func1"
	if g[sig].Count != 2 || g[sig].Top != "pkg.worker.func1" {
		t.Fatalf("group %q = %+v", sig, g[sig])
	}
}

func TestCountFDsAndTemp(t *testing.T) {
	if n := countFDs(); n == 0 {
		t.Fatalf("countFDs() = 0")
	}
	dir := t.TempDir()
	if n, _ := listTemp(dir); n != 0 {
		t.Fatalf("empty dir counted %d", n)
	}
}
