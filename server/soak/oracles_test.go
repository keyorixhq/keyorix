package soak

// oracles_test.go: the three resource-growth oracles. They are pure functions
// over samples, so the unit tests in oracles_unit_test.go prove each one fires
// on synthetic growth and stays quiet on a flat series without starting a server.
//
// Soundness rule: only a statement that cannot be false when the server is
// healthy may FAIL a run.
//
//	(a) SLOPE  report-only. Growth per 1000 requests of each series after
//	    warm-up, compared with a threshold derived from calibration runs
//	    (testdata/calibration.tsv), never an absolute number. A WARN here is a
//	    lead to read, not a verdict: audit_events grows with every request by
//	    design, and a few samples make a noisy regression.
//	(b) RETURN-TO-BASELINE  hard. After the load stops and the server has been
//	    idle, goroutines, descriptors, in-use DB connections and temp files must
//	    be back within a small tolerance of the baseline taken after warm-up. A
//	    healthy idle server holds no per-request resource; the check polls until
//	    the deadline, so a goroutine that is merely still exiting does not fail it.
//	(c) NEW STACKS  hard. No goroutine stack may exist in the final profile that
//	    was absent from the baseline, unless an allowlist entry (with a reason)
//	    covers it. The baseline is taken after every request kind in the mix ran
//	    (twice), so a lazily started worker is in it. The flip side: a leak that
//	    already happens during warm-up is part of the baseline's stacks, and (c)
//	    cannot see it. That is (b)'s job (the count grows), and its failure names
//	    the growing stack. (c) catches what (b)'s tolerance lets through: a new
//	    stack that first appears under load, even a single parked goroutine.
//
// What the soak does NOT verify (state this wherever results are quoted):
//   - slow leaks below the slope threshold, and below the noise of a run this
//     short: a goroutine leaked once per 10,000 requests is invisible to a smoke;
//     only the (b) check after a long run sees it;
//   - leaks on code paths the request mix does not reach (see the coverage table
//     in server/soak/README.md);
//   - growth outside the Go runtime's view: cgo allocations, kernel-side state
//     (socket buffers, page cache), a leak in a database server or another
//     process;
//   - the production factory's auxiliary DB pools (named-lock, scheduler-lock,
//     read-audit): the soak builds LocalStorage over one pool, so their
//     connections are covered only through the process-wide fd series;
//   - correctness of any response: that is what the other harnesses assert.

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type verdict struct {
	Oracle string // "slope" | "baseline" | "stacks"
	Series string
	Status string // PASS FAIL WARN SKIP INFO
	Hard   bool   // a FAIL here fails the run
	Detail string
}

func (v verdict) String() string {
	kind := "report"
	if v.Hard {
		kind = "hard"
	}
	return fmt.Sprintf("%-4s %-8s %-7s %-14s %s", v.Status, kind, v.Oracle, v.Series, v.Detail)
}

// tolerances are the "small delta" of oracle (b). Calibrated: see README.
type tolerances struct {
	Goroutines int
	FDs        int
	DBInUse    int
	TempFiles  int
}

// Calibrated on five control smoke runs (seeds 1-5, README.md): the largest
// final-minus-baseline was goroutines +0, fds +3, db_in_use +0, temp_files +0.
// Each tolerance is about twice the observed maximum (never below 3 for
// goroutines), and a leak the planted red-proofs model is hundreds of times
// larger, so the margin costs no sensitivity to growth that scales with load.
var defaultTolerances = tolerances{Goroutines: 3, FDs: 6, DBInUse: 0, TempFiles: 0}

// fdsPerPooledConn is the descriptors one more pooled database connection may
// hold: a SQLite connection has its database and WAL files open, a PostgreSQL
// one a socket. An idle pooled connection is not a leak (db_in_use is the
// check for a connection that was not returned), but it does hold them, and a
// pool that grew under 4 workers must not fail the descriptor check for it.
const fdsPerPooledConn = 3

// allowEntry is one explicitly allowed new stack: any stack whose signature
// contains Contains is exempt, and Reason says why that is not a leak.
type allowEntry struct {
	Contains string
	Reason   string
}

// stackAllowlist is empty unless calibration found a stack that legitimately
// appears only after load. Each entry needs a reason a reviewer can check.
var stackAllowlist = []allowEntry{}

// ownStack reports a stack that belongs to the sampler itself (the goroutine
// that is writing the profile), which exists in every profile but with a call
// chain that depends on who sampled.
func ownStack(sig string) bool {
	return strings.Contains(sig, "runtime/pprof.(*Profile).WriteTo")
}

// checkReturnToBaseline is oracle (b).
func checkReturnToBaseline(base, final sample, tol tolerances) []verdict {
	var out []verdict
	add := func(series string, ok bool, detail string) {
		st := "PASS"
		if !ok {
			st = "FAIL"
		}
		out = append(out, verdict{Oracle: "baseline", Series: series, Status: st, Hard: true, Detail: detail})
	}

	add("goroutines", final.Goroutines <= base.Goroutines+tol.Goroutines,
		fmt.Sprintf("baseline=%d final=%d tolerance=+%d%s", base.Goroutines, final.Goroutines, tol.Goroutines,
			growthDetail(base, final, final.Goroutines > base.Goroutines+tol.Goroutines)))

	if base.FDs < 0 || final.FDs < 0 {
		out = append(out, verdict{Oracle: "baseline", Series: "fds", Status: "SKIP", Hard: true,
			Detail: "SKIP: no /proc/self/fd or /dev/fd on this platform; descriptor leaks are NOT checked in this run"})
	} else {
		allow := tol.FDs + fdsPerPooledConn*max(0, final.DBOpen-base.DBOpen)
		add("fds", final.FDs <= base.FDs+allow,
			fmt.Sprintf("baseline=%d final=%d tolerance=+%d (db_open %d -> %d)", base.FDs, final.FDs, allow, base.DBOpen, final.DBOpen))
	}

	add("db_in_use", final.DBInUse <= base.DBInUse+tol.DBInUse,
		fmt.Sprintf("baseline=%d final=%d tolerance=+%d (open=%d idle=%d)", base.DBInUse, final.DBInUse, tol.DBInUse, final.DBOpen, final.DBIdle))

	detail := fmt.Sprintf("baseline=%d final=%d tolerance=+%d", base.TempFiles, final.TempFiles, tol.TempFiles)
	if final.TempFiles > base.TempFiles+tol.TempFiles {
		detail += " files: " + strings.Join(final.TempNames, ", ")
	}
	add("temp_files", final.TempFiles <= base.TempFiles+tol.TempFiles, detail)
	return out
}

// growthDetail names the stack groups that grew between base and final, so a
// goroutine failure says which function leaks.
func growthDetail(base, final sample, failed bool) string {
	if !failed {
		return ""
	}
	type g struct {
		top   string
		delta int
	}
	var grown []g
	for sig, fg := range final.Stacks {
		if ownStack(sig) {
			continue
		}
		if d := fg.Count - base.Stacks[sig].Count; d > 0 {
			grown = append(grown, g{fg.Top, d})
		}
	}
	sort.Slice(grown, func(i, j int) bool { return grown[i].delta > grown[j].delta })
	var parts []string
	for i, x := range grown {
		if i == 5 {
			break
		}
		parts = append(parts, fmt.Sprintf("+%d %s", x.delta, x.top))
	}
	return " grew: " + strings.Join(parts, "; ")
}

// checkNewStacks is oracle (c).
func checkNewStacks(base, final sample, allow []allowEntry) []verdict {
	var sigs []string
	for sig := range final.Stacks {
		if _, ok := base.Stacks[sig]; !ok && !ownStack(sig) {
			sigs = append(sigs, sig)
		}
	}
	sort.Strings(sigs)
	var out []verdict
	for _, sig := range sigs {
		g := final.Stacks[sig]
		if reason, ok := allowed(sig, allow); ok {
			out = append(out, verdict{Oracle: "stacks", Series: g.Top, Status: "INFO", Hard: true,
				Detail: fmt.Sprintf("new stack x%d allowlisted: %s", g.Count, reason)})
			continue
		}
		out = append(out, verdict{Oracle: "stacks", Series: g.Top, Status: "FAIL", Hard: true,
			Detail: fmt.Sprintf("new goroutine stack absent at baseline, x%d:\n%s", g.Count, g.Full)})
	}
	if len(sigs) == 0 {
		out = append(out, verdict{Oracle: "stacks", Series: "-", Status: "PASS", Hard: true,
			Detail: fmt.Sprintf("no stack beyond the %d baseline stacks", len(base.Stacks))})
	}
	return out
}

func allowed(sig string, allow []allowEntry) (string, bool) {
	for _, a := range allow {
		if a.Reason != "" && strings.Contains(sig, a.Contains) {
			return a.Reason, true
		}
	}
	return "", false
}

// calibration maps a series name to the largest slope (per 1000 requests)
// observed across the calibration runs.
type calibration map[string]float64

// loadCalibration reads testdata/calibration.tsv: series<TAB>max_slope_per_1k<TAB>note.
func loadCalibration(path string) calibration {
	cal := calibration{}
	b, err := os.ReadFile(path)
	if err != nil {
		return cal
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		if v, err := strconv.ParseFloat(f[1], 64); err == nil {
			cal[f[0]] = v
		}
	}
	return cal
}

const (
	slopeFactor = 3.0 // the threshold is this many times the calibrated maximum
)

// slopeFloor is the smallest threshold per series: a calibrated slope of zero
// must not turn one extra object into a warning.
func slopeFloor(series string) float64 {
	switch {
	case series == "heap_inuse":
		return 64 << 10 // 64 KiB per 1000 requests
	case series == "heap_objects":
		return 500
	case strings.HasPrefix(series, "rows_"):
		return 5
	}
	return 0.5
}

// seriesOf extracts every series from the in-load samples.
func seriesOf(samples []sample) map[string][]float64 {
	out := map[string][]float64{}
	put := func(name string, v float64) { out[name] = append(out[name], v) }
	for _, s := range samples {
		put("goroutines", float64(s.Goroutines))
		put("heap_inuse", float64(s.HeapInuse))
		put("heap_objects", float64(s.HeapObjects))
		if s.FDs >= 0 {
			put("fds", float64(s.FDs))
		}
		put("db_open", float64(s.DBOpen))
		put("temp_files", float64(s.TempFiles))
		for t, n := range s.Rows {
			put("rows_"+t, float64(n))
		}
	}
	return out
}

// slope is the least-squares slope of ys against xs.
func slope(xs, ys []float64) float64 {
	n := float64(len(xs))
	if len(xs) < 2 {
		return 0
	}
	var sx, sy, sxx, sxy float64
	for i := range xs {
		sx += xs[i]
		sy += ys[i]
		sxx += xs[i] * xs[i]
		sxy += xs[i] * ys[i]
	}
	den := n*sxx - sx*sx
	if den == 0 {
		return 0
	}
	return (n*sxy - sx*sy) / den
}

// checkSlopes is oracle (a): report-only. samples are the in-load samples
// after the baseline; x is requests in thousands. Only the SECOND HALF of the
// run is fitted: bounded caches (the secret metadata cache holds up to 10,000
// entries per map, the token cache its own cap) fill during the first half and
// would otherwise read as growth. A series still rising in the second half is
// the lead worth reading.
func checkSlopes(samples []sample, cal calibration) []verdict {
	var out []verdict
	samples = samples[len(samples)/2:]
	if len(samples) < 3 {
		return []verdict{{Oracle: "slope", Series: "-", Status: "SKIP",
			Detail: fmt.Sprintf("SKIP: %d in-load samples in the second half, need at least 3 for a slope", len(samples))}}
	}
	xs := make([]float64, len(samples))
	for i, s := range samples {
		xs[i] = float64(s.Requests) / 1000
	}
	series := seriesOf(samples)
	names := make([]string, 0, len(series))
	for n := range series {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		ys := series[name]
		if len(ys) != len(xs) {
			continue // a series missing from some samples (a table that appeared late)
		}
		sl := slope(xs, ys)
		c, calibrated := cal[name]
		if !calibrated {
			out = append(out, verdict{Oracle: "slope", Series: name, Status: "INFO",
				Detail: fmt.Sprintf("slope=%.3f per 1k req, no calibration entry", sl)})
			continue
		}
		thr := c*slopeFactor + slopeFloor(name)
		st := "PASS"
		if sl > thr {
			st = "WARN"
		}
		out = append(out, verdict{Oracle: "slope", Series: name, Status: st,
			Detail: fmt.Sprintf("slope=%.3f per 1k req threshold=%.3f (calibrated max %.3f x%.0f + floor)", sl, thr, c, slopeFactor)})
	}
	return out
}
