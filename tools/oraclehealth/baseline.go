package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// baselineRow is one target's committed kill-rate floor. KillRate and Tolerance
// are percentages / percentage-points (0..100); a run passes when the measured
// rate is >= KillRate - Tolerance. The run-manifest columns (Package/Funcs/…) let
// oracle-health.sh drive the tool from the same file the comparison reads.
type baselineRow struct {
	Target    string
	Package   string
	Funcs     string
	FuzzTime  string
	Max       int
	Seed      int64
	KillRate  float64
	Tolerance float64
}

// loadBaseline reads the baseline TSV. Columns (tab-separated):
// target, package, funcs, fuzztime, max, seed, kill_rate, tolerance.
// Blank/'#' lines and a "target" header row are skipped.
func loadBaseline(path string) ([]baselineRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var rows []baselineRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		raw := sc.Text()
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		cols := strings.Split(raw, "\t")
		if len(cols) < 8 {
			return nil, fmt.Errorf("%s:%d: want 8 tab-separated columns, got %d", path, ln, len(cols))
		}
		if cols[0] == "target" {
			continue
		}
		mx, err := strconv.Atoi(strings.TrimSpace(cols[4]))
		if err != nil {
			return nil, fmt.Errorf("%s:%d: max: %w", path, ln, err)
		}
		sd, err := strconv.ParseInt(strings.TrimSpace(cols[5]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: seed: %w", path, ln, err)
		}
		kr, err := strconv.ParseFloat(strings.TrimSpace(cols[6]), 64)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: kill_rate: %w", path, ln, err)
		}
		tol, err := strconv.ParseFloat(strings.TrimSpace(cols[7]), 64)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: tolerance: %w", path, ln, err)
		}
		rows = append(rows, baselineRow{
			Target: cols[0], Package: cols[1], Funcs: cols[2], FuzzTime: cols[3],
			Max: mx, Seed: sd, KillRate: kr, Tolerance: tol,
		})
	}
	return rows, sc.Err()
}

// compareResult is one target's baseline comparison outcome.
type compareResult struct {
	Target   string
	Baseline float64
	Measured float64 // -1 means the target was absent from the measurement
	Floor    float64
	OK       bool
	Reason   string
}

// compareBaseline checks each baseline row against the measured kill-rates
// (target -> percentage). A target absent from the measurement FAILS (a baseline
// target that stopped being measured is a regression in coverage, not a pass).
// A measured rate below KillRate-Tolerance FAILS. Equal-to-baseline PASSES.
func compareBaseline(rows []baselineRow, measured map[string]float64) []compareResult {
	out := make([]compareResult, 0, len(rows))
	for _, r := range rows {
		floor := r.KillRate - r.Tolerance
		m, ok := measured[r.Target]
		if !ok {
			out = append(out, compareResult{
				Target: r.Target, Baseline: r.KillRate, Measured: -1, Floor: floor,
				OK: false, Reason: "missing from measurement (baseline target not run)",
			})
			continue
		}
		if m < floor {
			out = append(out, compareResult{
				Target: r.Target, Baseline: r.KillRate, Measured: m, Floor: floor, OK: false,
				Reason: fmt.Sprintf("kill-rate %.0f%% below floor %.0f%% (baseline %.0f%% - tolerance %.0f%%)", m, floor, r.KillRate, r.Tolerance),
			})
			continue
		}
		out = append(out, compareResult{
			Target: r.Target, Baseline: r.KillRate, Measured: m, Floor: floor, OK: true, Reason: "ok",
		})
	}
	return out
}

// measuredFromReports reads the kill-rate (as a percentage) for every target in
// the given JSON report files, last-write-wins on a repeated target.
func measuredFromReports(paths []string) (map[string]float64, error) {
	out := map[string]float64{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var rep Report
		if err := json.Unmarshal(b, &rep); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for _, r := range rep.Runs {
			out[r.Target] = r.KillRate * 100
		}
	}
	return out, nil
}

// runCompare is the -compare mode: load the baseline, read measured kill-rates
// from the report JSONs named as positional args, print the comparison and
// return a non-nil error when any target regressed or is missing.
func runCompare(baselinePath string, reportPaths []string) error {
	rows, err := loadBaseline(baselinePath)
	if err != nil {
		return fmt.Errorf("load baseline: %w", err)
	}
	if len(rows) == 0 {
		return fmt.Errorf("baseline %s has no rows", baselinePath)
	}
	measured, err := measuredFromReports(reportPaths)
	if err != nil {
		return fmt.Errorf("read reports: %w", err)
	}
	results := compareBaseline(rows, measured)

	fmt.Println("| target | baseline | measured | floor | verdict |")
	fmt.Println("|--------|----------|----------|-------|---------|")
	failed := 0
	for _, r := range results {
		meas := "—"
		if r.Measured >= 0 {
			meas = fmt.Sprintf("%.0f%%", r.Measured)
		}
		verdict := "PASS"
		if !r.OK {
			verdict = "FAIL — " + r.Reason
			failed++
		}
		fmt.Printf("| %s | %.0f%% | %s | %.0f%% | %s |\n", r.Target, r.Baseline, meas, r.Floor, verdict)
	}
	if failed > 0 {
		return fmt.Errorf("%d target(s) regressed below baseline", failed)
	}
	return nil
}
