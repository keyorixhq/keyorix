package fuzzutil

import (
	"fmt"
	"os"
	"sync"
)

var (
	stateReportPathOnce sync.Once
	stateReportPath     string
)

func stateReportPathValue() string {
	stateReportPathOnce.Do(func() { stateReportPath = os.Getenv("FUZZ_STATE_REPORT") })
	return stateReportPath
}

// StateReportEnabled reports whether FUZZ_STATE_REPORT is set. Check this
// before building a label (typically an fmt.Sprintf call) so a harness skips
// the formatting cost on every fuzz step when reporting is off -- label
// construction runs on the same hot path as StateEdge itself.
func StateReportEnabled() bool {
	return stateReportPathValue() != ""
}

var (
	stateReportMu   sync.Mutex
	stateReportFile *os.File
	stateReportSeen map[string]bool
)

// StateReport appends label to the file named by FUZZ_STATE_REPORT the FIRST
// time this exact label is seen in THIS PROCESS. Unlike StateEdgeGate
// (deliberately reset every fuzz iteration -- see its doc comment), this
// dedup is process-lifetime: the report answers "how many distinct security
// states did this run reach in total," not "how many did one input reach."
//
// `go test -fuzz` runs multiple WORKER PROCESSES in parallel, each with its
// own process-local dedup map -- so the file can end up containing the same
// label more than once across workers. A caller that wants a true distinct
// count must dedup the file's lines (e.g. `sort -u`);
// scripts/fuzzing/state-coverage-diff.sh does this.
//
// A no-op if FUZZ_STATE_REPORT is unset. Never fails the fuzz run: an open or
// write error is swallowed -- this is diagnostic tooling, not a correctness
// oracle, and must not turn a report-file permission problem into a spurious
// fuzz failure.
func StateReport(label string) {
	path := stateReportPathValue()
	if path == "" {
		return
	}
	stateReportMu.Lock()
	defer stateReportMu.Unlock()
	if stateReportSeen == nil {
		stateReportSeen = make(map[string]bool)
	}
	if stateReportSeen[label] {
		return
	}
	stateReportSeen[label] = true
	if stateReportFile == nil {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return
		}
		stateReportFile = f
	}
	fmt.Fprintln(stateReportFile, label)
}
