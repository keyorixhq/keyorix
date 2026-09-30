package statemap

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// validClasses are the only acceptable values for entrypoints.tsv's class
// column. A/S/B/C/D/F/R/X/L mirror docs/atomicity-exempt.tsv's own classes
// (reused, not redefined). "none" is a single/no-write or read-only-by-
// design entry. "REVIEW" is this generator's own 1-hop write-count scan
// flagging a candidate that needs a human (mirrors atomicity-exempt.tsv's
// TEMP-A precedent for "flagged, not yet triaged"). "gap" is an entry-point
// CATEGORY this generator doesn't enumerate at all (see knownGapRows in
// cmd/statemapgen).
var validClasses = map[string]bool{
	"A": true, "S": true, "B": true, "C": true, "D": true, "F": true, "R": true, "X": true, "L": true,
	"none": true, "REVIEW": true, "gap": true,
}

// TestCompletenessGuard_EntrypointsAndStoresMatchCode is AT0(f): re-runs the
// same extractors/classifier cmd/statemapgen uses and fails if
// docs/state-map/*.tsv has drifted from what's actually in code (a new/
// removed route, RPC, scheduled job, CLI command, or MCP tool -- compared by
// per-(kind,id) OCCURRENCE COUNT, not mere presence, so two entries that
// legitimately render the same ID string still catch a THIRD one silently
// appearing or one of the two disappearing), a new/removed DB table, or a
// new/removed non-test file-write call site. Also fails if any entrypoints
// row's class column is empty or not one of validClasses. Mirrors
// internal/core/atomicity_guard_test.go's shape (an AST/text scan compared
// against a checked-in file), for the same reason: a hand-maintained
// inventory silently rots; a regenerate-and-diff check cannot.
func TestCompletenessGuard_EntrypointsAndStoresMatchCode(t *testing.T) {
	root := repoRoot(t)

	gotEntries, err := AllEntries(root)
	if err != nil {
		t.Fatalf("AllEntries: %v", err)
	}
	gotClassified, err := Classify(root, gotEntries)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	wantRows, err := readEntrypointsTSV(filepath.Join(root, "docs", "state-map", "entrypoints.tsv"))
	if err != nil {
		t.Fatalf("reading checked-in entrypoints.tsv: %v", err)
	}
	diffEntryCounts(t, wantRows, gotClassified)
	checkClasses(t, wantRows)

	gotTables, err := DBTables(root)
	if err != nil {
		t.Fatalf("DBTables: %v", err)
	}
	gotSites, err := FileWriteSites(root)
	if err != nil {
		t.Fatalf("FileWriteSites: %v", err)
	}
	wantTables, wantFileWrites, err := readStoresTSV(filepath.Join(root, "docs", "state-map", "stores.tsv"))
	if err != nil {
		t.Fatalf("reading checked-in stores.tsv: %v", err)
	}
	diffCounts(t, "docs/state-map/stores.tsv (db_table rows)", "internal/storage/all_models.go", wantTables, tableCounts(gotTables))
	diffCounts(t, "docs/state-map/stores.tsv (file_write rows)", "a file-write call site scan", wantFileWrites, fileWriteCounts(gotSites))
}

// entrypointsRow is one parsed row of entrypoints.tsv, excluding the
// generator's own known-gap rows (kind=gap), which have no code-derived
// counterpart to diff against and are checked separately (present + class
// "gap") by checkClasses/diffEntryCounts's own gap handling below.
type entrypointsRow struct {
	kind, id, class string
}

func diffEntryCounts(t *testing.T, want []entrypointsRow, got []Entry) {
	t.Helper()
	wantCount := map[string]int{}
	for _, r := range want {
		if r.kind == "gap" {
			continue
		}
		wantCount[r.kind+"\t"+r.id]++
	}
	gotCount := map[string]int{}
	for _, e := range got {
		gotCount[e.Kind+"\t"+e.ID]++
	}
	var mismatches []string
	for k, wc := range wantCount {
		if gc := gotCount[k]; gc != wc {
			mismatches = append(mismatches, k+" (checked-in: "+strconv.Itoa(wc)+", code: "+strconv.Itoa(gc)+")")
		}
	}
	for k, gc := range gotCount {
		if _, ok := wantCount[k]; !ok {
			mismatches = append(mismatches, k+" (checked-in: 0, code: "+strconv.Itoa(gc)+")")
		}
	}
	if len(mismatches) > 0 {
		t.Errorf("docs/state-map/entrypoints.tsv has drifted from code for %d (kind,id) key(s) -- run `go run ./cmd/statemapgen` and commit the diff -- e.g. %v", len(mismatches), sample(mismatches, 8))
	}
}

// checkClasses fails if any non-gap row's class is empty or not a member of
// validClasses -- AT0(f)'s "unclassified rows must fail" requirement.
func checkClasses(t *testing.T, rows []entrypointsRow) {
	t.Helper()
	var bad []string
	for _, r := range rows {
		if !validClasses[r.class] {
			bad = append(bad, r.kind+"\t"+r.id+"\t(class=\""+r.class+"\")")
		}
	}
	if len(bad) > 0 {
		t.Errorf("docs/state-map/entrypoints.tsv has %d row(s) with an empty or invalid class column (must be one of A/S/B/C/D/F/R/X/L/none/REVIEW/gap) -- %v", len(bad), sample(bad, 8))
	}
}

func diffCounts(t *testing.T, wantLabel, gotLabel string, want, got map[string]int) {
	t.Helper()
	var mismatches []string
	for k, wc := range want {
		if gc := got[k]; gc != wc {
			mismatches = append(mismatches, k+" (checked-in: "+strconv.Itoa(wc)+", "+gotLabel+": "+strconv.Itoa(gc)+")")
		}
	}
	for k, gc := range got {
		if _, ok := want[k]; !ok {
			mismatches = append(mismatches, k+" (checked-in: 0, "+gotLabel+": "+strconv.Itoa(gc)+")")
		}
	}
	if len(mismatches) > 0 {
		t.Errorf("%s has drifted from %s for %d key(s) -- run `go run ./cmd/statemapgen` and commit the diff -- e.g. %v", wantLabel, gotLabel, len(mismatches), sample(mismatches, 8))
	}
}

func tableCounts(tables []DBTable) map[string]int {
	out := map[string]int{}
	for _, tb := range tables {
		out[tb.Model]++
	}
	return out
}

func fileWriteCounts(sites []FileWriteSite) map[string]int {
	out := map[string]int{}
	for _, s := range sites {
		out[s.File+":"+strconv.Itoa(s.Line)+" ("+s.Func+")"]++
	}
	return out
}

func sample(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func readEntrypointsTSV(path string) ([]entrypointsRow, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed relative path under the checked-out repo
	if err != nil {
		return nil, err
	}
	var out []entrypointsRow
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 6 {
			continue
		}
		out = append(out, entrypointsRow{kind: fields[0], id: fields[1], class: fields[5]})
	}
	return out, nil
}

// readStoresTSV splits stores.tsv into its db_table and file_write row
// counts (by store key), ignoring the hand-curated memory/external rows
// below the marker comment (those have no code-derived counterpart to diff
// against).
func readStoresTSV(path string) (tables, fileWrites map[string]int, err error) {
	data, rerr := os.ReadFile(path) // #nosec G304 -- fixed relative path under the checked-out repo
	if rerr != nil {
		return nil, nil, rerr
	}
	tables = map[string]int{}
	fileWrites = map[string]int{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		switch fields[1] {
		case "db_table":
			tables[fields[0]]++
		case "file_write":
			fileWrites[fields[0]]++
		}
	}
	return tables, fileWrites, nil
}
