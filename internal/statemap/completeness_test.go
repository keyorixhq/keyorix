package statemap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompletenessGuard_EntrypointsAndStoresMatchCode is AT0(f): re-runs the
// same extractors cmd/statemapgen uses and fails if docs/state-map/*.tsv has
// drifted from what's actually in code -- a new/removed route, RPC,
// scheduled job, or CLI command, or a new/removed DB table, ships without
// the state map being regenerated. Mirrors internal/core/atomicity_guard_test.go's
// shape (an AST/text scan compared against a checked-in file), for the same
// reason: a hand-maintained inventory silently rots; a regenerate-and-diff
// check cannot.
func TestCompletenessGuard_EntrypointsAndStoresMatchCode(t *testing.T) {
	root := repoRoot(t)

	gotEntries, err := AllEntries(root)
	if err != nil {
		t.Fatalf("AllEntries: %v", err)
	}
	wantEntries, err := readEntrypointsTSV(filepath.Join(root, "docs", "state-map", "entrypoints.tsv"))
	if err != nil {
		t.Fatalf("reading checked-in entrypoints.tsv: %v", err)
	}
	diffEntries(t, wantEntries, gotEntries)

	gotTables, err := DBTables(root)
	if err != nil {
		t.Fatalf("DBTables: %v", err)
	}
	wantTables, err := readStoreModels(filepath.Join(root, "docs", "state-map", "stores.tsv"))
	if err != nil {
		t.Fatalf("reading checked-in stores.tsv: %v", err)
	}
	diffTables(t, wantTables, gotTables)
}

func diffEntries(t *testing.T, want map[string]bool, got []Entry) {
	t.Helper()
	gotSet := map[string]bool{}
	for _, e := range got {
		gotSet[e.Kind+"\t"+e.ID] = true
	}
	var missing, extra []string
	for k := range want {
		if !gotSet[k] {
			missing = append(missing, k)
		}
	}
	for k := range gotSet {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	if len(missing) > 0 {
		t.Errorf("docs/state-map/entrypoints.tsv lists %d entry point(s) no longer found in code (stale row, or an extractor regressed) -- e.g. %v", len(missing), sample(missing, 5))
	}
	if len(extra) > 0 {
		t.Errorf("code has %d entry point(s) not in docs/state-map/entrypoints.tsv -- run `go run ./cmd/statemapgen` and commit the diff -- e.g. %v", len(extra), sample(extra, 5))
	}
}

func diffTables(t *testing.T, want map[string]bool, got []DBTable) {
	t.Helper()
	gotSet := map[string]bool{}
	for _, tb := range got {
		gotSet[tb.Model] = true
	}
	var missing, extra []string
	for k := range want {
		if !gotSet[k] {
			missing = append(missing, k)
		}
	}
	for k := range gotSet {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	if len(missing) > 0 {
		t.Errorf("docs/state-map/stores.tsv lists %d db_table row(s) no longer in internal/storage/all_models.go -- %v", len(missing), sample(missing, 5))
	}
	if len(extra) > 0 {
		t.Errorf("internal/storage/all_models.go has %d model(s) not in docs/state-map/stores.tsv -- run `go run ./cmd/statemapgen` and commit the diff -- %v", len(extra), sample(extra, 5))
	}
}

func sample(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func readEntrypointsTSV(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed relative path under the checked-out repo
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		out[fields[0]+"\t"+fields[1]] = true
	}
	return out, nil
}

func readStoreModels(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed relative path under the checked-out repo
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 || fields[1] != "db_table" {
			continue
		}
		out[fields[0]] = true
	}
	return out, nil
}
