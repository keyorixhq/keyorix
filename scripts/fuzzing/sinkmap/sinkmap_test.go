package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// materializeFixture copies testdata/fixture into a temp dir, dropping the
// ".tmpl" suffix. The toy module is stored as .tmpl so that repo-wide tooling
// (gofmt, semgrep, gosec, guard-input walks) does not see a nested go.mod and
// deliberately unsafe sample code as part of the repository.
func materializeFixture(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src := "testdata/fixture"
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, strings.TrimSuffix(rel, ".tmpl"))
		if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
			return err
		}
		data, err := os.ReadFile(p) // #nosec G304 -- test fixture path under testdata
		if err != nil {
			return err
		}
		return os.WriteFile(out, data, 0o600)
	})
	if err != nil {
		t.Fatalf("materialize fixture: %v", err)
	}
	return dst
}

// scanFixture runs the full pipeline over the pinned toy module and returns
// the classified sinks.
func scanFixture(t *testing.T) []Sink {
	t.Helper()
	res, err := scanModule(materializeFixture(t), true)
	if err != nil {
		t.Fatalf("scanModule: %v", err)
	}
	classify(res)
	return res.Sinks
}

// find returns the single sink whose kind matches and whose enclosing func
// contains funcSub. It fails if there is not exactly one.
func find(t *testing.T, sinks []Sink, kind SinkKind, funcSub string) Sink {
	t.Helper()
	var hits []Sink
	for _, s := range sinks {
		if s.Kind == kind && strings.Contains(s.Func, funcSub) {
			hits = append(hits, s)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly one %s sink in %q, got %d: %+v", kind, funcSub, len(hits), hits)
	}
	return hits[0]
}

// TestFixtureHasEverySinkKind is the planted-miss guard: the fixture contains
// exactly one sink of each kind, so if a matcher is removed from sinks.go the
// corresponding kind disappears here and this test goes red. (Verified red by
// commenting out a matcher during development — see the sinkmap REPORT.)
func TestFixtureHasEverySinkKind(t *testing.T) {
	sinks := scanFixture(t)
	want := []SinkKind{
		KindFSPath, KindExec, KindNetOut, KindSQL,
		KindTemplate, KindDeserialize, KindCryptoCompare,
	}
	present := map[SinkKind]int{}
	for _, s := range sinks {
		present[s.Kind]++
	}
	for _, k := range want {
		if present[k] == 0 {
			t.Errorf("sink kind %q not detected in fixture — a matcher is missing or broken", k)
		}
	}
	// The fixture is minimal: one product sink per kind, nothing else.
	if got := len(sinks); got != len(want) {
		t.Errorf("fixture sink count = %d, want %d (one per kind): %+v", got, len(want), sinks)
	}
}

// TestFixtureClassification pins the per-sink classification: the exact
// enclosing function, API-reachability, fuzz coverage, product flag, and the
// discriminating part of the Detail text for each kind.
func TestFixtureClassification(t *testing.T) {
	sinks := scanFixture(t)

	cases := []struct {
		kind        SinkKind
		funcSub     string
		api         bool
		fuzz        bool
		detailSubst string
	}{
		{KindFSPath, "server/http/handlers.Handle", true, false, "filesystem path"},
		{KindExec, "sinks.RunExec", true, false, "shell-ish"},
		{KindSQL, "sinks.BuildQuery", true, false, "fmt.Sprintf"},
		{KindNetOut, "sinks.Dial", false, false, "variable URL"},
		{KindTemplate, "sinks.Compile", false, true, "variable pattern"},
		{KindDeserialize, "sinks.Parse", false, false, "json.Unmarshal"},
		{KindCryptoCompare, "sinks.Compare", false, false, "credential-named"},
	}
	for _, c := range cases {
		s := find(t, sinks, c.kind, c.funcSub)
		if !s.Product {
			t.Errorf("%s/%s: product=false, want true", c.kind, c.funcSub)
		}
		if s.APIReachable != c.api {
			t.Errorf("%s/%s: api_reachable=%v, want %v (entry=%q)", c.kind, c.funcSub, s.APIReachable, c.api, s.APIEntry)
		}
		if s.FuzzCovered != c.fuzz {
			t.Errorf("%s/%s: fuzz_covered=%v, want %v (by=%q)", c.kind, c.funcSub, s.FuzzCovered, c.fuzz, s.FuzzBy)
		}
		if !strings.Contains(s.Detail, c.detailSubst) {
			t.Errorf("%s/%s: detail=%q, want substring %q", c.kind, c.funcSub, s.Detail, c.detailSubst)
		}
	}
}

// TestNestedModuleSkipped confirms a nested go.mod subtree is not descended
// into: the real root run must skip the known separate modules.
func TestNestedModuleSkipped(t *testing.T) {
	// `go test` runs with CWD = this package dir; the repo root is three up.
	res, err := scanModule("../../..", false)
	if err != nil {
		t.Fatalf("scanModule: %v", err)
	}
	wantSkipped := "cli"
	found := false
	for _, s := range res.skipped {
		if s == wantSkipped {
			found = true
		}
	}
	if !found {
		t.Errorf("expected nested module %q to be skipped; skipped=%v", wantSkipped, res.skipped)
	}
	// No sink should ever be reported from inside a skipped nested module.
	for _, s := range res.Sinks {
		if strings.HasPrefix(s.File, "cli/") || strings.HasPrefix(s.File, "operator/") {
			t.Errorf("sink reported from nested module: %s:%d", s.File, s.Line)
		}
	}
}
