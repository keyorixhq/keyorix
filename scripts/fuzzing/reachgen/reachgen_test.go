package reachgen

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// materialiseFixtures copies testdata into a temp dir, dropping the .tmpl
// suffix from every file (go.mod.tmpl -> go.mod, app.go.tmpl -> app.go). The
// fixture modules are stored that way so the repo-wide guards and linters that
// walk the tree see neither nested modules nor Go sources that do not build in
// the root module; the relative replace paths still resolve inside the copy.
func materialiseFixtures(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir("testdata", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel("testdata", p)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o750)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(strings.TrimSuffix(out, ".tmpl"), b, 0o600)
	})
	if err != nil {
		t.Fatalf("materialise fixtures: %v", err)
	}
	return dst
}

// scanFixture loads the testdata fixture module (offline, local replaces) and
// returns the entries keyed by "pkg\x00Func".
func scanFixture(t *testing.T) map[string]Entry {
	t.Helper()
	res, err := Scan(Config{
		ModulePrefix: "example.com/app",
		Patterns:     []string{"./..."},
		Dir:          filepath.Join(materialiseFixtures(t), "fixturemod"),
		// The parent repo uses a go.work; the fixture module is not part of it.
		Env: append(os.Environ(), "GOWORK=off", "GOFLAGS="),
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.LoadErrors) > 0 {
		t.Fatalf("unexpected load errors: %v", res.LoadErrors)
	}
	m := map[string]Entry{}
	for _, e := range res.Entries {
		m[e.Pkg+"\x00"+e.Func] = e
	}
	return m
}

func provSet(e Entry) map[Provenance]bool {
	s := map[Provenance]bool{}
	for p := range e.ProvAgg {
		s[p] = true
	}
	return s
}

func TestScan_RecordsThirdPartyCallsOnly(t *testing.T) {
	m := scanFixture(t)

	// Stdlib (fmt.Println) and own-code (ownHelper) must never be recorded.
	for k := range m {
		if got := m[k]; got.Pkg == "fmt" || got.Pkg == "example.com/app" {
			t.Errorf("recorded a non-third-party call: %s.%s", got.Pkg, got.Func)
		}
	}

	// Unexported third-party func must never be recorded.
	if _, ok := m["example.com/lib\x00unexportedHelper"]; ok {
		t.Errorf("recorded an unexported third-party func")
	}
}

func TestScan_Provenance(t *testing.T) {
	m := scanFixture(t)

	req, ok := m["example.com/lib\x00ParseRequest"]
	if !ok {
		t.Fatalf("ParseRequest not found; have: %v", keys(m))
	}
	ps := provSet(req)
	if !ps[ProvRequest] {
		t.Errorf("ParseRequest: want request-body provenance, got %v", ps)
	}
	if !ps[ProvBackend] {
		t.Errorf("ParseRequest: want backend-response provenance (UsesBackend), got %v", ps)
	}
	if req.UntrustedSites() < 2 {
		t.Errorf("ParseRequest: want >=2 untrusted sites, got %d", req.UntrustedSites())
	}
	if !req.Fuzzable {
		t.Errorf("ParseRequest(string) should be Fuzzable")
	}

	// ParseBytes gets request-body via assignment propagation (body := []byte(s)).
	pb, ok := m["example.com/lib\x00ParseBytes"]
	if !ok {
		t.Fatalf("ParseBytes not found")
	}
	if !provSet(pb)[ProvRequest] {
		t.Errorf("ParseBytes: assignment taint propagation failed, got %v", provSet(pb))
	}

	// FromConfig gets config provenance from a config-typed value.
	fc, ok := m["example.com/lib\x00FromConfig"]
	if !ok {
		t.Fatalf("FromConfig not found")
	}
	if !provSet(fc)[ProvConfig] {
		t.Errorf("FromConfig: want config provenance, got %v", provSet(fc))
	}

	// StaticOnly is called only with a literal: static, zero untrusted sites.
	so, ok := m["example.com/lib\x00StaticOnly"]
	if !ok {
		t.Fatalf("StaticOnly not found")
	}
	if so.UntrustedSites() != 0 {
		t.Errorf("StaticOnly: want 0 untrusted sites, got %d (prov %v)", so.UntrustedSites(), provSet(so))
	}

	// Method resolution: Decoder.Decode recorded with []byte request provenance.
	dec, ok := m["example.com/lib\x00Decoder.Decode"]
	if !ok {
		t.Fatalf("Decoder.Decode not found; have: %v", keys(m))
	}
	if !dec.IsMethod {
		t.Errorf("Decoder.Decode: IsMethod should be true")
	}
	if !provSet(dec)[ProvRequest] {
		t.Errorf("Decoder.Decode: want request-body provenance, got %v", provSet(dec))
	}
}

func TestMarkCovered(t *testing.T) {
	m := scanFixture(t)
	var entries []Entry
	for _, e := range m {
		entries = append(entries, e)
	}
	cover := map[string]map[string]bool{
		"example.com/lib": {"parserequest": true},
	}
	MarkCovered(entries, cover)
	for _, e := range entries {
		want := e.Func == "ParseRequest"
		if e.Pkg == "example.com/lib" && e.Func == "ParseRequest" && !e.Covered {
			t.Errorf("ParseRequest should be marked covered")
		}
		if !want && e.Covered {
			t.Errorf("%s.%s should NOT be marked covered", e.Pkg, e.Func)
		}
	}
}

func TestClassifiers(t *testing.T) {
	if !isStdlib("fmt") || !isStdlib("net/http") {
		t.Errorf("isStdlib failed on stdlib paths")
	}
	if isStdlib("github.com/foo/bar") {
		t.Errorf("isStdlib misclassified a dotted path")
	}
	if !isBackendPath("github.com/jackc/pgx/v5/pgconn") {
		t.Errorf("isBackendPath missed a pgx subpackage")
	}
	if isBackendPath("github.com/go-chi/chi/v5") {
		t.Errorf("isBackendPath false positive on chi")
	}
	if !configTypeHint("LoadOptions") || !configTypeHint("ServerConfig") {
		t.Errorf("configTypeHint missed a config-like name")
	}
	if configTypeHint("Request") {
		t.Errorf("configTypeHint false positive")
	}
}

func keys(m map[string]Entry) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
