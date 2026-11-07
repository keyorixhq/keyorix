package configspace

import (
	"encoding/json"

	"github.com/keyorixhq/keyorix/internal/config"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func mustModel(t testing.TB) *Model {
	t.Helper()
	m, err := LoadModel()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestModelLoadsAndIsConsistent(t *testing.T) {
	m := mustModel(t)
	c := m.Counts()
	t.Logf("model: %d options (%d yaml, %d env, %d flags), %d values (%d invalid), %d conflicts, %d posture rules, groups %v",
		c.Params, c.YAML, c.Env, c.Arg, c.Values, c.Invalid, len(m.Conflicts), len(m.Posture), c.Groups)
	for _, r := range m.Posture {
		if postureFuncs[r.ID] == nil {
			t.Errorf("posture rule %s has no predicate", r.ID)
		}
	}
	for id := range postureFuncs {
		if m.PostureRule(id) == nil {
			t.Errorf("predicate %s has no model entry", id)
		}
	}
}

// surfacePaths is the YAML surface plus the deprecated alias spellings Load rewrites.
func surfacePaths() map[string]SurfaceEntry {
	out := map[string]SurfaceEntry{}
	for _, e := range Surface() {
		out[strings.ReplaceAll(e.Path, "[]", "")] = e
	}
	for _, a := range config.DeprecatedSettingAliasPaths() {
		out[strings.ReplaceAll(a[0], "[]", "")] = SurfaceEntry{Path: a[0], Type: "alias of " + a[1]}
	}
	return out
}

// Every YAML option of the model must exist in config.Config, so the model cannot rot
// as options are renamed or removed.
func TestModelPathsExistInConfig(t *testing.T) {
	m := mustModel(t)
	sp := surfacePaths()
	for _, p := range m.Params {
		if p.Kind != KindYAML {
			continue
		}
		if _, ok := sp[p.Path]; !ok {
			t.Errorf("model option %s (%s) is not a key of config.Config", p.ID, p.Path)
		}
	}
	for _, cf := range m.Conflicts {
		for path := range cf.When {
			if strings.HasPrefix(path, "KEYORIX_") || strings.HasPrefix(path, "--") || strings.HasSuffix(path, "#haspw") {
				continue
			}
			if _, ok := sp[path]; !ok {
				t.Errorf("conflict %s refers to unknown key %s", cf.ID, path)
			}
		}
	}
	for _, r := range m.Posture {
		for _, k := range r.Explicit {
			if _, ok := sp[k]; !ok {
				t.Errorf("posture %s refers to unknown key %s", r.ID, k)
			}
		}
	}
}

// surface.json is the machine-readable inventory of the whole YAML surface. Run with
// CONFIGSPACE_UPDATE=1 to regenerate after the configuration structs change.
func TestSurfaceInventoryUpToDate(t *testing.T) {
	got, _ := json.MarshalIndent(Surface(), "", " ")
	got = append(got, '\n')
	path := "surface.json"
	if os.Getenv("CONFIGSPACE_UPDATE") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run CONFIGSPACE_UPDATE=1 go test ./scripts/fuzzing/configspace -run Surface)", err)
	}
	if string(want) != string(got) {
		t.Fatalf("surface.json is stale: config.Config gained or lost options; regenerate with CONFIGSPACE_UPDATE=1")
	}
	t.Logf("surface: %d YAML keys, %d secret-bearing", len(Surface()), countSecret(Surface()))
}

func countSecret(s []SurfaceEntry) int {
	n := 0
	for _, e := range s {
		if e.Secret {
			n++
		}
	}
	return n
}

func TestPairwiseSmallIsCovering(t *testing.T) {
	for _, sizes := range [][]int{{2, 2}, {3, 3, 3}, {2, 3, 4, 5}, {4, 4, 4, 4, 4, 4, 4}, {1, 5, 1, 3}} {
		rows := Pairwise(sizes, 7, 12)
		if g := PairGaps(sizes, rows); g != 0 {
			t.Errorf("sizes %v: %d uncovered pairs", sizes, g)
		}
	}
	// 3^4 needs at least 9 rows; the greedy result must not be wildly worse.
	if n := len(Pairwise([]int{3, 3, 3, 3}, 1, 20)); n > 13 {
		t.Errorf("3^4 array has %d rows, want <= 13", n)
	}
}

func TestPairwiseModelCoversAndIsDeterministic(t *testing.T) {
	m := mustModel(t)
	a, rowsA, sizes := PairwiseCases(m, PairwiseOpts{Name: "pair-all", Seed: 1, Tries: 8})
	b, _, _ := PairwiseCases(m, PairwiseOpts{Name: "pair-all", Seed: 1, Tries: 8})
	if g := PairGaps(sizes, rowsA); g != 0 {
		t.Fatalf("%d uncovered pairs", g)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same seed produced different arrays")
	}
	for _, c := range a {
		for id, vi := range c.Assign {
			if m.Param(id).Values[vi].Class == ClassInvalid {
				t.Fatalf("invalid value in pairwise row %s", c.ID)
			}
		}
	}
	t.Logf("pair-all: %d rows over %d options", len(a), len(sizes))
}

func TestSecretPathDetection(t *testing.T) {
	for p, want := range map[string]bool{
		"storage.database.password": true, "server.http.metrics_token": true, "server.http.metrics_token_file": false,
		"storage.database.dsn": true, "audit.siem.token": true, "server.http.port": false, "sso.providers.client_secret": true,
	} {
		if IsSecretPath(p) != want {
			t.Errorf("IsSecretPath(%q) != %v", p, want)
		}
	}
}

func TestRenderPlaceholders(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"certs", "keys", "secrets"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o700)
	}
	_ = os.WriteFile(filepath.Join(dir, "secrets", "master_password"), []byte("pw\n"), 0o600)
	tpl := &Template{Dir: dir, Doc: map[string]any{"server": map[string]any{"http": map[string]any{"port": "1"}}}, Passphrase: "pw"}
	m := mustModel(t)
	c := &Case{ID: "t1", Assign: map[string]int{"http.port": 0, "http.metrics.token": 1}}
	if err := c.Materialize(m, tpl, t.TempDir(), true); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetPath(c.Doc, "server.http.port"); got == "$PORT" || got == "" {
		t.Errorf("port placeholder not resolved: %v", got)
	}
	tok, _ := GetPath(c.Doc, "server.http.metrics_token")
	if !strings.HasPrefix(tok.(string), "cnry_metrics_") {
		t.Errorf("canary not resolved: %v", tok)
	}
	if len(c.Canaries) != 1 {
		t.Errorf("canaries: %v", c.Canaries)
	}
}
