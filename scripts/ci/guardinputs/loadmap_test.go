package main

// Tests of the dual-read LoadMap: the legacy guard-inputs.tsv plus the
// one-row fragments in guard-inputs.d/.

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const legacyHeader = "# legacy header\n\n"

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadMapDualRead(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		want    []string // File of each row, in order
		wantErr []string // substrings of the error; nil = no error
	}{
		{
			name: "legacy and fragments merge, legacy first, fragments sorted by file name",
			files: map[string]string{
				"guard-inputs.tsv":                  legacyHeader + "a_test.go\t**/*.md\tlegacy a\n",
				"guard-inputs.d/z__z_test.go.tsv":   "z_test.go\t*.sh\tfrag z\n",
				"guard-inputs.d/b__b_test.go.tsv":   "b_test.go\t*.yml\tfrag b\n",
				"guard-inputs.d/README.md":          "not a fragment: only *.tsv is read\n",
				"guard-inputs.d/sub/ignored.tsv":    "s_test.go\t*.go\tin a subdirectory\n",
				"guard-inputs.d/mid__m_test.go.tsv": "m_test.go\t!x\tfrag m\n",
			},
			want: []string{"a_test.go", "b_test.go", "m_test.go", "z_test.go"},
		},
		{
			name:  "missing fragment directory is fine",
			files: map[string]string{"guard-inputs.tsv": legacyHeader + "a_test.go\t*.md\tn\n"},
			want:  []string{"a_test.go"},
		},
		{
			name:    "missing legacy file is an error",
			files:   map[string]string{"guard-inputs.d/a.tsv": "a_test.go\t*.md\tn\n"},
			wantErr: []string{"guard-inputs.tsv"},
		},
		{
			name: "two rows in one fragment",
			files: map[string]string{
				"guard-inputs.tsv":     legacyHeader,
				"guard-inputs.d/x.tsv": "a_test.go\t*.md\tn\nb_test.go\t*.md\tn\n",
			},
			wantErr: []string{"guard-inputs.d/x.tsv", "exactly one data row", "found 2"},
		},
		{
			name: "comment-only fragment holds no row",
			files: map[string]string{
				"guard-inputs.tsv":     legacyHeader,
				"guard-inputs.d/c.tsv": "# only a comment\n\n",
			},
			wantErr: []string{"guard-inputs.d/c.tsv", "exactly one data row", "found 0"},
		},
		{
			name: "comments and blank lines around the one row are allowed",
			files: map[string]string{
				"guard-inputs.tsv":     legacyHeader,
				"guard-inputs.d/c.tsv": "# why\n\nc_test.go\t*.md\tn\n\n# end\n",
			},
			want: []string{"c_test.go"},
		},
		{
			name: "duplicate key, legacy vs fragment",
			files: map[string]string{
				"guard-inputs.tsv":     legacyHeader + "a_test.go\t*.md\tlegacy\n",
				"guard-inputs.d/a.tsv": "a_test.go\t*.sh\tfrag\n",
			},
			wantErr: []string{"guard-inputs.d/a.tsv:1", "a_test.go already mapped at", "guard-inputs.tsv:3"},
		},
		{
			name: "duplicate key, fragment vs fragment",
			files: map[string]string{
				"guard-inputs.tsv":     legacyHeader,
				"guard-inputs.d/a.tsv": "a_test.go\t*.md\tone\n",
				"guard-inputs.d/b.tsv": "# c\na_test.go\t*.sh\ttwo\n",
			},
			wantErr: []string{"guard-inputs.d/b.tsv:2", "a_test.go already mapped at", "guard-inputs.d/a.tsv:1"},
		},
		{
			name: "duplicate key inside the legacy file stays an error",
			files: map[string]string{
				"guard-inputs.tsv": legacyHeader + "a_test.go\t*.md\tone\na_test.go\t*.sh\ttwo\n",
			},
			wantErr: []string{"guard-inputs.tsv:4", "already mapped at", "guard-inputs.tsv:3"},
		},
		{
			name: "empty note in a fragment names the fragment",
			files: map[string]string{
				"guard-inputs.tsv":     legacyHeader,
				"guard-inputs.d/n.tsv": "n_test.go\t*.md\t \n",
			},
			wantErr: []string{"guard-inputs.d/n.tsv:1", "note column is empty"},
		},
		{
			name: "empty glob in a fragment names the fragment",
			files: map[string]string{
				"guard-inputs.tsv":     legacyHeader,
				"guard-inputs.d/g.tsv": "g_test.go\t*.md,,*.sh\tn\n",
			},
			wantErr: []string{"guard-inputs.d/g.tsv:1", "empty glob"},
		},
		{
			name: "wrong column count in a fragment names the fragment",
			files: map[string]string{
				"guard-inputs.tsv":     legacyHeader,
				"guard-inputs.d/w.tsv": "w_test.go\t*.md\n",
			},
			wantErr: []string{"guard-inputs.d/w.tsv:1", "want 3 tab-separated columns"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeTree(t, c.files)
			rows, err := LoadMap(filepath.Join(dir, "guard-inputs.tsv"))
			if c.wantErr != nil {
				if err == nil {
					t.Fatalf("want an error containing %q, got rows %+v", c.wantErr, rows)
				}
				for _, s := range c.wantErr {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("error %q lacks %q", err, s)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, r := range rows {
				got = append(got, r.File)
				if r.Source == "" || r.Line == 0 {
					t.Errorf("row %s has no source/line: %+v", r.File, r)
				}
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("rows = %v, want %v", got, c.want)
			}
		})
	}
}

// TestLoadMapFragmentRowIsParsedLikeALegacyRow: globs, '!' non-inputs and the
// note come out the same from a fragment as from the legacy file.
func TestLoadMapFragmentRowIsParsedLikeALegacyRow(t *testing.T) {
	row := "s_test.go\t**/*.md, scripts/**/*.sh ,!web/**\tthe note\n"
	dir := writeTree(t, map[string]string{
		"guard-inputs.tsv":     legacyHeader + row,
		"guard-inputs.d/s.tsv": strings.Replace(row, "s_test.go", "t_test.go", 1),
	})
	rows, err := LoadMap(filepath.Join(dir, "guard-inputs.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows", len(rows))
	}
	a, b := rows[0], rows[1]
	if !slices.Equal(a.Inputs, b.Inputs) || !slices.Equal(a.NotRead, b.NotRead) || a.Note != b.Note {
		t.Errorf("legacy %+v and fragment %+v rows differ", a, b)
	}
	if !slices.Equal(b.Inputs, []string{"**/*.md", "scripts/**/*.sh"}) || !slices.Equal(b.NotRead, []string{"web/**"}) {
		t.Errorf("fragment row parsed as %+v", b)
	}
	if !b.Matches("docs/x.md") || !b.Matches("scripts/a/b.sh") || b.Matches("web/x.js") {
		t.Errorf("Matches is wrong for the fragment row")
	}
}

// TestPlanWithFragmentsIsDeterministic: the plan from legacy+fragments does
// not depend on how the rows are spread over the two stores.
func TestPlanWithFragmentsIsDeterministic(t *testing.T) {
	test := func(name string) string {
		return "package p\n\nimport \"testing\"\n\nfunc Test" + name + "(t *testing.T) {}\n"
	}
	tree := map[string]string{
		"x/a_test.go": test("A"),
		"x/b_test.go": test("B"),
		"y/c_test.go": test("C"),
	}
	allLegacy := legacyHeader + "x/a_test.go\t*.md\tn\nx/b_test.go\t*.md\tn\ny/c_test.go\t*.md\tn\n"
	split := map[string]string{
		"guard-inputs.tsv":                legacyHeader + "x/b_test.go\t*.md\tn\n",
		"guard-inputs.d/y__c_test.go.tsv": "y/c_test.go\t*.md\tn\n",
		"guard-inputs.d/x__a_test.go.tsv": "x/a_test.go\t*.md\tn\n",
		"guard-inputs.d/README.md":        "x\n",
	}
	var plans [2][]Step
	for i, files := range []map[string]string{{"guard-inputs.tsv": allLegacy}, split} {
		dir := writeTree(t, tree)
		for name, body := range files {
			p := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		rows, err := LoadMap(filepath.Join(dir, "guard-inputs.tsv"))
		if err != nil {
			t.Fatal(err)
		}
		plans[i], err = Plan(dir, rows, []string{"README.md"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(plans[0], plans[1]) {
		t.Errorf("plans differ: legacy-only %+v, split %+v", plans[0], plans[1])
	}
	if len(plans[0]) != 2 || plans[0][0].Package != "./x" || plans[0][1].Package != "./y" {
		t.Errorf("unexpected plan %+v", plans[0])
	}
}

// TestPlanErrorNamesTheFragment: a fragment row whose test file is missing
// reports the fragment path, not a bare line number.
func TestPlanErrorNamesTheFragment(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"guard-inputs.tsv":     legacyHeader,
		"guard-inputs.d/m.tsv": "gone_test.go\t*.md\tn\n",
	})
	rows, err := LoadMap(filepath.Join(dir, "guard-inputs.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Plan(dir, rows, nil)
	if err == nil || !strings.Contains(err.Error(), "guard-inputs.d/m.tsv:1") {
		t.Fatalf("want an error naming guard-inputs.d/m.tsv:1, got %v", err)
	}
}

// TestFixHintAsksForOneFragment: a guard with no row is told to add one
// fragment, not a line in the legacy file.
func TestFixHintAsksForOneFragment(t *testing.T) {
	got := fixHint("server/utc_write_guard_test.go", false, Row{})
	for _, s := range []string{"ONE fragment", "scripts/ci/guard-inputs.d/server__utc_write_guard_test.go.tsv", "not a line in scripts/ci/guard-inputs.tsv"} {
		if !strings.Contains(got, s) {
			t.Errorf("hint %q lacks %q", got, s)
		}
	}
	mapped := fixHint("a_test.go", true, Row{Source: "scripts/ci/guard-inputs.d/a.tsv"})
	if !strings.Contains(mapped, "extend its row in scripts/ci/guard-inputs.d/a.tsv") {
		t.Errorf("mapped hint %q", mapped)
	}
}

// TestMigrateScriptKnowsGuardInputs: scripts/ledgers/migrate-to-fragments.sh
// --dry-run lists guard-inputs.tsv and writes nothing.
func TestMigrateScriptKnowsGuardInputs(t *testing.T) {
	root := repoRoot(t)
	before, err := os.ReadFile(filepath.Join(root, DefaultMap)) // #nosec G304 -- tracked repo file
	if err != nil {
		t.Fatal(err)
	}
	rows, err := LoadMap(filepath.Join(root, DefaultMap))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "ledgers", "migrate-to-fragments.sh"), "--dry-run")
	cmd.Env = append(os.Environ(), "LEDGER_ROOT="+root)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("migrate --dry-run: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "scripts/ci/guard-inputs.tsv") {
		t.Errorf("--dry-run does not mention scripts/ci/guard-inputs.tsv:\n%s", out)
	}
	after, err := os.ReadFile(filepath.Join(root, DefaultMap)) // #nosec G304 -- tracked repo file
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("--dry-run modified the legacy file")
	}
	if len(rows) == 0 {
		t.Error("no rows loaded")
	}
}
