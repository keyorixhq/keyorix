package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestIsFuzzTest_MatchesCmdGoRule(t *testing.T) {
	cases := map[string]struct {
		src  string
		want bool
	}{
		"plain":           {`func FuzzX(f *testing.F) {}`, true},
		"bare Fuzz":       {`func Fuzz(f *testing.F) {}`, true},
		"dot-import":      {`func FuzzX(f *F) {}`, true},
		"digit after":     {`func Fuzz1(f *testing.F) {}`, true},
		"lowercase after": {`func Fuzzy(f *testing.F) {}`, false},
		"t param":         {`func FuzzX(t *testing.T) {}`, false},
		"no param":        {`func FuzzX() {}`, false},
		"two params":      {`func FuzzX(f *testing.F, n int) {}`, false},
		"result":          {`func FuzzX(f *testing.F) error { return nil }`, false},
		"method":          {`func (r R) FuzzX(f *testing.F) {}`, false},
		"not fuzz":        {`func TestX(f *testing.F) {}`, false},
		"value F":         {`func FuzzX(f testing.F) {}`, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "x_test.go", "package x\n"+c.src, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := isFuzzTest(f.Decls[0].(*ast.FuncDecl)); got != c.want {
				t.Fatalf("isFuzzTest(%s) = %v, want %v", c.src, got, c.want)
			}
		})
	}
}

// writeModule creates a throwaway module and returns its directory.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["go.mod"] = "module example.com/m\n\ngo 1.24\n"
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runList(t *testing.T, dir string, pkgs ...string) string {
	t.Helper()
	t.Chdir(dir)
	var out, errb bytes.Buffer
	if err := list(&out, &errb, pkgs); err != nil {
		t.Fatalf("list: %v (stderr %s)", err, errb.String())
	}
	return out.String()
}

// TestListMatchesGoTestList pins the replaced command: on a module with internal
// and external test files, a build-tagged file and a *testing.F helper, list
// must print exactly what `go test -list '^Fuzz'` lists.
func TestListMatchesGoTestList(t *testing.T) {
	t.Setenv("GOFLAGS", "-mod=mod")
	dir := writeModule(t, map[string]string{
		"p/p.go": "package p\n",
		"p/a_test.go": `package p
import "testing"
func FuzzA(f *testing.F) {}
func helper(f *testing.F) {}
`,
		"p/x_test.go": `package p_test
import "testing"
func FuzzB(f *testing.F) {}
`,
		"p/tagged_test.go": `//go:build taintoverlay

package p
import "testing"
func FuzzTagged(f *testing.F) {}
`,
	})
	got := runList(t, dir, "./p")
	if want := "./p|FuzzA\n./p|FuzzB\n"; got != want {
		t.Fatalf("list = %q, want %q", got, want)
	}

	cmd := exec.Command("go", "test", "-list", "^Fuzz", "./p")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test -list: %v\n%s", err, out)
	}
	var listed []string
	for l := range strings.SplitSeq(string(out), "\n") {
		if strings.HasPrefix(l, "Fuzz") {
			listed = append(listed, "./p|"+l)
		}
	}
	slices.Sort(listed)
	if want := strings.Join(listed, "\n") + "\n"; got != want {
		t.Fatalf("list = %q, go test -list = %q", got, want)
	}
}

func TestListSkipsWhatGoCannotResolve(t *testing.T) {
	t.Setenv("GOFLAGS", "-mod=mod")
	dir := writeModule(t, map[string]string{
		"tool/main.go":      "//go:build ignore\n\npackage main\n",
		"tool/main_test.go": "//go:build ignore\n\npackage main\n",
		"good/g_test.go":    "package good\nimport \"testing\"\nfunc FuzzG(f *testing.F) {}\n",
		"broken/b_test.go":  "package broken\nimport \"testing\"\nfunc FuzzB(f *testing.F) {\n",
	})
	if got, want := runList(t, dir, "./tool", "./missing", "./broken", "./good"), "./good|FuzzG\n"; got != want {
		t.Fatalf("list = %q, want only the resolvable package %q", got, want)
	}
}

func planOf(pkgTargets map[string]int) []target {
	var ts []target
	for pkg, n := range pkgTargets {
		for i := range n {
			ts = append(ts, target{pkg, "Fuzz" + string(rune('A'+i))})
		}
	}
	slices.SortFunc(ts, func(a, b target) int { return strings.Compare(a.String(), b.String()) })
	return ts
}

func TestPackPlacesEveryTargetExactlyOnce(t *testing.T) {
	plan := planOf(map[string]int{"./internal/core": 14, "./server/http": 9, "./internal/saml": 3, "./pkg/new": 2})
	shards := pack(plan, 6, 720)
	var got []string
	for _, s := range shards {
		for _, t := range s {
			got = append(got, t.String())
		}
	}
	slices.Sort(got)
	var want []string
	for _, t := range plan {
		want = append(want, t.String())
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("packed targets differ from the plan:\n got %v\nwant %v", got, want)
	}
}

func TestPackIsDeterministic(t *testing.T) {
	plan := planOf(map[string]int{"./internal/core": 14, "./server/http": 9, "./internal/saml": 3})
	first := pack(plan, 6, 720)
	for range 20 {
		shuffled := slices.Clone(plan)
		slices.Reverse(shuffled)
		if !slices.EqualFunc(first, pack(shuffled, 6, 720), slices.Equal[[]target]) {
			t.Fatal("pack depends on input order")
		}
	}
}

func TestPackDoesNotSplitAPackageForNothing(t *testing.T) {
	// Six small targets of one package fit one shard: compiling it on two
	// runners would cost a second compile and buy no fuzzing.
	shards := pack(planOf(map[string]int{"./internal/core": 6}), 6, 720)
	if len(shards) != 1 {
		t.Fatalf("got %d shards, want 1: %v", len(shards), shards)
	}
}

func TestPackSpreadsAPackageThatWouldOverloadOneShard(t *testing.T) {
	plan := planOf(map[string]int{"./internal/core": 30})
	shards := pack(plan, 6, 720)
	if len(shards) < 2 {
		t.Fatalf("30 targets of one package landed on %d shard(s)", len(shards))
	}
	for _, s := range shards {
		if got := shardSeconds(s); got > 720+targetSeconds+compileCost("./internal/core") {
			t.Fatalf("shard estimated %ds", got)
		}
	}
}

func TestPackNeverExceedsMaxShardsOrTargetCount(t *testing.T) {
	if got := len(pack(planOf(map[string]int{"./a": 40, "./b": 40}), 6, 60)); got != 6 {
		t.Fatalf("got %d shards, want the cap of 6", got)
	}
	if got := len(pack(planOf(map[string]int{"./a": 2}), 6, 1)); got != 2 {
		t.Fatalf("got %d shards for 2 targets, want 2", got)
	}
}

func TestPackEmptyPlan(t *testing.T) {
	var out, errb bytes.Buffer
	if err := runPack(strings.NewReader("\n"), &out, &errb, nil); err != nil {
		t.Fatal(err)
	}
	var got []shard
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || len(got) != 0 {
		t.Fatalf("empty plan = %s (err %v), want []", out.String(), err)
	}
}

func TestPackOutputKeepsTheWorkflowFormat(t *testing.T) {
	var out, errb bytes.Buffer
	plan := "./internal/core|FuzzA\n./server|FuzzB\n"
	if err := runPack(strings.NewReader(plan), &out, &errb, []string{"-shards", "2", "-max-shard-seconds", "60"}); err != nil {
		t.Fatal(err)
	}
	var got []shard
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i, s := range got {
		if s.ID != i {
			t.Fatalf("shard %d has id %d", i, s.ID)
		}
		for entry := range strings.FieldsSeq(s.Targets) {
			seen[entry] = true
		}
	}
	if want := []string{"./internal/core|FuzzA", "./server|FuzzB"}; !slices.Equal(slices.Sorted(maps.Keys(seen)), want) {
		t.Fatalf("targets = %v, want %v", seen, want)
	}
}

func TestPackRejectsAMalformedLine(t *testing.T) {
	var out, errb bytes.Buffer
	if err := runPack(strings.NewReader("no-separator\n"), &out, &errb, nil); err == nil {
		t.Fatal("malformed plan line was accepted")
	}
}
