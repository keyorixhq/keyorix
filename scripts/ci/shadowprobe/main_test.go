package main

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `package p

const K = 1

func A(x int) int {
	if x > 0 {
		x++
	}

	return x
}

func B(x int) int {
	if x > 100 {
		x--
	}
	switch x {
	case 1:
		x = 2
	}
	return x
}

func Empty() {}
`

func TestInstrumentReportsAndStaysValidGo(t *testing.T) {
	out, rep, pkg, err := instrument([]byte(sample), "p.go", []int{7, 3, 18, 24}, []int{15})
	if err != nil {
		t.Fatal(err)
	}
	if pkg != "p" {
		t.Fatalf("pkg=%q", pkg)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "p.go", out, 0); err != nil {
		t.Fatalf("rewritten source does not parse: %v\n%s", err, out)
	}
	want := map[int]string{3: "UNPROBED", 7: "probed", 15: "probed at function entry B", 18: "probed", 24: "UNPROBED"}
	for ln, w := range want {
		if !strings.HasPrefix(rep[ln], w) {
			t.Errorf("line %d: %q, want prefix %q", ln, rep[ln], w)
		}
	}
	// innermost statement: line 7 (x++) is probed inside the if, not before the if
	s := string(out)
	if i, j := strings.Index(s, `cs23Hit("p.go:7")`), strings.Index(s, "x++"); i < 0 || j < i {
		t.Errorf("probe for line 7 not directly before x++:\n%s", s)
	}
	if strings.Contains(s, `cs23Hit("p.go:3")`) {
		t.Errorf("a const line must not be probed")
	}
}

// TestProbeFiresOnlyWhenTheStatementRuns is the oracle's own red/green check on a
// real `go test`: B is never called, A is.
func TestProbeFiresOnlyWhenTheStatementRuns(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool")
	}
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module probetest\n\ngo 1.21\n")
	write("p.go", sample)
	write("p_test.go", "package p\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {\n\tif A(1) != 2 {\n\t\tt.Fatal(\"bad\")\n\t}\n}\n")
	out, _, pkg, err := instrument([]byte(sample), "p.go", []int{7, 10, 15, 21}, nil)
	if err != nil {
		t.Fatal(err)
	}
	write("p.go", string(out))
	write("cs23_probe.go", strings.Replace(probeFile, "%s", pkg, 1))
	mark := filepath.Join(dir, "mark.txt")
	cmd := exec.Command("go", "test", "-count=1", "./...")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CS23_PROBE_FILE="+mark, "GOFLAGS=", "GOWORK=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go test: %v\n%s", err, b)
	}
	got, _ := os.ReadFile(mark)
	hit := string(got)
	for _, must := range []string{"p.go:7", "p.go:10"} {
		if !strings.Contains(hit, must+"\n") {
			t.Errorf("A's statement %s ran but was not recorded:\n%s", must, hit)
		}
	}
	for _, mustNot := range []string{"p.go:15", "p.go:21"} {
		if strings.Contains(hit, mustNot+"\n") {
			t.Errorf("B's statement %s never ran but was recorded", mustNot)
		}
	}
}
