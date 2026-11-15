package ci_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run the jq filter that ci.yml's `changes` job uses to decide
// whether the `fuzz-targets` check runs on a FAST pull_request (MQ-LEVERS-2 P1).
// The filter is not copied here: it is extracted from ci.yml between the
// "BEGIN fuzz-pr-gate" / "END fuzz-pr-gate" markers, so the test cannot drift
// from the workflow. Inputs are the recorded `pulls/N/files` lists of real PRs
// (testdata/fuzzgate; patches are cut to their hunk headers plus the lines that
// mention `func Fuzz` or `//go:build`, the only lines the filter reads). They
// need jq, as the ubuntu runners have.

const fuzzGateCI = "../../.github/workflows/ci.yml"

// fuzzGateFilter returns the jq program between the markers.
func fuzzGateFilter(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(fuzzGateCI)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	_, rest, ok := strings.Cut(text, "# BEGIN fuzz-pr-gate\n")
	if !ok {
		t.Fatal("ci.yml has no '# BEGIN fuzz-pr-gate' marker")
	}
	body, _, ok := strings.Cut(rest, "# END fuzz-pr-gate")
	if !ok {
		t.Fatal("ci.yml has no '# END fuzz-pr-gate' marker")
	}
	_, prog, ok := strings.Cut(body, "FUZZ_PR_GATE_JQ='")
	if !ok {
		t.Fatal("the gate block does not assign FUZZ_PR_GATE_JQ='...'")
	}
	prog, _, ok = strings.Cut(prog, "'\n")
	if !ok {
		t.Fatal("the FUZZ_PR_GATE_JQ assignment is not closed by a single quote")
	}
	return prog
}

type prFile struct {
	Filename string `json:"filename"`
	Status   string `json:"status"`
	Patch    string `json:"patch"`
}

func fuzzGateFixture(t *testing.T, name string) []prFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "fuzzgate", name)) //nolint:gosec // repo testdata
	if err != nil {
		t.Fatal(err)
	}
	var files []prFile
	if err := json.Unmarshal(raw, &files); err != nil {
		t.Fatal(err)
	}
	return files
}

func fuzzGateDrop(files []prFile, drop func(prFile) bool) []prFile {
	var out []prFile
	for _, f := range files {
		if !drop(f) {
			out = append(out, f)
		}
	}
	return out
}

// fuzzGateRun feeds the file list to the CI filter exactly as the workflow does
// (`jq -s 'add // []' | jq "$FUZZ_PR_GATE_JQ"`) and returns its verdict.
func fuzzGateRun(t *testing.T, files []prFile) string {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	if files == nil {
		files = []prFile{}
	}
	in, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	slurp := exec.Command("jq", "-s", "add // []") //nolint:gosec // fixed args
	slurp.Stdin = strings.NewReader(string(in))
	mid, err := slurp.Output()
	if err != nil {
		t.Fatalf("jq -s: %v", err)
	}
	gate := exec.Command("jq", fuzzGateFilter(t)) //nolint:gosec // program from this repo's ci.yml
	gate.Stdin = strings.NewReader(string(mid))
	out, err := gate.CombinedOutput()
	if err != nil {
		t.Fatalf("gate filter: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func isScriptsFuzzing(f prFile) bool { return strings.HasPrefix(f.Filename, "scripts/fuzzing/") }

func TestFuzzPRGate_RealPRs(t *testing.T) {
	pr4194 := fuzzGateFixture(t, "pr4194-files.json")
	pr4143 := fuzzGateFixture(t, "pr4143-files.json")

	cases := []struct {
		name  string
		files []prFile
		want  string
	}{
		{
			// The PR as merged: new Fuzz func plus its targets.d conf.
			name: "#4194 as merged", files: pr4194, want: "true",
		},
		{
			// The head that failed fuzz-targets in the queue three times:
			// FuzzAuthzSeqSwarmPlant added in seq_swarm_test.go, no targets.d conf.
			// The file name does not say "fuzz"; only the patch does.
			name: "#4194 failing head (no scripts/fuzzing change)", files: fuzzGateDrop(pr4194, isScriptsFuzzing), want: "true",
		},
		{
			// #4194 without its two Fuzz-adding files: the remaining _test.go
			// patches only MENTION FuzzAuthzSeq / FuzzOpenAPIStateful in a context
			// line or a hunk header, which is no change to a target.
			name: "#4194 minus the files that add a Fuzz func", want: "false",
			files: fuzzGateDrop(pr4194, func(f prFile) bool {
				return isScriptsFuzzing(f) || strings.HasSuffix(f.Filename, "seq_swarm_test.go")
			}),
		},
		{
			name: "#4315 go.mod bump", files: fuzzGateFixture(t, "pr4315-files.json"), want: "false",
		},
		{
			name: "#4143 as merged", files: pr4143, want: "true",
		},
		{
			// #4143's _test.go files that define no Fuzz func, nothing under scripts/fuzzing.
			name: "#4143 plain tests only", want: "false",
			files: fuzzGateDrop(pr4143, func(f prFile) bool {
				return isScriptsFuzzing(f) || strings.HasSuffix(f.Filename, "egress_parity_differential_test.go")
			}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fuzzGateRun(t, tc.files); got != tc.want {
				t.Fatalf("gate = %q, want %q", got, tc.want)
			}
		})
	}
}

// Synthetic edge cases for shapes the recorded PRs do not contain.
func TestFuzzPRGate_Shapes(t *testing.T) {
	cases := []struct {
		name  string
		files []prFile
		want  string
	}{
		{"empty list", nil, "false"},
		{"targets.d conf only", []prFile{{Filename: "scripts/fuzzing/targets.d/a__FuzzA.conf", Status: "added", Patch: "@@ -0,0 +1 @@"}}, "true"},
		{"targets.conf only", []prFile{{Filename: "scripts/fuzzing/targets.conf", Status: "modified", Patch: "@@ -1 +1 @@"}}, "true"},
		{"other scripts/fuzzing file is not this gate", []prFile{{Filename: "scripts/fuzzing/README.md", Status: "modified", Patch: "@@ -1 +1 @@"}}, "false"},
		{"Fuzz func removed", []prFile{{Filename: "x/a_test.go", Status: "modified", Patch: "@@ -3,5 +3,0 @@\n-func FuzzGone(f *testing.F) {"}}, "true"},
		{"Fuzz func renamed", []prFile{{Filename: "x/a_test.go", Status: "modified", Patch: "@@ -3 +3 @@\n-func FuzzOld(f *testing.F) {\n+func FuzzNew(f *testing.F) {"}}, "true"},
		{"build tag moved", []prFile{{Filename: "x/a_test.go", Status: "modified", Patch: "@@ -1,2 +1,2 @@\n-//go:build !race\n+//go:build race"}}, "true"},
		{"fuzz-named test file", []prFile{{Filename: "x/fuzz_helpers_test.go", Status: "modified", Patch: "@@ -1 +1 @@\n+x"}}, "true"},
		{"renamed test file has no patch", []prFile{{Filename: "x/b_test.go", Status: "renamed"}}, "true"},
		{"non-test go file with a Fuzz func is not a target", []prFile{{Filename: "x/fuzzkit.go", Status: "modified", Patch: "@@ -1 +1 @@\n+func FuzzHelper() {}"}}, "false"},
		{"test without Fuzz", []prFile{{Filename: "x/a_test.go", Status: "modified", Patch: "@@ -1 +1 @@\n+func TestA(t *testing.T) {}"}}, "false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fuzzGateRun(t, tc.files); got != tc.want {
				t.Fatalf("gate = %q, want %q", got, tc.want)
			}
		})
	}
}

// The job must read the output, keep its skip conditions, and the context name
// must stay `fuzz-targets` (a required check).
func TestFuzzPRGate_JobWiring(t *testing.T) {
	raw, err := os.ReadFile(fuzzGateCI)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	_, job, ok := strings.Cut(text, "\n  fuzz-targets:\n")
	if !ok {
		t.Fatal("ci.yml has no fuzz-targets job")
	}
	var cond string
	for l := range strings.SplitSeq(job, "\n") {
		if strings.HasPrefix(l, "    if: ") {
			cond = l
			break
		}
	}
	for _, need := range []string{
		"needs.changes.outputs.fuzz_pr_relevant == 'true'",
		"needs.changes.outputs.full_profile == 'true'",
		"needs.changes.outputs.queue_verified != 'true'",
		"needs.changes.outputs.docs_only != 'true'",
		"needs.select.outputs.gate_fuzz_targets == 'true'",
	} {
		if !strings.Contains(cond, need) {
			t.Errorf("fuzz-targets if: lost %q\n%s", need, cond)
		}
	}
	if !strings.Contains(text, "fuzz_pr_relevant: ${{ steps.filter.outputs.fuzz_pr_relevant }}") {
		t.Error("changes job does not export fuzz_pr_relevant")
	}
}
