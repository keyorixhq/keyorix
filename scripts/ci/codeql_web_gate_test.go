package ci_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// These tests pin how .github/workflows/codeql.yml decides to run the JS/TS
// analysis in the merge queue: only when the group diff touches web/**. Since
// CI-LIGHT-1, CodeQL runs on merge_group, push to main and the weekly
// schedule; on pull_request only the PR-time gate runs (Analyze (server), for
// non-test root-module Go, CODEQL-PR-GATE-1). They execute the real
// `changes` job script (extracted from the workflow, `gh` stubbed, context
// values passed through env: as the workflow does), so a regression in the
// filter is caught here, not by an alert that never appears. They do not prove
// CodeQL itself runs; that is CI's job.

type workflow struct {
	Jobs map[string]struct {
		If    string `yaml:"if"`
		Steps []struct {
			ID  string `yaml:"id"`
			Run string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func loadWorkflow(t *testing.T) workflow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "codeql.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var w workflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

// runFilter executes the `changes` job's filter script for the given event and
// changed-file list and returns the key=value pairs it wrote to GITHUB_OUTPUT.
func runFilter(t *testing.T, event string, files []string) map[string]string {
	t.Helper()
	var script string
	for _, s := range loadWorkflow(t).Jobs["changes"].Steps {
		if s.ID == "filter" {
			script = s.Run
		}
	}
	if script == "" {
		t.Fatal("changes job has no step with id: filter")
	}
	dir := t.TempDir()
	stub := "#!/bin/sh\nprintf '%s\\n' \"$FAKE_FILES\"\n"
	if len(files) == 0 {
		stub = "#!/bin/sh\nexit 0\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(stub), 0o755); err != nil { //nolint:gosec // test stub must be executable
		t.Fatal(err)
	}
	out := filepath.Join(dir, "output")
	cmd := exec.Command("bash", "-e", "-c", script) //nolint:gosec // script is this repo's own workflow step
	cmd.Env = append(os.Environ(),
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GITHUB_OUTPUT="+out,
		"FAKE_FILES="+strings.Join(files, "\n"),
		"EVENT_NAME="+event,
		"REPO=keyorixhq/keyorix",
		"MG_BASE_SHA=base",
		"MG_HEAD_SHA=head",
		"PR_NUMBER=1",
	)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("filter script failed: %v\n%s", err, b)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for l := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		k, v, _ := strings.Cut(l, "=")
		got[k] = v
	}
	return got
}

func TestCodeQLWebChanged(t *testing.T) {
	cases := []struct {
		name  string
		event string
		files []string
		want  string
	}{
		{"group touching web", "merge_group", []string{"web/src/App.tsx", "server/x.go"}, "true"},
		{"group touching only web", "merge_group", []string{"web/package.json"}, "true"},
		{"group touching only go", "merge_group", []string{"server/x.go", "internal/y.go"}, "false"},
		{"group touching a look-alike dir", "merge_group", []string{"website/x.ts", "docs/web/a.md"}, "false"},
		{"group touching only the workflow", "merge_group", []string{".github/workflows/codeql.yml"}, "false"},
		{"group with empty file list fails safe", "merge_group", nil, "true"},
		{"push keeps full scan", "push", []string{"server/x.go"}, "true"},
		{"schedule keeps full scan", "schedule", nil, "true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runFilter(t, tc.event, tc.files)["web_changed"]
			if got != tc.want {
				t.Fatalf("web_changed = %q, want %q", got, tc.want)
			}
		})
	}
}

// The Go legs must keep their own gating: a web-only group must not turn them on.
func TestCodeQLWebOnlyGroupDoesNotRunGoLegs(t *testing.T) {
	got := runFilter(t, "merge_group", []string{"web/src/App.tsx"})
	for _, k := range []string{"root_go_changed", "operator_go_changed"} {
		if got[k] != "false" {
			t.Errorf("%s = %q for a web-only group, want false", k, got[k])
		}
	}
	if got["docs_only"] != "false" || got["go_unaffected"] != "false" || got["operator_only"] != "false" {
		t.Errorf("web-only group must not be classed docs-only/go-unaffected/operator-only: %v", got)
	}
}

// On pull_request the changes job runs (it decides the PR-time gate), the
// CodeQL summary stays skipped, and only Analyze (server) can run.
func TestCodeQLPullRequestJobs(t *testing.T) {
	w := loadWorkflow(t)
	if strings.Contains(w.Jobs["changes"].If, "pull_request") {
		t.Errorf("changes must run on pull_request (it decides the PR-time gate), got: %q", w.Jobs["changes"].If)
	}
	if !strings.Contains(w.Jobs["summary"].If, "github.event_name != 'pull_request'") {
		t.Errorf("summary must stay skipped on pull_request, got: %q", w.Jobs["summary"].If)
	}
	for _, f := range [][]string{{"internal/core/x.go"}, {"web/src/App.tsx", "operator/main.go"}, nil} {
		got := runFilter(t, "pull_request", f)
		if got["operator_go_changed"] != "false" || got["web_changed"] != "false" {
			t.Errorf("pull_request %v: operator/web legs must not run on a PR: %v", f, got)
		}
	}
}

// serverRuns evaluates Analyze (server)'s job condition on the filter outputs
// (TestCodeQLServerCondition pins that this is the workflow's condition).
func serverRuns(o map[string]string) bool {
	return o["docs_only"] != "true" && o["go_unaffected"] != "true" && o["operator_only"] != "true" && o["root_go_changed"] == "true"
}

func TestCodeQLServerCondition(t *testing.T) {
	want := "needs.changes.outputs.docs_only != 'true' && needs.changes.outputs.go_unaffected != 'true' && needs.changes.outputs.operator_only != 'true' && needs.changes.outputs.root_go_changed == 'true'"
	if got := loadWorkflow(t).Jobs["analyze-server"].If; got != want {
		t.Errorf("analyze-server if: changed; update serverRuns too.\ngot:  %s\nwant: %s", got, want)
	}
}

// The PR-time gate runs Analyze (server) only for non-test Go of the root
// module (plus go.mod/go.sum, the query pack, codeql.yml and the gate script),
// and when the PR's file list cannot be read.
func TestCodeQLPullRequestServerGate(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  bool
	}{
		{"core change", []string{"internal/core/account.go", "internal/core/account_test.go"}, true},
		{"handler change (#3543 shape)", []string{"server/http/handlers/auth.go", "changelog.d/x.md"}, true},
		{"cmd change", []string{"cmd/keyorix-mcp/main.go"}, true},
		{"go.mod bump", []string{"go.mod", "go.sum"}, true},
		{"query pack", []string{".github/codeql/go-queries/Ssrf.ql"}, true},
		{"this workflow", []string{".github/workflows/codeql.yml"}, true},
		{"gate script", []string{"scripts/ci/codeql-gate.sh"}, true},
		{"unreadable file list fails safe", nil, true},
		{"test-only change", []string{"internal/core/account_test.go", "server/http/x_test.go"}, false},
		{"cli module", []string{"cli/cmd/run.go"}, false},
		{"operator module", []string{"operator/internal/controller/x.go"}, false},
		{"migrate module", []string{"migrate/internal/healthscan/client.go"}, false},
		{"docs", []string{"docs/x.md", "README.md"}, false},
		{"web", []string{"web/src/App.tsx"}, false},
		// Same as the queue: scripts/ is in go_unaffected's allowlist, so a
		// scripts-only Go change is not analysed before merge (see LEFTOVERS
		// of CODEQL-PR-GATE-1).
		{"scripts-only go", []string{"scripts/metrics/surfacewalk/startup.go"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := serverRuns(runFilter(t, "pull_request", tc.files)); got != tc.want {
				t.Fatalf("Analyze (server) runs = %v, want %v", got, tc.want)
			}
		})
	}
}

// A gate-script-only merge group runs the gate (it lives under scripts/, which
// go_unaffected otherwise treats as Go-free); queue behaviour for other diffs
// is unchanged.
func TestCodeQLMergeGroupServerGate(t *testing.T) {
	cases := []struct {
		files []string
		want  bool
	}{
		{[]string{"scripts/ci/codeql-gate.sh"}, true},
		{[]string{".github/workflows/codeql.yml"}, true},
		{[]string{"internal/core/account_test.go"}, true},
		{[]string{"cli/cmd/run.go"}, true},
		{[]string{"scripts/ci/select-affected.py"}, false},
		{[]string{"docs/x.md"}, false},
		{[]string{"web/src/App.tsx"}, false},
	}
	for _, tc := range cases {
		if got := serverRuns(runFilter(t, "merge_group", tc.files)); got != tc.want {
			t.Errorf("merge_group %v: Analyze (server) runs = %v, want %v", tc.files, got, tc.want)
		}
	}
}

func TestCodeQLAnalyzeWebGate(t *testing.T) {
	cond := loadWorkflow(t).Jobs["analyze-web"].If
	if !strings.Contains(cond, "needs.changes.outputs.web_changed == 'true'") {
		t.Errorf("analyze-web must be gated on web_changed, got: %s", cond)
	}
	if strings.Contains(cond, "github.event_name != 'pull_request'") {
		t.Errorf("analyze-web is skipped on pull_request through the changes job; its own if: must not repeat that, got: %s", cond)
	}
	for _, keep := range []string{"docs_only != 'true'", "go_unaffected != 'true'", "operator_only != 'true'"} {
		if !strings.Contains(cond, keep) {
			t.Errorf("analyze-web lost the %s gate: %s", keep, cond)
		}
	}
}
