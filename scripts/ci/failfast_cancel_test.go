package ci_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run scripts/ci/failfast-cancel.sh, the merge-queue fail-fast cancel,
// against GitHub API responses recorded from a real queue entry (testdata/failfast).
// A fake `gh` on PATH records every call, so the real (non-dry-run) path is what is
// tested: which runs get a POST .../cancel, in which order, and that nothing outside
// the entry's own merge-group commit is ever touched. They need jq, as the ubuntu
// runners have.

const (
	ffRepo  = "keyorixhq/keyorix"
	ffRunID = "40131253944" // the CI run of the recorded entry
	ffSHA   = "654613e1c08a3bdffa81816d0dee228c9bd4e6ad"
)

const fakeGH = `#!/usr/bin/env bash
echo "$*" >> "$FAKE_GH_LOG"
case "$*" in
  "api repos/"*"/actions/runs?"*)
    if [ -n "${FAKE_GH_LIST:-}" ]; then cat "$FAKE_GH_LIST"; else exit 1; fi ;;
  "api -X POST "*)
    if [ -n "${FAKE_GH_POST_FAIL:-}" ]; then exit 1; fi
    echo '{}' ;;
  *) exit 2 ;;
esac
`

// runFailfast runs the script with a fake gh and returns its output and the gh calls.
func runFailfast(t *testing.T, list string, extraEnv ...string) (string, []string) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fakeGH), 0o700); err != nil { //nolint:gosec // test-only fake, must be executable
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "gh.log")
	listPath := ""
	if list != "" {
		listPath = filepath.Join("testdata", "failfast", list)
	}
	cmd := exec.Command("bash", "failfast-cancel.sh", "repo-guards") //nolint:gosec // this repo's own script
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_GH_LOG="+logPath, "FAKE_GH_LIST="+listPath,
		"GITHUB_REPOSITORY="+ffRepo, "GITHUB_RUN_ID="+ffRunID, "GITHUB_SHA="+ffSHA,
		"FAILFAST_RUNS_JSON=", "FAILFAST_DRY_RUN=")
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failfast-cancel.sh must never fail its caller, got %v\n%s", err, out)
	}
	raw, err := os.ReadFile(logPath) //nolint:gosec // path from t.TempDir
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var calls []string
	for l := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		if url, ok := strings.CutPrefix(l, "api -X POST "); ok {
			calls = append(calls, url)
		}
	}
	return string(out), calls
}

func cancelURL(id string) string { return "repos/" + ffRepo + "/actions/runs/" + id + "/cancel" }

func TestFailfastCancel(t *testing.T) {
	cases := []struct {
		name    string
		list    string
		env     []string
		want    []string // POST .../cancel calls, in order
		wantOut string
	}{
		{
			// Recorded entry: CI and CodeQL in progress, three workflows completed.
			name: "recorded entry: in-progress sibling first, own run last, completed runs untouched",
			list: "runs-654613e1.json",
			want: []string{cancelURL("40131253994"), cancelURL(ffRunID)},
		},
		{
			// The entry ahead in the queue (9ae53ec1...) still had CI and CodeQL running.
			name: "runs of another queue entry are never cancelled",
			list: "runs-mixed-queue.json",
			want: []string{cancelURL("40131253994"), cancelURL(ffRunID)},
		},
		{
			name:    "listing fails: still cancels its own run",
			list:    "",
			want:    []string{cancelURL(ffRunID)},
			wantOut: "listing the runs of " + ffSHA + " failed",
		},
		{
			name:    "cancel rejected (run already finished): warns, exits 0",
			list:    "runs-654613e1.json",
			env:     []string{"FAKE_GH_POST_FAIL=1"},
			want:    []string{cancelURL("40131253994"), cancelURL(ffRunID)},
			wantOut: "could not cancel run 40131253994 (CodeQL)",
		},
		{
			name:    "dry run sends nothing",
			list:    "runs-654613e1.json",
			env:     []string{"FAILFAST_DRY_RUN=1"},
			want:    nil,
			wantOut: "would cancel 40131253994 CodeQL",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, calls := runFailfast(t, tc.list, tc.env...)
			if strings.Join(calls, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("cancel calls:\n got %q\nwant %q\noutput:\n%s", calls, tc.want, out)
			}
			if tc.wantOut != "" && !strings.Contains(out, tc.wantOut) {
				t.Errorf("output lacks %q:\n%s", tc.wantOut, out)
			}
		})
	}
}

// The recorded response is only useful as a fixture while it still has a sibling in
// progress, a completed run and the entry's own CI run: guard against someone
// "refreshing" it with a response that no longer exercises the filter.
func TestFailfastCancelFixtureShape(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "failfast", "runs-654613e1.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`"id":` + ffRunID, `"status":"completed"`, `"name":"CodeQL","status":"in_progress"`, ffSHA} {
		if !strings.Contains(s, want) {
			t.Errorf("fixture lacks %s", want)
		}
	}
}
