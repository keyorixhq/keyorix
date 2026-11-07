package main

// CI-PATHGATE-1: the FAST pull_request gates of two always-on checks in
// .github/workflows/ci.yml.
//
//   - adr-numbers: `check-closures.sh --self-test` and
//     `check-adr-conformance.sh --self-test` run on a FAST PR only when
//     closure_selftest_relevant; otherwise the plain "Verify" step of the same
//     ledger runs instead (the self-test verifies the real ledger first, so
//     each ledger is verified exactly once).
//   - assert-leg-completeness: the shard-partition step
//     (assert_all_shards_complete) runs on a FAST PR only when
//     shard_layout_relevant.
//
// The checks below run the REAL `changes` filter step under bash with a stub
// gh (as guardinputs_test.go does) and evaluate the REAL step conditions. The
// gates' inputs are derived from the scripts that define them, not copied:
// the fixture packages from check-closures.sh's self-test rows, the scripts
// it sources or execs, and the sharded packages from sharded_legs in
// scripts/ci-test-legs.sh. A new fixture package or a new sharded package
// that the ci.yml regex does not cover fails TestPathGateOpensForEveryInput.

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type pgStep struct {
	Name string `yaml:"name"`
	If   string `yaml:"if"`
	Run  string `yaml:"run"`
}

type pgWorkflow struct {
	Jobs map[string]struct {
		If    string   `yaml:"if"`
		Steps []pgStep `yaml:"steps"`
	} `yaml:"jobs"`
}

// pathGate is the parsed workflow plus the five step conditions under test.
type pathGate struct {
	filter                   string
	adrIf, legIf             string
	selfClosures, verifyClos string
	selfConf, verifyConf     string
	shards                   string
}

func loadPathGate(t *testing.T, root string) pathGate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf pgWorkflow
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatalf("ci.yml: %v", err)
	}
	step := func(job string, match func(run string) bool, what string) string {
		t.Helper()
		j, ok := wf.Jobs[job]
		if !ok {
			t.Fatalf("ci.yml has no job %s", job)
		}
		for _, s := range j.Steps {
			if match(strings.TrimSpace(s.Run)) {
				if strings.TrimSpace(s.If) == "" {
					return "true"
				}
				return s.If
			}
		}
		t.Fatalf("ci.yml job %s has no step running %s", job, what)
		return ""
	}
	exact := func(cmd string) func(string) bool { return func(r string) bool { return r == cmd } }
	jobIf := func(job string) string {
		if s := strings.TrimSpace(wf.Jobs[job].If); s != "" {
			return s
		}
		return "true"
	}
	var base workflow
	if err := yaml.Unmarshal(b, &base); err != nil {
		t.Fatalf("ci.yml: %v", err)
	}
	return pathGate{
		filter:       base.filterStep(t),
		adrIf:        jobIf("adr-numbers"),
		legIf:        jobIf("assert-leg-completeness"),
		selfClosures: step("adr-numbers", exact("./scripts/check-closures.sh --self-test"), "./scripts/check-closures.sh --self-test"),
		verifyClos:   step("adr-numbers", exact("./scripts/check-closures.sh"), "./scripts/check-closures.sh"),
		selfConf:     step("adr-numbers", exact("./scripts/check-adr-conformance.sh --self-test"), "./scripts/check-adr-conformance.sh --self-test"),
		verifyConf:   step("adr-numbers", exact("./scripts/check-adr-conformance.sh"), "./scripts/check-adr-conformance.sh"),
		shards: step("assert-leg-completeness", func(r string) bool {
			return strings.Contains(r, "assert_all_shards_complete")
		}, "assert_all_shards_complete"),
	}
}

// pgResult is what one run decides, per gated step and per job.
type pgResult struct {
	adr, selfClos, verifyClos, selfConf, verifyConf bool
	leg, shards                                     bool
}

func (g pathGate) eval(t *testing.T, ev string, out map[string]string) pgResult {
	t.Helper()
	r := resolver(ev, out)
	e := func(name, expr string) bool {
		t.Helper()
		v, err := evalIf(expr, r)
		if err != nil {
			t.Fatalf("%s if: %v", name, err)
		}
		return v
	}
	return pgResult{
		adr:        e("adr-numbers", g.adrIf),
		selfClos:   e("closure self-test", g.selfClosures),
		verifyClos: e("closure verify", g.verifyClos),
		selfConf:   e("conformance self-test", g.selfConf),
		verifyConf: e("conformance verify", g.verifyConf),
		leg:        e("assert-leg-completeness", g.legIf),
		shards:     e("shard partition", g.shards),
	}
}

// runFilter runs the changes/filter step once for event ev with the given
// changed-file list (what the stub gh prints for the pulls/files and compare
// calls) and returns its GITHUB_OUTPUT. For push, gh answers the merge-queue
// lookup with 0 runs (queue_verified=false).
func runFilter(t *testing.T, step, ev string, changed []string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	stepFile := filepath.Join(dir, "filter.sh")
	listFile := filepath.Join(dir, "changed.txt")
	outFile := filepath.Join(dir, "out")
	if err := os.WriteFile(stepFile, []byte(step), 0o600); err != nil {
		t.Fatal(err)
	}
	body := strings.Join(changed, "\n")
	if len(changed) > 0 {
		body += "\n"
	}
	if err := os.WriteFile(listFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ref := "refs/pull/1/merge"
	switch ev {
	case "merge_group":
		ref = "refs/heads/gh-readonly-queue/main/pr-1-2222222"
	case "push":
		ref = "refs/heads/main"
	}
	driver := `set -eo pipefail
gh() { if [ "$EVENT_NAME" = push ]; then echo 0; else cat "$LIST"; fi; }
. "$STEP"
`
	cmd := exec.Command("bash", "-c", driver)
	cmd.Env = append(os.Environ(),
		"STEP="+stepFile, "LIST="+listFile, "GITHUB_OUTPUT="+outFile,
		"EVENT_NAME="+ev, "REPO=keyorixhq/keyorix", "REF="+ref, "SHA=0000000", "PR_NUMBER=1",
		"MG_BASE_SHA=1111111", "MG_HEAD_SHA=2222222", "HAS_CI_FULL_LABEL=false", "BASE_REF=main", "GH_TOKEN=x")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("changes/filter step failed for %s %v: %v\n%s", ev, changed, err, out)
	}
	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	kv := map[string]string{}
	for l := range strings.SplitSeq(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			kv[k] = v
		}
	}
	return kv
}

// ---- the inputs, derived from the scripts ----------------------------------

var (
	scriptRefRE = regexp.MustCompile(`\$REPO_ROOT/(scripts/[A-Za-z0-9_.-]+\.sh)`)
	// a self-test row: <claim>\t./<pkg>\tTestCheckClosuresSelfTestFixture_...,
	// written with literal tabs or with \t inside $'...'
	fixtureRowRE = regexp.MustCompile(`(?:\t|\\t)\./([A-Za-z0-9_/]+)(?:\t|\\t)TestCheckClosuresSelfTestFixture_`)
)

// selfTestScripts: the self-test entry points plus every script they source
// or exec, transitively.
func selfTestScripts(t *testing.T, root string) []string {
	t.Helper()
	seen := map[string]bool{}
	queue := []string{"scripts/check-closures.sh", "scripts/check-adr-conformance.sh"}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		if seen[s] {
			continue
		}
		seen[s] = true
		src, err := os.ReadFile(filepath.Join(root, s)) // #nosec G304 -- tracked repo script
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range scriptRefRE.FindAllStringSubmatch(string(src), -1) {
			queue = append(queue, m[1])
		}
	}
	var out []string
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// fixturePackages: the package directories check-closures.sh's self-test runs
// its fixture tests in.
func fixturePackages(t *testing.T, root string) []string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, "scripts", "check-closures.sh"))
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, m := range fixtureRowRE.FindAllStringSubmatch(string(src), -1) {
		set[m[1]] = true
	}
	var out []string
	for d := range set {
		if fi, err := os.Stat(filepath.Join(root, d)); err != nil || !fi.IsDir() {
			t.Errorf("check-closures.sh self-test fixture package %s is not a directory", d)
			continue
		}
		out = append(out, d)
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("found no TestCheckClosuresSelfTestFixture_ row in scripts/check-closures.sh: the fixture pattern changed")
	}
	return out
}

// shardedPackages: the package directories sharded_legs splits over more
// than one leg, plus the weights file the split reads.
func shardedPackages(t *testing.T, root string) (dirs []string, weights string) {
	t.Helper()
	script := `set -euo pipefail
source scripts/ci-test-legs.sh
while IFS='|' read -r prefix fn shards preload; do
  if [ "$shards" -gt 1 ]; then echo "pkg $("$fn")"; fi
done < <(sharded_legs)
echo "weights $CI_TEST_WEIGHTS_FILE"
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CI_TEST_WEIGHTS_FILE=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sharded_legs: %v\n%s", err, out)
	}
	for l := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		k, v, _ := strings.Cut(l, " ")
		switch k {
		case "pkg":
			d, ok := strings.CutPrefix(v, "github.com/keyorixhq/keyorix/")
			if !ok {
				t.Fatalf("sharded package %s is outside the root module", v)
			}
			dirs = append(dirs, d)
		case "weights":
			weights = v
		}
	}
	if len(dirs) == 0 || weights == "" {
		t.Fatalf("sharded_legs listed no multi-shard package or no weights file:\n%s", out)
	}
	return dirs, weights
}

// testFilesIn: a new _test.go directly in dir plus the first and last
// tracked one there. The gate regexes key on the directory and the _test.go
// suffix only, so these stand for every test file of the directory.
func testFilesIn(tracked []string, dir string) []string {
	var in []string
	for _, f := range tracked {
		if path.Dir(f) == dir && strings.HasSuffix(f, "_test.go") {
			in = append(in, f)
		}
	}
	return append([]string{dir + "/zz_pathgate_new_test.go"}, firstLast(in)...)
}

func firstLast(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	s = slices.Sorted(slices.Values(s))
	if len(s) == 1 {
		return s
	}
	return []string{s[0], s[len(s)-1]}
}

func moduleFiles(tracked []string) []string {
	var out []string
	for _, f := range tracked {
		switch path.Base(f) {
		case "go.mod", "go.sum", "go.work", "go.work.sum":
			if !strings.Contains(f, "node_modules/") {
				out = append(out, f)
			}
		}
	}
	return out
}

// ---- the checks ------------------------------------------------------------

// TestPathGateOpensForEveryInput: on a FAST pull_request, a change to any one
// input of a gated step runs that step: the self-test scripts and everything
// they source or exec, every test file of a fixture package, internal/testutil,
// the module files, ci.yml, and an unknown file list; for the shard step, every
// test file of a multi-shard package, scripts/ci-test-legs.sh and the weights
// file.
func TestPathGateOpensForEveryInput(t *testing.T) {
	root := repoRoot(t)
	tracked := trackedFiles(t, root)
	g := loadPathGate(t, root)
	common := append([]string{".github/workflows/ci.yml"}, moduleFiles(tracked)...)

	selfIn := append(append([]string{}, common...), selfTestScripts(t, root)...)
	for _, d := range fixturePackages(t, root) {
		selfIn = append(selfIn, testFilesIn(tracked, d)...)
	}
	var testutil []string
	for _, f := range tracked {
		if strings.HasPrefix(f, "internal/testutil/") && !strings.HasSuffix(f, ".md") {
			testutil = append(testutil, f)
		}
	}
	selfIn = append(append(selfIn, "internal/testutil/zz_pathgate_new/helper.go"), firstLast(testutil)...)
	dirs, weights := shardedPackages(t, root)
	shardIn := append(append([]string{}, common...), "scripts/ci-test-legs.sh", weights)
	for _, d := range dirs {
		shardIn = append(shardIn, testFilesIn(tracked, d)...)
	}
	t.Logf("closure self-test inputs: %d paths; shard-partition inputs: %d paths (packages %s)", len(selfIn), len(shardIn), strings.Join(dirs, " "))

	// A job-level skip that predates the gate (docs_only, go_unaffected,
	// operator_only on the job's own `if:`) is logged, not failed: the gate
	// is the step condition, which must open for every input.
	check := func(what string, paths []string, step func(pgResult) bool, job func(pgResult) bool) {
		t.Helper()
		for _, p := range paths {
			out := runFilter(t, g.filter, "pull_request", []string{p})
			if out["full_profile"] != "false" {
				t.Fatalf("a plain pull_request must be FAST (full_profile=false), got %q", out["full_profile"])
			}
			r := g.eval(t, "pull_request", out)
			if !step(r) {
				t.Errorf("a FAST pull_request changing only %s skips the %s", p, what)
			}
			if !job(r) {
				var flags []string
				for _, f := range []string{"docs_only", "go_unaffected", "operator_only", "web_only"} {
					if out[f] == "true" {
						flags = append(flags, f)
					}
				}
				if len(flags) == 0 {
					t.Errorf("a FAST pull_request changing only %s skips the job of the %s with no docs/go/operator/web skip set", p, what)
					continue
				}
				t.Logf("pre-existing job-level skip: a FAST pull_request changing only %s skips the job of the %s (%s)", p, what, strings.Join(flags, ","))
			}
		}
	}
	check("closure and conformance self-tests", selfIn,
		func(r pgResult) bool { return r.selfClos && r.selfConf }, func(r pgResult) bool { return r.adr })
	check("shard-partition step", shardIn,
		func(r pgResult) bool { return r.shards }, func(r pgResult) bool { return r.leg })

	// An unknown file list (API error, the 300-file cap) runs everything.
	r := g.eval(t, "pull_request", runFilter(t, g.filter, "pull_request", nil))
	if !r.selfClos || !r.selfConf || !r.shards {
		t.Errorf("an unknown file list must run every gated step, got %+v", r)
	}
}

// TestPathGateSkipsUnrelatedPRs: the gates are not vacuous. A FAST PR that
// touches none of the inputs skips the self-tests and the shard step and still
// verifies both ledgers.
func TestPathGateSkipsUnrelatedPRs(t *testing.T) {
	root := repoRoot(t)
	tracked := trackedFiles(t, root)
	g := loadPathGate(t, root)
	isTracked := map[string]bool{}
	for _, f := range tracked {
		isTracked[f] = true
	}
	for _, p := range []string{
		"internal/storage/store/local_users.go",
		"internal/secretenv/describe_envname_test.go",
		"server/http/handlers/openapi.yaml",
		"deploy/helm/keyorix/values.yaml",
		"internal/core/guards/atomicity_guard_test.go",
	} {
		if !isTracked[p] {
			t.Fatalf("%s is not a tracked file any more: pick another unrelated path", p)
		}
		r := g.eval(t, "pull_request", runFilter(t, g.filter, "pull_request", []string{p}))
		if r.selfClos || r.selfConf || r.shards {
			t.Errorf("a FAST PR changing only %s runs a gated step (%+v): the gate opens for an unrelated path", p, r)
		}
		if !r.verifyClos || !r.verifyConf {
			t.Errorf("a FAST PR changing only %s verifies neither ledger (%+v)", p, r)
		}
	}
}

// TestPathGateIsInertOutsideTheFastProfile: with full_profile=true (merge_group,
// push, schedule, dispatch, ci:full, release/**) the two gate outputs change
// nothing, and every step runs exactly as before CI-PATHGATE-1: the self-tests
// unless docs_only, the verify and shard steps always. On every event and
// every combination, each ledger is verified by its self-test or its verify
// step. Also: the filter step reports full_profile=true on merge_group and
// push, and opens both gates on push.
func TestPathGateIsInertOutsideTheFastProfile(t *testing.T) {
	root := repoRoot(t)
	g := loadPathGate(t, root)
	vals := []string{"true", "false", ""}
	for _, ev := range []string{"pull_request", "merge_group", "push", "schedule", "workflow_dispatch"} {
		for _, full := range vals {
			for _, docs := range vals {
				for _, self := range vals {
					for _, shard := range vals {
						out := map[string]string{"full_profile": full, "docs_only": docs, "closure_selftest_relevant": self, "shard_layout_relevant": shard}
						r := g.eval(t, ev, out)
						if !r.selfClos && !r.verifyClos {
							t.Errorf("%s %v: the security-closure ledger is verified by neither step", ev, out)
						}
						if !r.selfConf && !r.verifyConf {
							t.Errorf("%s %v: the ADR conformance ledger is verified by neither step", ev, out)
						}
						if full != "true" {
							continue
						}
						if want := docs != "true"; r.selfClos != want || r.selfConf != want {
							t.Errorf("%s %v (FULL): self-tests ran=%v/%v, want %v (docs_only only, as before)", ev, out, r.selfClos, r.selfConf, want)
						}
						if !r.verifyClos || !r.verifyConf || !r.shards {
							t.Errorf("%s %v (FULL): a verify or the shard step is skipped (%+v)", ev, out, r)
						}
					}
				}
			}
		}
	}
	// merge_group computes the gates from its file list like a PR, but runs
	// FULL, so they are inert there (above); push has no file list and opens
	// them.
	out := runFilter(t, g.filter, "merge_group", []string{"docs/SELF_HOSTING.md"})
	if out["full_profile"] != "true" {
		t.Errorf("merge_group: want full_profile=true, got %q", out["full_profile"])
	}
	out = runFilter(t, g.filter, "push", nil)
	if out["full_profile"] != "true" || out["closure_selftest_relevant"] != "true" || out["shard_layout_relevant"] != "true" {
		t.Errorf("push: want full_profile, closure_selftest_relevant and shard_layout_relevant all true, got %q %q %q",
			out["full_profile"], out["closure_selftest_relevant"], out["shard_layout_relevant"])
	}
}

// TestPathGateOnRealPRs replays real merged PRs (their file lists, fetched
// from the pulls/N/files API the changes job reads, in testdata/pathgate) and
// pins what each FAST pull_request run would have run. Columns: closure
// self-test, closure verify, conformance self-test, conformance verify,
// assert-leg-completeness job, its shard step. On merge_group the same list
// must run everything that ran before (gates inert).
func TestPathGateOnRealPRs(t *testing.T) {
	root := repoRoot(t)
	g := loadPathGate(t, root)
	type want struct {
		class             string
		self, leg, shards bool
	}
	// self: both self-tests run (and both plain verify steps skip); else the
	// reverse. leg: the assert-leg-completeness job runs at all.
	cases := map[string]want{
		"3995": {"docs only", false, false, false},
		"3940": {"docs only", false, false, false},
		"4018": {"scripts/ci change (Go + guard-inputs ledger)", false, true, false},
		"3999": {"scripts only (no Go)", false, false, false},
		"4006": {"Makefile + other workflows + scripts", false, true, false},
		"3967": {"Go only, no test file (server/admin)", false, true, false},
		"3998": {"closure ledger fragments + internal/core and handlers tests", true, true, true},
		"4026": {"exemption ledger + internal/core test", true, true, true},
		"4019": {"Go + handlers tests + internal/testutil", true, true, true},
		"4017": {"ci.yml", true, true, true},
		"3994": {"ci.yml + scripts/ci", true, true, true},
		"4000": {"one internal/core _test.go", true, true, true},
		"3973": {"one server/faultops _test.go", false, true, true},
		"3958": {"internal/docsdrift _test.go only", false, true, false},
	}
	files, err := filepath.Glob(filepath.Join(root, "scripts", "ci", "guardinputs", "testdata", "pathgate", "pr-*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(cases) {
		t.Fatalf("testdata/pathgate has %d PR lists, the table has %d", len(files), len(cases))
	}
	var table []string
	for _, f := range files {
		pr := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "pr-"), ".txt")
		w, ok := cases[pr]
		if !ok {
			t.Errorf("testdata/pathgate/%s has no expected row", filepath.Base(f))
			continue
		}
		b, err := os.ReadFile(f) // #nosec G304 -- fixture under testdata
		if err != nil {
			t.Fatal(err)
		}
		changed := strings.Fields(string(b))
		r := g.eval(t, "pull_request", runFilter(t, g.filter, "pull_request", changed))
		got := want{w.class, r.selfClos, r.leg, r.leg && r.shards}
		if r.selfClos != r.selfConf || r.verifyClos == r.selfClos || r.verifyConf == r.selfConf || !r.adr {
			t.Errorf("#%s: adr-numbers steps inconsistent: %+v", pr, r)
		}
		if got != w {
			t.Errorf("#%s (%s): self-tests=%v assert-leg job=%v shard step=%v, want %v %v %v", pr, w.class, got.self, got.leg, got.shards, w.self, w.leg, w.shards)
		}
		mg := g.eval(t, "merge_group", runFilter(t, g.filter, "merge_group", changed))
		if (mg.leg && !mg.shards) || !mg.verifyClos || !mg.verifyConf {
			t.Errorf("#%s on merge_group: a step skipped although the gates are inert there (%+v)", pr, mg)
		}
		table = append(table, fmt.Sprintf("#%s\t%d files\t%s\tself-tests=%s verify=%s assert-leg=%s shards=%s",
			pr, len(changed), w.class, runSkip(r.selfClos), runSkip(r.verifyClos), runSkip(r.leg), runSkip(r.leg && r.shards)))
	}
	sort.Strings(table)
	t.Logf("FAST pull_request replay:\n%s", strings.Join(table, "\n"))
}

func runSkip(b bool) string {
	if b {
		return "run"
	}
	return "skip"
}
