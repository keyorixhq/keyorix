package main

// The CI check of CI-GUARD-TRIGGERS-1: no guard test may read a path whose
// change alone would skip every job that runs it.
//
// How it decides, per test file and per path the file reads:
//
//  1. What a test file reads is estimated from its source (readsOf): the
//     repo paths its string literals name ("../../docs/X.md", "web/nginx.conf",
//     "docs"), narrowed by the extensions it mentions (".md", ".go", ...), plus
//     the whole tracked tree when it walks from the repository root. A file
//     whose only reading mechanism is go/parser or go/packages reads .go only.
//     This is an estimate: it over-reports (a skip-list literal such as "web"
//     looks like an input) and the map records those as reviewed non-inputs
//     ('!glob'). It under-reports a path built at run time from pieces none of
//     which names a tracked file or directory; such a path is added to the map
//     by hand.
//  2. For each path, the REAL `changes` step of .github/workflows/ci.yml (job
//     changes, step id filter) is extracted and run under bash with a stubbed
//     gh that returns that one path, for pull_request and merge_group. Its
//     GITHUB_OUTPUT is fed to the jobs' own `if:` conditions (evalIf). A path
//     is "seen by the Go jobs" when repo-guards would run for it: that job and
//     every other Go job share the docs_only/web_only/go_unaffected/
//     operator_only skips, and on a merge_group run it runs every source-
//     scanning guard (scripts/ci/run-guards.sh) while select-affected.py picks
//     the literal readers.
//  3. A path not seen by the Go jobs must match an input glob of the file's
//     row in guard-inputs.tsv (or a reviewed '!glob'), and the docs-guards job
//     must run for that event.
//
// Paths are simulated once per (top two directories, extension) class, with
// root files and ci.yml simulated by name; the first and last path of each
// class are both simulated and must classify alike, so a rule keyed on a file
// name inside a class shows up as a test failure, not as a wrong answer.

import (
	"bytes"
	"fmt"
	"go/build/constraint"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

var events = []string{"pull_request", "merge_group"}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".github", "workflows", "ci.yml")); err != nil {
		t.Fatalf("repository root not found from %s: %v", root, err)
	}
	return root
}

func trackedFiles(t *testing.T, root string) []string {
	t.Helper()
	cmd := exec.Command("git", "-C", root, "ls-files", "-z")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	var files []string
	for f := range strings.SplitSeq(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	if len(files) < 100 {
		t.Fatalf("git ls-files returned %d files: not a real checkout", len(files))
	}
	return files
}

// ---- the workflow ----------------------------------------------------------

type workflow struct {
	Jobs map[string]struct {
		If    string `yaml:"if"`
		Steps []struct {
			ID  string `yaml:"id"`
			Run string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func loadWorkflow(t *testing.T, root string) workflow {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatalf("ci.yml: %v", err)
	}
	return wf
}

func (wf workflow) filterStep(t *testing.T) string {
	t.Helper()
	for _, s := range wf.Jobs["changes"].Steps {
		if s.ID == "filter" {
			return s.Run
		}
	}
	t.Fatal("ci.yml: job changes has no step with id: filter")
	return ""
}

func (wf workflow) jobIf(t *testing.T, job string) string {
	t.Helper()
	j, ok := wf.Jobs[job]
	if !ok {
		t.Fatalf("ci.yml has no job %s", job)
	}
	if strings.TrimSpace(j.If) == "" {
		return "true"
	}
	return j.If
}

// simulate runs the changes/filter step for each (event, path) and returns the
// GITHUB_OUTPUT key=value map of each, keyed by event+"\x00"+path.
func simulate(t *testing.T, step string, paths []string) map[string]map[string]string {
	t.Helper()
	dir := t.TempDir()
	stepFile := filepath.Join(dir, "filter.sh")
	if err := os.WriteFile(stepFile, []byte(step), 0o600); err != nil {
		t.Fatal(err)
	}
	// The stub gh prints the one changed path for both the pulls/files and
	// the compare call. Every other input the step reads comes through env,
	// as in ci.yml. GitHub runs `run:` scripts with bash -e -o pipefail.
	driver := `set -u
step=$1; out=$2
gh() { printf '%s\n' "$FAKE_CHANGED"; }
while IFS="$(printf '\t')" read -r idx ev f; do
  (
    set -eo pipefail
    export EVENT_NAME="$ev" REPO=keyorixhq/keyorix REF=refs/pull/1/merge SHA=0000000 PR_NUMBER=1
    export MG_BASE_SHA=1111111 MG_HEAD_SHA=2222222 HAS_CI_FULL_LABEL=false BASE_REF=main GH_TOKEN=x
    FAKE_CHANGED="$f"
    export GITHUB_OUTPUT="$out/$idx.out"
    : > "$GITHUB_OUTPUT"
    . "$step"
  ) > "$out/$idx.log" 2>&1
  echo "$?" > "$out/$idx.rc"
done
`
	driverFile := filepath.Join(dir, "driver.sh")
	if err := os.WriteFile(driverFile, []byte(driver), 0o600); err != nil {
		t.Fatal(err)
	}
	type job struct{ idx, ev, p string }
	var jobs []job
	for _, ev := range events {
		for _, p := range paths {
			jobs = append(jobs, job{fmt.Sprint(len(jobs)), ev, p})
		}
	}
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := range workers {
		var in bytes.Buffer
		for i := w; i < len(jobs); i += workers {
			fmt.Fprintf(&in, "%s\t%s\t%s\n", jobs[i].idx, jobs[i].ev, jobs[i].p)
		}
		wg.Go(func() {
			cmd := exec.Command("bash", driverFile, stepFile, dir)
			cmd.Stdin = &in
			if out, err := cmd.CombinedOutput(); err != nil {
				errs <- fmt.Errorf("driver: %v\n%s", err, out)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	res := map[string]map[string]string{}
	for _, j := range jobs {
		rc, _ := os.ReadFile(filepath.Join(dir, j.idx+".rc"))
		if strings.TrimSpace(string(rc)) != "0" {
			log, _ := os.ReadFile(filepath.Join(dir, j.idx+".log"))
			t.Fatalf("changes/filter step failed (rc=%q) for %s %s:\n%s", strings.TrimSpace(string(rc)), j.ev, j.p, log)
		}
		b, err := os.ReadFile(filepath.Join(dir, j.idx+".out"))
		if err != nil {
			t.Fatal(err)
		}
		kv := map[string]string{}
		for l := range strings.SplitSeq(string(b), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				kv[k] = v
			}
		}
		res[j.ev+"\x00"+j.p] = kv
	}
	return res
}

// resolver models the contexts ci.yml's job conditions read. select's mode is
// what the select job reports: full on pull_request, selected on merge_group
// (the selection path; a full-mode queue run tests at least as much).
func resolver(ev string, outputs map[string]string) func(string) (string, error) {
	return func(p string) (string, error) {
		switch {
		case p == "github.event_name":
			return ev, nil
		case strings.HasPrefix(p, "needs.changes.outputs."):
			return outputs[strings.TrimPrefix(p, "needs.changes.outputs.")], nil
		case p == "needs.select.outputs.mode":
			if ev == "merge_group" {
				return "selected", nil
			}
			return "full", nil
		case strings.HasPrefix(p, "needs.") && strings.HasSuffix(p, ".result"):
			return "success", nil
		}
		return "", fmt.Errorf("context %s is not modelled by guardinputs_test.go", p)
	}
}

// classKey is the simulation class of a path: see the file comment.
func classKey(p string) string {
	if !strings.Contains(p, "/") || p == ".github/workflows/ci.yml" {
		return p
	}
	segs := strings.Split(path.Dir(p), "/")
	if len(segs) > 2 {
		segs = segs[:2]
	}
	return strings.Join(segs, "/") + "\x00" + path.Ext(p)
}

// coverage holds, per path class and event, whether the Go jobs see a change
// to that class, and whether docs-guards runs at all per event.
type coverage struct {
	goJobs     map[string]map[string]bool // class -> event -> repo-guards runs
	flags      map[string]map[string]string
	docsGuards map[string]bool
}

func computeCoverage(t *testing.T, wf workflow, paths []string) coverage {
	t.Helper()
	first, last := map[string]string{}, map[string]string{}
	for _, p := range paths {
		k := classKey(p)
		if f, ok := first[k]; !ok || p < f {
			first[k] = p
		}
		if l, ok := last[k]; !ok || p > l {
			last[k] = p
		}
	}
	var sim []string
	for k := range first {
		sim = append(sim, first[k])
		if last[k] != first[k] {
			sim = append(sim, last[k])
		}
	}
	sort.Strings(sim)
	out := simulate(t, wf.filterStep(t), sim)
	repoGuardsIf := wf.jobIf(t, "repo-guards")
	docsGuardsIf := wf.jobIf(t, "docs-guards")
	cov := coverage{goJobs: map[string]map[string]bool{}, flags: map[string]map[string]string{}, docsGuards: map[string]bool{}}
	for _, ev := range events {
		for k := range first {
			var got [2]bool
			for i, p := range []string{first[k], last[k]} {
				o := out[ev+"\x00"+p]
				run, err := evalIf(repoGuardsIf, resolver(ev, o))
				if err != nil {
					t.Fatalf("repo-guards if: %v", err)
				}
				got[i] = run
				if cov.flags[k] == nil {
					cov.flags[k] = map[string]string{}
				}
				var set []string
				for _, f := range []string{"docs_only", "web_only", "go_unaffected", "operator_only"} {
					if o[f] == "true" {
						set = append(set, f)
					}
				}
				cov.flags[k][ev] = strings.Join(set, ",")
				dg, err := evalIf(docsGuardsIf, resolver(ev, o))
				if err != nil {
					t.Fatalf("docs-guards if: %v", err)
				}
				if prev, seen := cov.docsGuards[ev]; !seen || prev {
					cov.docsGuards[ev] = dg
				}
			}
			if got[0] != got[1] {
				t.Fatalf("ci.yml classifies %s and %s differently on %s: the changes step now keys a skip rule on something narrower than (top two directories, extension); refine classKey", first[k], last[k], ev)
			}
			if cov.goJobs[k] == nil {
				cov.goJobs[k] = map[string]bool{}
			}
			cov.goJobs[k][ev] = got[0]
		}
	}
	return cov
}

// ---- what a test file reads (estimate) -------------------------------------

var (
	literalRE  = regexp.MustCompile("\"((?:[^\"\\\\\\n]|\\\\.)*)\"|`([^`]*)`")
	readRE     = regexp.MustCompile(`os\.ReadFile|os\.Open|ReadDir\(|WalkDir\(|filepath\.Walk\(|filepath\.Glob|fs\.Glob|ls-files`)
	goOnlyRE   = regexp.MustCompile(`parser\.Parse|packages\.Load`)
	walkRE     = regexp.MustCompile(`WalkDir\(|filepath\.Walk\(`)
	rootishRE  = regexp.MustCompile(`repoRoot|findRepoRoot|moduleRoot|rootDir|RepoRoot|gitRoot|projectRoot`)
	extLitRE   = regexp.MustCompile(`^\.(go|md|sh|ya?ml|tsv|txt|json|proto|sql|tsx?|py|conf|toml|tpl|j2|html)$`)
	buildTagRE = regexp.MustCompile(`(?m)^//go:build (.+)$`)
	// a file-name literal such as "_test.go" or "init-secrets.sh" names its extension
	extSuffixRE = regexp.MustCompile(`^[A-Za-z0-9_.-]*(\.(?:go|md|sh|ya?ml|tsv|txt|json|proto|sql|tsx?|py|conf|toml|tpl|html))$`)
	// the separator between two string literals that are arguments of one call
	argSepRE = regexp.MustCompile(`^\s*,\s*$`)
)

// literalRuns returns the string literals of src grouped into runs: literals
// passed as consecutive arguments (filepath.Join(root, "scripts", "selfhost",
// "init-secrets.sh")) form one run, every other literal a run of its own.
func literalRuns(src []byte) [][]string {
	var out [][]string
	var run []string
	prevEnd := -1
	flush := func() {
		if len(run) > 0 {
			out = append(out, run)
		}
		run = nil
	}
	for _, m := range literalRE.FindAllSubmatchIndex(src, -1) {
		lit := ""
		if m[2] >= 0 {
			lit = string(src[m[2]:m[3]])
		} else {
			lit = string(src[m[4]:m[5]])
		}
		if prevEnd < 0 || !argSepRE.Match(src[prevEnd:m[0]]) {
			flush()
		}
		run = append(run, lit)
		prevEnd = m[1]
	}
	flush()
	return out
}

type reader struct {
	file  string
	tests []string
	reads map[string]string // path -> why (the literal, or "walks the repo root")
}

// defaultBuild reports whether a file is compiled by a plain `go test` on the
// linux/amd64 CI runner (e2e/integration-tagged files are not guard tests).
func defaultBuild(src []byte) bool {
	m := buildTagRE.FindSubmatch(src)
	if m == nil {
		return true
	}
	expr, err := constraint.Parse("//go:build " + string(m[1]))
	if err != nil {
		return true
	}
	return expr.Eval(func(tag string) bool {
		return tag == "linux" || tag == "unix" || tag == "amd64" || tag == "gc" || strings.HasPrefix(tag, "go1.")
	})
}

// index is the tracked tree: files, the directories holding them, and the
// top-level entries (what a bare "docs" or "web" literal can name).
type index struct {
	files  []string
	isFile map[string]bool
	isDir  map[string]bool
	top    map[string]bool
}

func newIndex(tracked []string) *index {
	ix := &index{files: tracked, isFile: map[string]bool{}, isDir: map[string]bool{}, top: map[string]bool{}}
	for _, f := range tracked {
		ix.isFile[f] = true
		ix.top[strings.SplitN(f, "/", 2)[0]] = true
		for d := path.Dir(f); d != "."; d = path.Dir(d) {
			ix.isDir[d] = true
		}
	}
	return ix
}

func readsOf(ix *index, file string, src []byte) *reader {
	if !defaultBuild(src) {
		return nil
	}
	tests := TestFuncs(src)
	if len(tests) == 0 {
		return nil
	}
	fileRead := readRE.Match(src)
	if !fileRead && !goOnlyRE.Match(src) {
		return nil
	}
	dir := path.Dir(file)
	exts := map[string]bool{}
	lits := map[string]bool{}
	names := map[string]bool{}
	rootLit := false
	// resolve maps a literal to a repo path ("" when it names none).
	resolve := func(lit string) string {
		if lit == "" || len(lit) > 200 || strings.ContainsAny(lit, " \n\t%") {
			return ""
		}
		switch {
		case lit == ".." || strings.HasPrefix(lit, "../"):
			p := path.Clean(path.Join(dir, lit))
			if p == "." {
				rootLit = true
				return ""
			}
			if strings.HasPrefix(p, "..") {
				return ""
			}
			return p
		case ix.top[strings.SplitN(lit, "/", 2)[0]]:
			return path.Clean(lit)
		}
		return ""
	}
	for _, run := range literalRuns(src) {
		for _, lit := range run {
			if extLitRE.MatchString(lit) {
				exts[lit] = true
			} else if m := extSuffixRE.FindStringSubmatch(lit); m != nil {
				exts[m[1]] = true
			}
			if !strings.Contains(lit, "/") {
				names[lit] = true
			}
		}
		// A run that joins into a tracked path is that path; otherwise each
		// literal counts on its own ([]string{"docs", "scripts"} is two dirs).
		if len(run) > 1 {
			if p := resolve(path.Join(run...)); p != "" && (ix.isFile[p] || ix.isDir[p]) {
				lits[p] = true
				continue
			}
		}
		for _, lit := range run {
			if p := resolve(lit); p != "" {
				lits[p] = true
			}
		}
	}
	if !fileRead {
		exts = map[string]bool{".go": true}
	}
	r := &reader{file: file, tests: tests, reads: map[string]string{}}
	extOK := func(f string) bool { return len(exts) == 0 || exts[path.Ext(f)] }
	for l := range lits {
		for _, f := range ix.files {
			switch {
			case f == l:
				r.reads[f] = fmt.Sprintf("literal %q", l)
			case strings.HasPrefix(f, l+"/") && extOK(f):
				r.reads[f] = fmt.Sprintf("literal %q", l)
			}
		}
	}
	if walkRE.Match(src) && (rootishRE.Match(src) || rootLit) {
		for _, f := range ix.files {
			if _, done := r.reads[f]; done {
				continue
			}
			if extOK(f) || (len(exts) > 0 && names[path.Base(f)]) {
				r.reads[f] = "walks the repository root"
			}
		}
	}
	if len(r.reads) == 0 {
		return nil
	}
	return r
}

func readers(t *testing.T, root string, tracked []string) []*reader {
	t.Helper()
	var out []*reader
	ix := newIndex(tracked)
	for _, f := range tracked {
		if !strings.HasSuffix(f, "_test.go") || strings.Contains(f, "node_modules/") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, f)) // #nosec G304 -- tracked repo file
		if err != nil {
			t.Fatal(err)
		}
		if r := readsOf(ix, f, src); r != nil {
			out = append(out, r)
		}
	}
	return out
}

func notRead(r Row, p string) bool {
	for _, g := range r.NotRead {
		if MatchGlob(g, p) {
			return true
		}
	}
	return false
}

// ---- the checks ------------------------------------------------------------

// TestGuardInputsCoverSkippedPaths is the CI check: every path a guard test
// reads whose change alone skips the Go jobs is mapped to that guard in
// guard-inputs.tsv, and docs-guards runs for it on pull_request and
// merge_group. See the file comment for how "reads" and "skips" are decided.
func TestGuardInputsCoverSkippedPaths(t *testing.T) {
	root := repoRoot(t)
	tracked := trackedFiles(t, root)
	rows, err := LoadMap(filepath.Join(root, DefaultMap))
	if err != nil {
		t.Fatal(err)
	}
	byFile := map[string]Row{}
	for _, r := range rows {
		byFile[r.File] = r
	}
	rs := readers(t, root, tracked)
	var all []string
	seen := map[string]bool{}
	for _, r := range rs {
		for p := range r.reads {
			if !seen[p] {
				seen[p] = true
				all = append(all, p)
			}
		}
	}
	cov := computeCoverage(t, loadWorkflow(t, root), all)
	for _, ev := range events {
		if !cov.docsGuards[ev] {
			t.Errorf("ci.yml: docs-guards does not run on every %s change; it must, or the guards below lose their only runner", ev)
		}
	}
	var missing int
	for _, r := range rs {
		row, mapped := byFile[r.file]
		var bad, badPaths []string
		for p, why := range r.reads {
			k := classKey(p)
			for _, ev := range events {
				if cov.goJobs[k][ev] {
					continue
				}
				if mapped && (row.Matches(p) || notRead(row, p)) {
					continue
				}
				bad = append(bad, fmt.Sprintf("%s (%s; on %s the Go jobs skip: %s)", p, why, ev, cov.flags[k][ev]))
				badPaths = append(badPaths, p+"\x00"+why)
				break
			}
		}
		if len(bad) == 0 {
			continue
		}
		missing++
		sort.Strings(bad)
		more := ""
		if len(bad) > 5 {
			more = fmt.Sprintf("\n      ... and %d more", len(bad)-5)
			bad = bad[:5]
		}
		t.Errorf("%s (%s) reads paths whose change alone runs none of its tests:\n      %s%s\n    add or extend its row in %s: an input glob if it reads them, a !glob if it does not. Covering globs: %s",
			r.file, strings.Join(r.tests, ","), strings.Join(bad, "\n      "), more, DefaultMap, strings.Join(suggestGlobs(badPaths), ","))
	}
	t.Logf("%d test files read %d distinct repo paths (simulated in %d classes); %d files unmapped", len(rs), len(all), len(cov.goJobs), missing)
}

// suggestGlobs turns uncovered "path\x00why" pairs into globs for the failure
// message, a starting point to narrow by hand: the literal's own path (a file
// exactly, a directory as dir/**/*ext) for a literal read, and **/*ext (or
// top/**/*ext when only one top-level directory is involved) for a root walk.
func suggestGlobs(pairs []string) []string {
	set := map[string]bool{}
	walkTops := map[string]map[string]bool{} // ext -> top dirs
	for _, pw := range pairs {
		p, why, _ := strings.Cut(pw, "\x00")
		ext := path.Ext(p)
		if ext == "" {
			ext = path.Base(p)
		}
		if lit, ok := strings.CutPrefix(why, "literal "); ok {
			lit = strings.Trim(lit, `"`)
			switch {
			case lit == p:
				set[p] = true
			case strings.HasPrefix(ext, "."):
				set[lit+"/**/*"+ext] = true
			default:
				set[lit+"/**/"+ext] = true
			}
			continue
		}
		top, _, nested := strings.Cut(p, "/")
		if !nested {
			top = "."
		}
		if walkTops[ext] == nil {
			walkTops[ext] = map[string]bool{}
		}
		walkTops[ext][top] = true
	}
	for ext, tops := range walkTops {
		pat := "*" + ext
		if !strings.HasPrefix(ext, ".") {
			pat = ext
		}
		if len(tops) > 1 {
			set["**/"+pat] = true
			continue
		}
		for top := range tops {
			if top == "." {
				set[pat] = true
			} else {
				set[top+"/**/"+pat] = true
			}
		}
	}
	var out []string
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// TestGoSourcesNeverSkipTheGoJobs: a change to any .go file (outside the
// operator module, which has its own job) runs the Go jobs. scripts/ holds
// Go packages (scripts/ci, scripts/demo, scripts/metrics, ...) that the
// go_unaffected allowlist once claimed did not exist.
func TestGoSourcesNeverSkipTheGoJobs(t *testing.T) {
	root := repoRoot(t)
	var gofiles []string
	for _, f := range trackedFiles(t, root) {
		if strings.HasSuffix(f, ".go") && !strings.HasPrefix(f, "operator/") && !strings.Contains(f, "node_modules/") {
			gofiles = append(gofiles, f)
		}
	}
	cov := computeCoverage(t, loadWorkflow(t, root), gofiles)
	for k, byEv := range cov.goJobs {
		for _, ev := range events {
			if !byEv[ev] {
				t.Errorf("a %s change to %s skips the Go jobs (%s)", ev, strings.ReplaceAll(k, "\x00", "/*"), cov.flags[k][ev])
			}
		}
	}
}

// TestQuickStartChangeRunsTheDocsSecretsGuard is the #3616 regression: a
// change to QUICK_START.md alone skips the Go jobs and must still run
// TestDocsShowNoLiteralSecretOnCommandLine (cli/cmd) through docs-guards.
func TestQuickStartChangeRunsTheDocsSecretsGuard(t *testing.T) {
	root := repoRoot(t)
	wf := loadWorkflow(t, root)
	cov := computeCoverage(t, wf, []string{"QUICK_START.md"})
	for _, ev := range events {
		if cov.goJobs["QUICK_START.md"][ev] {
			t.Logf("%s: the Go jobs now run for a QUICK_START.md change", ev)
		}
		if !cov.docsGuards[ev] {
			t.Errorf("%s: docs-guards does not run for a QUICK_START.md change", ev)
		}
	}
	rows, err := LoadMap(filepath.Join(root, DefaultMap))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Plan(root, rows, []string{"QUICK_START.md"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range plan {
		if s.Module == "cli" && s.Package == "./cmd" && regexp.MustCompile(s.Regex).MatchString("TestDocsShowNoLiteralSecretOnCommandLine") {
			return
		}
	}
	t.Fatalf("a QUICK_START.md change does not select cli/cmd TestDocsShowNoLiteralSecretOnCommandLine; plan: %+v", plan)
}

// TestDocsGuardsJobRunsTheSelection: the docs-guards job runs the plan.
func TestDocsGuardsJobRunsTheSelection(t *testing.T) {
	wf := loadWorkflow(t, repoRoot(t))
	j, ok := wf.Jobs["docs-guards"]
	if !ok {
		t.Fatal("ci.yml has no docs-guards job")
	}
	for _, s := range j.Steps {
		if strings.Contains(s.Run, "scripts/ci/run-input-guards.sh") {
			return
		}
	}
	t.Fatal("docs-guards has no step running scripts/ci/run-input-guards.sh")
}

// TestGuardInputsMapIsLive: every row names a tracked test file with Test
// funcs, and every glob (input or !non-input) matches a tracked file, so a
// renamed input or a deleted guard cannot leave a row that selects nothing.
func TestGuardInputsMapIsLive(t *testing.T) {
	root := repoRoot(t)
	tracked := trackedFiles(t, root)
	isTracked := map[string]bool{}
	for _, f := range tracked {
		isTracked[f] = true
	}
	rows, err := LoadMap(filepath.Join(root, DefaultMap))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("guard-inputs.tsv has no rows")
	}
	for _, r := range rows {
		if !isTracked[r.File] || !strings.HasSuffix(r.File, "_test.go") {
			t.Errorf("line %d: %s is not a tracked _test.go file", r.Line, r.File)
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, r.File)) // #nosec G304 -- tracked repo file
		if err != nil {
			t.Fatal(err)
		}
		if len(TestFuncs(src)) == 0 {
			t.Errorf("line %d: %s declares no Test func", r.Line, r.File)
		}
		for _, g := range append(append([]string{}, r.Inputs...), r.NotRead...) {
			hit := false
			for _, f := range tracked {
				if MatchGlob(g, f) {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("line %d: glob %q of %s matches no tracked file", r.Line, g, r.File)
			}
		}
	}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"**/*.md", "README.md", true},
		{"**/*.md", "docs/a/b.md", true},
		{"**/*.md", "docs/a/b.mdx", false},
		{"docs/**", "docs/x.tsv", true},
		{"docs/**", "docsx/y", false},
		{"web/nginx*.conf", "web/nginx-hsts.conf", true},
		{"web/nginx*.conf", "web/sub/nginx.conf", false},
		{"QUICK_START.md", "QUICK_START.md", true},
		{"deploy/**/NOTES.txt", "deploy/helm/keyorix/templates/NOTES.txt", true},
		{"scripts/**/*.sh", "scripts/a.sh", true},
	}
	for _, c := range cases {
		if got := MatchGlob(c.pat, c.name); got != c.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", c.pat, c.name, got, c.want)
		}
	}
}
