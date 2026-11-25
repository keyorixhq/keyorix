package main

// CI-ADR-FASTPATH-1: changes.adr_text_only in .github/workflows/ci.yml. When
// every changed file is a numbered ADR (docs/adr-NNN-<slug>.md) or a
// changelog.d/ fragment, the adr-numbers job skips Set up Go, the two ledger
// Verify steps and the review-coverage pair (about 6 of its 7 minutes on an
// ADR-only merge-queue round). The checks below pin that:
//
//   - TestADRTextOnlySkipsExactlyTheGoSteps: on real ADR-only PR file lists the
//     REAL filter step sets adr_text_only, and against the same outputs with
//     adr_text_only=false the adr-numbers steps it skips are exactly those five.
//   - TestADRTextOnlyTurnsOffForAnyOtherPath: one more path of any other kind
//     (ledger fragments, Go and test files, scripts, .github, INVARIANTS,
//     coverage tables, module files, other docs, an unknown list) turns it off,
//     and every one of the five steps runs again with each ledger verified
//     exactly once.
//   - TestADRTextOnlySkipsNoLedgerTestThatReadsIt: no proving test of either
//     ledger (nor a test file it can call into, nor its package's TestMain/init)
//     is a guard test that reads a path the gate allowlists, per
//     scripts/ci/guard-inputs.tsv (kept complete by
//     TestGuardInputsCoverSkippedPaths). A ledger row that names such a test
//     turns this red, and the gate would have to narrow first.
//
// What this does not cover: a ledger test that reads an ADR through a path
// built at run time that the guard-inputs map does not record (the map's own
// stated blind spot), and production code reading ADR text. The nightly
// schedule run and every non-ADR PR still verify both ledgers in full.

import (
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v4"
)

// adrTextOnlyRE is the gate's allowlist, as ci.yml's filter step states it
// (changelog.d/README.md is excluded there separately).
var adrTextOnlyRE = regexp.MustCompile(`^(docs/adr-[0-9]{3}-[^/]+\.md|changelog\.d/[^/]+\.md)$`)

func adrTextOnlyPath(p string) bool {
	return adrTextOnlyRE.MatchString(p) && p != "changelog.d/README.md"
}

// The five adr-numbers steps the gate may skip, by step name.
var adrFastSkipped = []string{
	"Set up Go",
	"Verify every security closure claim names a passing test",
	"Verify every ADR conformance claim names a passing test",
	"Self-test the review-coverage guard (must be able to go red both ways)",
	"Verify every Go package has an adversarial-review coverage row",
}

type adrStep struct{ name, cond string }

func adrNumbersSteps(t *testing.T, root string) []adrStep {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Uses string `yaml:"uses"`
				If   string `yaml:"if"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatalf("ci.yml: %v", err)
	}
	var out []adrStep
	for _, s := range wf.Jobs["adr-numbers"].Steps {
		name := s.Name
		if name == "" {
			name = s.Uses
		}
		cond := strings.TrimSpace(s.If)
		if cond == "" {
			cond = "true"
		}
		out = append(out, adrStep{name, cond})
	}
	if len(out) < len(adrFastSkipped) {
		t.Fatalf("ci.yml job adr-numbers has %d steps", len(out))
	}
	return out
}

// skippedSet: the adr-numbers steps whose `if:` is false for these outputs.
func skippedSet(t *testing.T, steps []adrStep, ev string, out map[string]string) map[string]bool {
	t.Helper()
	res := map[string]bool{}
	for _, s := range steps {
		run, err := evalIf(s.cond, resolver(ev, out))
		if err != nil {
			t.Fatalf("adr-numbers step %q if: %v", s.name, err)
		}
		if !run {
			res[s.name] = true
		}
	}
	return res
}

func copyWith(m map[string]string, k, v string) map[string]string {
	c := maps.Clone(m)
	c[k] = v
	return c
}

// Real ADR-only PRs whose merge-queue rounds were measured for
// CI-ADR-FASTPATH-1, and #4714, the PR held as the live test.
var adrOnlyPRs = map[string][]string{
	"4713": {"docs/adr-122-read-only-site-replica.md"},
	"4714": {"docs/adr-122-read-only-site-replica.md"},
	"4715": {"changelog.d/docs-adr-125-certificate-issuing.md", "docs/adr-125-certificate-issuing.md"},
	"4710": {"changelog.d/docs-adr-112-amendment-8-ups-assisted-audit-sync.md", "docs/adr-112-secure-by-default-baseline.md"},
	"4707": {"changelog.d/docs-adr-123-ui-one-time-page-hints.md", "changelog.d/docs-adr-124-server-side-user-preferences.md",
		"docs/adr-123-ui-teaching-one-time-page-hints.md", "docs/adr-124-server-side-user-preferences.md"},
}

func TestADRTextOnlySkipsExactlyTheGoSteps(t *testing.T) {
	root := repoRoot(t)
	g := loadPathGate(t, root)
	steps := adrNumbersSteps(t, root)
	for _, s := range adrFastSkipped {
		if !slices.ContainsFunc(steps, func(a adrStep) bool { return a.name == s }) {
			t.Fatalf("ci.yml job adr-numbers has no step %q", s)
		}
	}
	want := strings.Join(slices.Sorted(slices.Values(adrFastSkipped)), "\n")
	for pr, files := range adrOnlyPRs {
		for _, ev := range events {
			out := runFilter(t, g.filter, ev, files)
			if out["adr_text_only"] != "true" || out["docs_only"] != "true" {
				t.Errorf("#%s on %s: adr_text_only=%q docs_only=%q, want both true", pr, ev, out["adr_text_only"], out["docs_only"])
				continue
			}
			r := g.eval(t, ev, out)
			if !r.adr {
				t.Errorf("#%s on %s: the adr-numbers job itself is skipped", pr, ev)
			}
			if r.selfClos || r.verifyClos || r.selfConf || r.verifyConf {
				t.Errorf("#%s on %s: a ledger step still runs (%+v)", pr, ev, r)
			}
			// The delta against the same run without the gate is exactly the
			// five Go-based steps: nothing else changes.
			on := skippedSet(t, steps, ev, out)
			off := skippedSet(t, steps, ev, copyWith(out, "adr_text_only", "false"))
			var delta []string
			for s := range on {
				if !off[s] {
					delta = append(delta, s)
				}
			}
			for s := range off {
				if !on[s] {
					t.Errorf("#%s on %s: step %q runs only WITH the gate", pr, ev, s)
				}
			}
			slices.Sort(delta)
			if got := strings.Join(delta, "\n"); got != want {
				t.Errorf("#%s on %s: the gate skips\n%s\nwant exactly\n%s", pr, ev, got, want)
			}
		}
	}
}

func TestADRTextOnlyTurnsOffForAnyOtherPath(t *testing.T) {
	root := repoRoot(t)
	g := loadPathGate(t, root)
	steps := adrNumbersSteps(t, root)
	adr := "docs/adr-122-read-only-site-replica.md"
	others := []string{
		"docs/security-closures.d/zz-new-claim-001.tsv",
		"docs/adr-conformance-enforced.tsv",
		"docs/adr-conformance-enforced.d/ADR-999-NEW.tsv",
		"docs/review-coverage.tsv",
		"docs/review-coverage.d/zz.tsv",
		"docs/INVARIANTS.md",
		"internal/core/INVARIANTS.md",
		"internal/core/INVARIANTS.d/INV-CORE-zz.md",
		"internal/core/zz_new_test.go",
		"internal/core/service.go",
		"cli/cmd/zz_test.go",
		"scripts/check-closures.sh",
		"scripts/ci/zz.sh",
		"scripts/ci/guardinputs/adrfast_test.go",
		".github/workflows/ci.yml",
		".github/workflows/codeql.yml",
		"go.mod",
		"go.sum",
		"server/entrypoint.sh",
		"changelog.d/README.md",
		"changelog.d/sub/nested.md",
		"docs/README.md",
		"docs/SELF_HOSTING.md",
		"docs/operator/zz.md",
		"docs/adr-draft-request-idempotency-for-create-operations.md",
		"docs/adr-12-short-number.md",
		"docs/adr-122-sub/nested.md",
		"README.md",
		"CHANGELOG.md",
	}
	for _, ev := range events {
		for _, p := range others {
			if adrTextOnlyPath(p) {
				t.Fatalf("%s is in the allowlist: not a turn-on case", p)
			}
			out := runFilter(t, g.filter, ev, []string{adr, p})
			if out["adr_text_only"] != "false" {
				t.Errorf("%s: an ADR plus %s gives adr_text_only=%q, want false", ev, p, out["adr_text_only"])
				continue
			}
			r := g.eval(t, ev, out)
			if r.selfClos == r.verifyClos || r.selfConf == r.verifyConf {
				t.Errorf("%s: an ADR plus %s: a ledger is not verified exactly once (%+v)", ev, p, r)
			}
			skipped := skippedSet(t, steps, ev, out)
			for _, s := range adrFastSkipped {
				if skipped[s] && !((s == adrFastSkipped[1] && r.selfClos) || (s == adrFastSkipped[2] && r.selfConf)) {
					t.Errorf("%s: an ADR plus %s still skips %q", ev, p, s)
				}
			}
		}
		// An unknown list (API error, the 300-file cap) is never ADR-only.
		if out := runFilter(t, g.filter, ev, nil); out["adr_text_only"] != "false" {
			t.Errorf("%s: an unknown file list gives adr_text_only=%q, want false", ev, out["adr_text_only"])
		}
	}
	// Every tracked numbered ADR and changelog.d fragment is in the allowlist
	// together, and a tracked docs/ or changelog.d file outside it turns the
	// gate off (first and last of each directory+extension class).
	tracked := trackedFiles(t, root)
	var allow []string
	first, last := map[string]string{}, map[string]string{}
	for _, f := range tracked {
		if adrTextOnlyPath(f) {
			allow = append(allow, f)
			continue
		}
		if !strings.HasPrefix(f, "docs/") && !strings.HasPrefix(f, "changelog.d/") {
			continue
		}
		k := path.Dir(f) + "\x00" + path.Ext(f)
		if v, ok := first[k]; !ok || f < v {
			first[k] = f
		}
		if v, ok := last[k]; !ok || f > v {
			last[k] = f
		}
	}
	if len(allow) < 50 {
		t.Fatalf("only %d tracked files match the allowlist: the ADR naming changed", len(allow))
	}
	for _, ev := range events {
		if out := runFilter(t, g.filter, ev, allow); out["adr_text_only"] != "true" {
			t.Errorf("%s: all %d tracked ADRs and changelog fragments together give adr_text_only=%q, want true", ev, len(allow), out["adr_text_only"])
		}
	}
	// The allowlist is a per-file test, so one path on its own is enough here
	// (simulate batches them; its pull_request results are the real filter).
	var sample []string
	for k, f := range first {
		sample = append(sample, f)
		if last[k] != f {
			sample = append(sample, last[k])
		}
	}
	slices.Sort(sample)
	sim := simulate(t, g.filter, sample)
	for _, p := range sample {
		if v := sim["pull_request\x00"+p]["adr_text_only"]; v != "false" {
			t.Errorf("a pull_request changing only the tracked %s gives adr_text_only=%q, want false", p, v)
		}
	}
	t.Logf("%d tracked ADRs and changelog fragments in the allowlist; %d other docs/ and changelog.d/ paths checked outside it", len(allow), len(sample))
	// push, schedule and dispatch have no file list: never ADR-only.
	if out := runFilter(t, g.filter, "push", nil); out["adr_text_only"] != "false" {
		t.Errorf("push: adr_text_only=%q, want false", out["adr_text_only"])
	}
}

// ---- no ledger proving test reads what the gate allowlists ------------------

type ledgerRow struct{ claim, dir, test string }

func loadLedgerRows(t *testing.T, root string) []ledgerRow {
	t.Helper()
	var files []string
	for _, g := range []string{"docs/security-closures.d/*.tsv", "docs/adr-conformance-enforced.d/*.tsv"} {
		m, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(g)))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	files = append(files, filepath.Join(root, "docs", "adr-conformance-enforced.tsv"))
	var rows []ledgerRow
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- tracked ledger file
		if err != nil {
			t.Fatal(err)
		}
		for l := range strings.SplitSeq(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "#") || strings.TrimSpace(l) == "" {
				continue
			}
			c := strings.Split(l, "\t")
			if len(c) < 3 || c[1] == "-" || c[2] == "-" {
				continue
			}
			rows = append(rows, ledgerRow{c[0], strings.TrimPrefix(path.Clean(c[1]), "./"), c[2]})
		}
	}
	return rows
}

var (
	declRE  = regexp.MustCompile(`(?m)^(?:func (?:\([^)]*\) )?|var |const |type )([A-Za-z_][A-Za-z0-9_]*)`)
	identRE = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
)

// ledgerADRReaders returns one problem per ledger row whose proving test can
// reach a guard test file that reads an allowlisted path. src holds the
// _test.go files by repo path; readers maps a test file to the input glob that
// makes it read one. "Can reach" over-approximates: the file declaring the
// test, its package's TestMain and init files, and every test file of the
// package that declares a name one of those mentions, transitively.
func ledgerADRReaders(rows []ledgerRow, src map[string][]byte, readers map[string]string) (problems []string, resolved int) {
	byDir := map[string][]string{}
	for f := range src {
		byDir[path.Dir(f)] = append(byDir[path.Dir(f)], f)
	}
	readerDir := map[string]bool{}
	for f := range readers {
		readerDir[path.Dir(f)] = true
	}
	// Identifiers are only needed where the walk below runs.
	decls, idents := map[string]map[string]bool{}, map[string]map[string]bool{}
	for f, b := range src {
		decls[f], idents[f] = map[string]bool{}, map[string]bool{}
		for _, m := range declRE.FindAllSubmatch(b, -1) {
			decls[f][string(m[1])] = true
		}
		if readerDir[path.Dir(f)] {
			for _, m := range identRE.FindAll(b, -1) {
				idents[f][string(m)] = true
			}
		}
	}
	for _, r := range rows {
		var roots []string
		found, anyReader := false, false
		for _, f := range byDir[r.dir] {
			if decls[f][r.test] {
				found = true
			}
			if decls[f][r.test] || decls[f]["TestMain"] || decls[f]["init"] {
				roots = append(roots, f)
			}
			if _, ok := readers[f]; ok {
				anyReader = true
			}
		}
		if !found {
			continue // not a root-module or cli test file in this tree (check-closures.sh reports a missing test)
		}
		resolved++
		if !anyReader {
			continue // no test file of this package reads an allowlisted path
		}
		seen := map[string]bool{}
		queue := roots
		for len(queue) > 0 {
			f := queue[0]
			queue = queue[1:]
			if seen[f] {
				continue
			}
			seen[f] = true
			if g, ok := readers[f]; ok {
				problems = append(problems, r.claim+" ("+r.dir+" "+r.test+") reaches "+f+", which reads "+g)
			}
			for _, o := range byDir[r.dir] {
				if seen[o] {
					continue
				}
				for d := range decls[o] {
					if idents[f][d] {
						queue = append(queue, o)
						break
					}
				}
			}
		}
	}
	slices.Sort(problems)
	return problems, resolved
}

func TestADRTextOnlySkipsNoLedgerTestThatReadsIt(t *testing.T) {
	root := repoRoot(t)
	tracked := trackedFiles(t, root)
	rows := loadLedgerRows(t, root)
	if len(rows) < 500 {
		t.Fatalf("only %d ledger rows read: the ledger layout changed", len(rows))
	}
	// What the gate lets through: every tracked numbered ADR and changelog.d
	// fragment, and a new one of each.
	allow := []string{"docs/adr-999-zz-new.md", "changelog.d/zz-new-fragment.md"}
	for _, f := range tracked {
		if adrTextOnlyPath(f) {
			allow = append(allow, f)
		}
	}
	mapRows, err := LoadMap(filepath.Join(root, DefaultMap))
	if err != nil {
		t.Fatal(err)
	}
	readers := map[string]string{}
	for _, mr := range mapRows {
		for _, p := range allow {
			// An input glob wins over a reviewed '!glob' (rows pair
			// "**/*.md" with "!**").
			if mr.Matches(p) {
				readers[mr.File] = p
				break
			}
		}
	}
	// Not vacuous: the docs secret guard reads every Markdown file.
	if _, ok := readers["cli/cmd/docs_no_literal_secrets_test.go"]; !ok {
		t.Fatalf("guard-inputs.tsv no longer maps cli/cmd/docs_no_literal_secrets_test.go to ADR text: re-derive the readers (%d found)", len(readers))
	}
	dirs := map[string]bool{}
	for _, r := range rows {
		dirs[r.dir] = true
	}
	src := map[string][]byte{}
	for _, f := range tracked {
		if strings.HasSuffix(f, "_test.go") && dirs[path.Dir(f)] {
			b, err := os.ReadFile(filepath.Join(root, f)) // #nosec G304 -- tracked repo file
			if err != nil {
				t.Fatal(err)
			}
			if defaultBuild(b) {
				src[f] = b
			}
		}
	}
	problems, resolved := ledgerADRReaders(rows, src, readers)
	t.Logf("%d ledger rows, %d resolved to a test file; %d guard test files read an allowlisted path", len(rows), resolved, len(readers))
	if resolved < len(rows)*9/10 {
		t.Errorf("only %d of %d ledger rows resolved to a declaring _test.go: the row or file layout changed", resolved, len(rows))
	}
	for _, p := range problems {
		t.Errorf("adr_text_only would skip a ledger test that reads ADR or changelog text: %s. Narrow the gate in ci.yml (or keep this ledger's Verify step on) before adding the row.", p)
	}
}

// The tripwire itself must be able to go red: a proving test that calls into a
// reader file, and a package TestMain in one, are reported; an unrelated
// reader in the same package is not.
func TestLedgerADRReadersCalibration(t *testing.T) {
	src := map[string][]byte{
		"p/claim_test.go":   []byte("package p\nfunc TestClaim(t *testing.T) { scanDocs(t) }\n"),
		"p/helper_test.go":  []byte("package p\nfunc scanDocs(t *testing.T) {}\n"),
		"p/other_test.go":   []byte("package p\nfunc TestOther(t *testing.T) {}\n"),
		"p/docs_test.go":    []byte("package p\nfunc TestDocs(t *testing.T) { walkAll() }\nfunc walkAll() {}\n"),
		"q/claim_test.go":   []byte("package q\nfunc TestQ(t *testing.T) {}\n"),
		"q/main_test.go":    []byte("package q\nfunc TestMain(m *testing.M) { loadADRs() }\n"),
		"q/adrload_test.go": []byte("package q\nfunc loadADRs() {}\n"),
	}
	readers := map[string]string{"p/helper_test.go": "docs/adr-001-x.md", "p/docs_test.go": "docs/adr-001-x.md", "q/adrload_test.go": "docs/adr-001-x.md"}
	got, n := ledgerADRReaders([]ledgerRow{{"C1", "p", "TestClaim"}, {"C2", "p", "TestOther"}, {"C3", "q", "TestQ"}, {"C4", "p", "TestGone"}}, src, readers)
	want := []string{
		"C1 (p TestClaim) reaches p/helper_test.go, which reads docs/adr-001-x.md",
		"C3 (q TestQ) reaches q/adrload_test.go, which reads docs/adr-001-x.md",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") || n != 3 {
		t.Errorf("calibration: got %d resolved and\n%s\nwant 3 and\n%s", n, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
