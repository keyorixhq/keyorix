package docsdrift

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// findingFieldRequiredFrom is the first filename date (YYYY-MM-DD) from which a
// FINDING doc must carry a **Regression test:** field. Older FINDING docs are
// grandfathered: they are checked when they carry the field and skipped (and
// counted in the log) when they do not. Compared lexically with the filename
// prefix, never with the clock (docs/guard-rollout-contract.md rule 1).
const findingFieldRequiredFrom = "2026-11-27"

// regressionTestLine matches a well-formed **Regression test:** metadata line.
// The whole field value (after the colon) is captured in group 1.
var regressionTestLine = regexp.MustCompile(`^\*\*Regression test:\*\*\s+(\S.*)$`)

// regressionTestNearMiss matches any line that looks like an attempt at the
// field (no bold, bold around the colon, plural, a list or quote marker in
// front). A line that matches this but not regressionTestLine is reported, so a
// misspelled field cannot pass as "no field".
var regressionTestNearMiss = regexp.MustCompile(`(?i)^[\s*_>#-]*regression[ _-]?tests?[\s*_]*:`)

// namedTestRef matches the structured form `FuncName` (`path/to/pkg`) within a
// Regression test field value. Group 1 = function name, Group 2 = package path.
var namedTestRef = regexp.MustCompile("`([A-Za-z_][A-Za-z0-9_]*)`\\s+\\(`([^`]+)`\\)")

// goTestName is a name `go test` runs: Test or Fuzz followed by nothing
// lower-case (the testing package's own rule), so a production function cannot
// be named as the regression test.
var goTestName = regexp.MustCompile(`^(Test|Fuzz)([^a-z][A-Za-z0-9_]*)?$`)

// naWithReason is the N/A form: N/A, a dash, and a non-empty reason.
var naWithReason = regexp.MustCompile(`^N/A\s*[—–-]+\s*\S`)

// findingDocDate is the YYYY-MM-DD filename prefix of a finding doc.
var findingDocDate = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})-`)

type findingRegressionStats struct {
	total, required, grandfathered, checked, naExempt int
}

// fieldRequired reports whether a doc named name must carry the field: every
// *FINDING* doc dated on or after findingFieldRequiredFrom, and every FINDING
// doc whose name has no date prefix (fail closed).
func fieldRequired(name string) bool {
	if !strings.Contains(name, "FINDING") {
		return false
	}
	m := findingDocDate.FindStringSubmatch(name)
	return m == nil || m[1] >= findingFieldRequiredFrom
}

// checkFindingRegressionDocs checks every *.md in findingsDir except TEMPLATE.md
// and returns one message per problem. Package paths are resolved against root.
func checkFindingRegressionDocs(root, findingsDir string) ([]string, findingRegressionStats, error) {
	var problems []string
	var st findingRegressionStats
	report := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		return nil, st, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") || e.Name() == "TEMPLATE.md" {
			continue
		}
		name := e.Name()
		docBytes, err := os.ReadFile(filepath.Join(findingsDir, name)) // #nosec G304 -- fixed docs directory
		if err != nil {
			return nil, st, err
		}
		st.total++

		var values []string
		for i, line := range strings.Split(string(docBytes), "\n") {
			line = strings.TrimRight(line, "\r")
			if m := regressionTestLine.FindStringSubmatch(line); m != nil {
				values = append(values, strings.TrimSpace(m[1]))
				continue
			}
			if regressionTestNearMiss.MatchString(line) {
				report("%s:%d: %q looks like a Regression test field but is not the exact form "+
					"**Regression test:** `TestName` (`path/to/package`) or **Regression test:** N/A — <reason>",
					name, i+1, line)
			}
		}

		required := fieldRequired(name)
		if required {
			st.required++
		}
		switch {
		case len(values) == 0 && required:
			report("%s: FINDING docs dated %s or later must carry exactly one **Regression test:** line "+
				"(see docs/findings/TEMPLATE.md)", name, findingFieldRequiredFrom)
			continue
		case len(values) == 0:
			st.grandfathered++
			continue
		case len(values) > 1:
			report("%s: %d **Regression test:** lines; a doc carries exactly one (name several tests in one line)",
				name, len(values))
		}

		for _, value := range values {
			if strings.HasPrefix(value, "N/A") {
				if !naWithReason.MatchString(value) {
					report("%s: **Regression test:** %q: N/A needs a reason (N/A — <reason>)", name, value)
					continue
				}
				st.naExempt++
				continue
			}
			refs := namedTestRef.FindAllStringSubmatch(value, -1)
			if len(refs) == 0 {
				report("%s: **Regression test:** value %q does not match "+
					"the expected format `TestName` (`path/to/package`) or N/A — reason", name, value)
				continue
			}
			for _, ref := range refs {
				st.checked++
				if msg := checkNamedTest(root, ref[1], ref[2]); msg != "" {
					report("%s: **Regression test:** %s", name, msg)
				}
			}
		}
	}
	return problems, st, nil
}

// checkNamedTest returns "" when package directory pkgPath (relative to root)
// declares func funcName(<x> *testing.T) for a Test name or (<x> *testing.F)
// for a Fuzz name, otherwise what is wrong.
func checkNamedTest(root, funcName, pkgPath string) string {
	m := goTestName.FindStringSubmatch(funcName)
	if m == nil {
		return fmt.Sprintf("`%s` is not a Go test or fuzz function name (Test… or Fuzz…)", funcName)
	}
	rel := filepath.FromSlash(pkgPath)
	if !filepath.IsLocal(rel) {
		return fmt.Sprintf("package path %q must be a directory inside the repository", pkgPath)
	}
	pkgDir := filepath.Join(root, rel)
	if fi, err := os.Stat(pkgDir); err != nil || !fi.IsDir() {
		return fmt.Sprintf("package directory %q not found", pkgPath)
	}
	goFiles, err := filepath.Glob(filepath.Join(pkgDir, "*.go"))
	if err != nil || len(goFiles) == 0 {
		return fmt.Sprintf("no *.go files in %q", pkgPath)
	}
	tb := "T"
	if m[1] == "Fuzz" {
		tb = "F"
	}
	funcPattern := regexp.MustCompile(`(?m)^func ` + regexp.QuoteMeta(funcName) + `\(\s*\w+\s+\*testing\.` + tb + `\s*\)`)
	for _, gf := range goFiles {
		fileBytes, err := os.ReadFile(gf) // #nosec G304 -- *.go under a repo-local package directory
		if err != nil {
			return fmt.Sprintf("read %s: %v", gf, err)
		}
		if funcPattern.Match(fileBytes) {
			return ""
		}
	}
	return fmt.Sprintf("`%s` not found in package %q (no `func %s(<x> *testing.%s)` at the start of a line in any *.go file there)",
		funcName, pkgPath, funcName, tb)
}

// TestFindingRegressionTests_NamedTestsExist reads every docs/findings/*.md and
// checks the **Regression test:** field.
//
// What this check verifies:
//   - every FINDING doc dated findingFieldRequiredFrom or later carries exactly
//     one field (older FINDING docs without it are grandfathered and counted)
//   - no line is a near-miss spelling of the field
//   - an N/A value gives a reason
//   - every `Name` (`pkg`) reference in a value names a Test… func taking
//     *testing.T or a Fuzz… func taking *testing.F, declared at the start of a
//     line in a *.go file of that repo-local package directory
//
// What this check does NOT verify:
//   - that the test actually exercises the specific bug (only that a test
//     function with this name exists in the named package)
//   - that the test currently passes — that is CI's job via the normal test suite
//   - that the test was written to prove this bug specifically
//   - non-FINDING docs (TRIAGE, NOTE, PLAN, DRAFT-ISSUE) that omit the field
//
// Red proof: TestFindingRegressionCheckCatchesPlantedErrors.
func TestFindingRegressionTests_NamedTestsExist(t *testing.T) {
	root := repoRoot(t)
	g := guardrules.Rollout(t) // report-only on PR runs until promoted (docs/guard-rollout-contract.md)
	problems, st, err := checkFindingRegressionDocs(root, filepath.Join(root, "docs", "findings"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		g.Errorf("%s", p)
	}
	t.Logf("docs/findings: %d docs, %d required to carry the field, %d grandfathered without it (skipped), %d named tests checked, %d N/A",
		st.total, st.required, st.grandfathered, st.checked, st.naExempt)
}

// TestFindingRegressionCheckCatchesPlantedErrors is the red proof: each planted
// doc must produce its problem, and the well-formed docs (named test, Fuzz
// target, two tests in one line, N/A with a reason, a grandfathered doc
// without the field, a non-FINDING doc) must produce none.
func TestFindingRegressionCheckCatchesPlantedErrors(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("pkg/a/a_test.go", "package a\n\nimport \"testing\"\n\n"+
		"func TestReal(t *testing.T) {}\nfunc FuzzReal(f *testing.F) {}\nfunc TestOther(t *testing.T) {}\n")
	write("pkg/a/a.go", "package a\n\nfunc Production() {}\nfunc TestLooksLikeATest() {}\n")

	field := func(v string) string { return "# F\n\n**Status:** Fixed\n**Regression test:** " + v + "\n" }
	good := map[string]string{
		"2026-12-01-FINDING-good.md":     field("`TestReal` (`pkg/a`)"),
		"2026-12-01-FINDING-fuzz.md":     field("`FuzzReal` (`pkg/a`) — fuzz target"),
		"2026-12-01-FINDING-two.md":      field("`TestReal` (`pkg/a`), `TestOther` (`pkg/a`)"),
		"2026-12-01-FINDING-na.md":       field("N/A — third-party containment, no Keyorix change"),
		"2026-09-01-FINDING-old.md":      "# Old\n\nNo field, predates the cutoff.\n",
		"2026-12-01-TRIAGE-not-a-bug.md": "# T\n\nNo field, not a FINDING doc.\n",
	}
	bad := map[string]string{
		"2026-12-01-FINDING-missing.md":   "# F\n\nNo field.\n",
		"FINDING-undated.md":              "# F\n\nNo date prefix, no field.\n",
		"2026-12-01-FINDING-nearmiss.md":  "# F\n\n**Regression test**: `TestReal` (`pkg/a`)\n",
		"2026-09-01-FINDING-nobold.md":    "# F\n\nRegression test: `TestReal` (`pkg/a`)\n",
		"2026-12-01-FINDING-duplicate.md": field("`TestReal` (`pkg/a`)") + "**Regression test:** `TestOther` (`pkg/a`)\n",
		"2026-12-01-FINDING-bare-na.md":   field("N/A"),
		"2026-12-01-FINDING-format.md":    field("TestReal in pkg/a"),
		"2026-12-01-FINDING-nosuch.md":    field("`TestNoSuchFunc123` (`pkg/a`)"),
		"2026-12-01-FINDING-second.md":    field("`TestReal` (`pkg/a`), `TestNoSuchFunc123` (`pkg/a`)"),
		"2026-12-01-FINDING-prod.md":      field("`Production` (`pkg/a`)"),
		"2026-12-01-FINDING-notest.md":    field("`TestLooksLikeATest` (`pkg/a`)"),
		"2026-12-01-FINDING-escape.md":    field("`TestReal` (`../outside`)"),
		"2026-12-01-FINDING-nopkg.md":     field("`TestReal` (`pkg/none`)"),
	}

	run := func(docs map[string]string) []string {
		t.Helper()
		dir := filepath.Join(root, "docs", "findings")
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		for name, body := range docs {
			write("docs/findings/"+name, body)
		}
		write("docs/findings/TEMPLATE.md", "**Regression test**: placeholder, never checked\n")
		problems, _, err := checkFindingRegressionDocs(root, dir)
		if err != nil {
			t.Fatal(err)
		}
		return problems
	}

	if got := run(good); len(got) != 0 {
		t.Fatalf("well-formed docs reported: %q", got)
	}
	for name, body := range bad {
		got := run(map[string]string{name: body})
		if len(got) == 0 {
			t.Errorf("%s: planted problem not reported", name)
			continue
		}
		for _, p := range got {
			if !strings.HasPrefix(p, name+":") {
				t.Errorf("%s: problem does not name the doc: %q", name, p)
			}
		}
	}
}
