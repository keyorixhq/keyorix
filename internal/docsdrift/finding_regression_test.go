package docsdrift

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// regressionTestLine matches a **Regression test:** metadata line in a finding doc.
// The whole field value (after the colon) is captured in group 1.
var regressionTestLine = regexp.MustCompile(`(?m)^\*\*Regression test:\*\*\s+(.+)$`)

// namedTestRef matches the structured form `FuncName` (`path/to/pkg`) within a
// Regression test field value.  Group 1 = function name, Group 2 = package path.
var namedTestRef = regexp.MustCompile("`([A-Z][A-Za-z0-9_]+)`\\s+\\(`([^`]+)`\\)")

// TestFindingRegressionTests_NamedTestsExist reads every docs/findings/*.md and,
// for any file that contains a **Regression test:** field, verifies the named
// function exists in the stated package directory.
//
// Grandfathering: finding docs that predate this requirement carry no
// **Regression test:** field and are silently skipped.  The check activates only
// for docs that explicitly include the field.
//
// What this check verifies:
//   - the stated package directory exists in the repo
//   - at least one *.go file in that directory declares
//     `func <FunctionName>(` as the first token on a line
//
// What this check does NOT verify:
//   - that the test actually exercises the specific bug (only that a function
//     with this name exists in the named package)
//   - that the test currently passes — that is CI's job via the normal test suite
//   - that the test was written to prove this bug specifically
//
// Red proof: change a **Regression test:** field to name a function that does not
// exist (e.g. TestNonExistentFunction123) and this test fails with a clear message.
func TestFindingRegressionTests_NamedTestsExist(t *testing.T) {
	root := repoRoot(t)
	g := guardrules.Rollout(t) // report-only on PR runs until promoted (docs/guard-rollout-contract.md)
	findingsDir := filepath.Join(root, "docs", "findings")

	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		t.Fatalf("read %s: %v", findingsDir, err)
	}

	var total, naExempt, checked int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		if e.Name() == "TEMPLATE.md" {
			continue
		}
		docPath := filepath.Join(findingsDir, e.Name())
		docBytes, err := os.ReadFile(docPath)
		if err != nil {
			t.Fatalf("read %s: %v", docPath, err)
		}
		total++

		matches := regressionTestLine.FindAllSubmatch(docBytes, -1)
		for _, m := range matches {
			value := strings.TrimSpace(string(m[1]))
			if strings.HasPrefix(value, "N/A") {
				naExempt++
				continue
			}
			nm := namedTestRef.FindStringSubmatch(value)
			if nm == nil {
				g.Errorf("%s: **Regression test:** value %q does not match "+
					"the expected format `TestName` (`path/to/package`) or N/A — reason",
					e.Name(), value)
				continue
			}
			funcName := nm[1]
			pkgPath := nm[2]
			checked++

			pkgDir := filepath.Join(root, filepath.FromSlash(pkgPath))
			if _, err := os.Stat(pkgDir); err != nil {
				g.Errorf("%s: **Regression test:** package directory %q not found: %v",
					e.Name(), pkgPath, err)
				continue
			}

			goFiles, err := filepath.Glob(filepath.Join(pkgDir, "*.go"))
			if err != nil || len(goFiles) == 0 {
				g.Errorf("%s: **Regression test:** no *.go files in %q",
					e.Name(), pkgPath)
				continue
			}

			funcPattern := regexp.MustCompile(`(?m)^func ` + regexp.QuoteMeta(funcName) + `\(`)
			found := false
			for _, gf := range goFiles {
				fileBytes, err := os.ReadFile(gf)
				if err != nil {
					continue
				}
				if funcPattern.Match(fileBytes) {
					found = true
					break
				}
			}
			if !found {
				g.Errorf("%s: **Regression test:** `%s` not found in package %q "+
					"(no `func %s(` as the start of a line in any *.go file there)",
					e.Name(), funcName, pkgPath, funcName)
			}
		}
	}
	t.Logf("docs/findings: %d docs total, %d with named regression tests (checked), %d N/A",
		total, checked, naExempt)
}
