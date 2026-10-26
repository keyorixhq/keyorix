package guardrules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// calendarExempt lists _test.go files that read the clock and use a
// date-only layout for a reason that is not a guard's pass/fail decision.
// Keep it short: every row is a file this guard no longer looks at.
var calendarExempt = map[string]string{
	"internal/storage/factory_schema_epoch_1674_test.go": "asserts the error names the date a newer epoch was just recorded; no ledger, no expiry",
}

// skipDirs are never scanned: VCS and tool state, dependencies, fixtures,
// and the throwaway exports sessions keep next to a clone.
var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "testdata": true, ".scratch": true, "tmp": true, ".gopath": true}

// TestGuardTestsDoNotReadTheCalendar enforces docs/guard-rollout-contract.md
// rule 1 over every _test.go file in the repository (all modules): a file that
// reads the wall clock (time.Now, time.Since, time.Until) AND parses or
// formats a date-only value ("2006-01-02" or time.DateOnly) is how every
// expiry time bomb so far was built (full-row-write and child-parent-liveness
// pending rows, knownOpenTolerances, NamedLockPendingExpires, ADR open
// decisions). Such a check goes red for every PR on one calendar day. Dated
// rows go through CheckExpiry instead, which the nightly job evaluates.
//
// What it does not see: a clock read hidden in a helper in another file, a
// date compared as a Unix number or with a layout other than date-only, and
// shell or workflow code (the CI exclusion-freshness check is moved to the
// nightly schedule by the workflow change, not by this test).
func TestGuardTestsDoNotReadTheCalendar(t *testing.T) {
	g := Rollout(t)
	root := srcpath.RepoRoot()
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (skipDirs[name] || strings.HasPrefix(name, ".redproof-")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if _, ok := calendarExempt[rel]; ok {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- walking the repository
		if err != nil {
			return err
		}
		files++
		for _, v := range calendarViolations(rel, src) {
			g.Errorf("%s\n\tDecide pass/fail without the calendar: validate the date's format and route the expiry through guardrules.CheckExpiry in a Test*NotExpired test (docs/guard-rollout-contract.md rule 1).", v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 1000 {
		g.Fatalf("scanned only %d _test.go files under %s; the walk stopped seeing the tree", files, root)
	}
	for rel := range calendarExempt {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			g.Errorf("calendarExempt lists %s, which does not exist: delete the row", rel)
		}
	}
}

// calendarViolations returns one message per wall-clock read in a file that
// also uses a date-only layout. It parses without type information, so it
// matches the time package by its import name.
func calendarViolations(rel string, src []byte) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{rel + ": does not parse: " + err.Error()}
	}
	timeName := importName(f, "time")
	if timeName == "" {
		return nil
	}
	var clocks []token.Pos
	dateLayout := false
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				if v, err := strconv.Unquote(x.Value); err == nil && v == DateLayout {
					dateLayout = true
				}
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == timeName && x.Sel.Name == "DateOnly" {
				dateLayout = true
			}
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == timeName && slices.Contains([]string{"Now", "Since", "Until"}, sel.Sel.Name) {
					clocks = append(clocks, x.Pos())
				}
			}
		}
		return true
	})
	if !dateLayout {
		return nil
	}
	out := make([]string, 0, len(clocks))
	for _, p := range clocks {
		out = append(out, fset.Position(p).String()+": reads the wall clock in a file that parses or formats YYYY-MM-DD dates")
	}
	return out
}

func importName(f *ast.File, path string) string {
	for _, im := range f.Imports {
		if p, _ := strconv.Unquote(im.Path.Value); p == path {
			if im.Name != nil {
				return im.Name.Name
			}
			return filepath.Base(path)
		}
	}
	return ""
}

// TestGuardRollout_RowsNameAReportingGuard: every docs/guard-rollout.d row is
// well formed and names a test in its package that reports through
// guardrules.Rollout; a row for anything else would be inert.
func TestGuardRollout_RowsNameAReportingGuard(t *testing.T) {
	g := Rollout(t)
	root := srcpath.RepoRoot()
	paths, err := filepath.Glob(filepath.Join(root, RolloutDir, "*.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p) // #nosec G304 -- glob of a fixed directory
		if err != nil {
			t.Fatal(err)
		}
		row, err := ParseRolloutRow(p, data)
		if err != nil {
			g.Error(err)
			continue
		}
		body := testFuncBody(t, filepath.Join(root, row.Package), row.Test)
		if body == "" {
			g.Errorf("%s: no func %s(t *testing.T) in %s", p, row.Test, row.Package)
		} else if !strings.Contains(body, "guardrules.Rollout(") && !strings.Contains(body, " Rollout(t)") {
			g.Errorf("%s: %s does not report through guardrules.Rollout(t), so the row changes nothing", p, row.Test)
		}
	}
}

// testFuncBody returns the source text of func name in dir's _test.go files.
func testFuncBody(t *testing.T, dir, name string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, p := range files {
		src, err := os.ReadFile(p) // #nosec G304 -- glob of a package directory
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == name && fd.Body != nil {
				return string(src[fset.Position(fd.Body.Pos()).Offset:fset.Position(fd.Body.End()).Offset])
			}
		}
	}
	return ""
}

var notExpiredName = regexp.MustCompile(`^Test\w*NotExpired$`)

// TestCheckExpiryCallersAreNamedNotExpired: the nightly job finds expiry checks
// by name (-run 'NotExpired$' in every package that calls CheckExpiry), so a
// check under any other name would never be evaluated against the calendar.
func TestCheckExpiryCallersAreNamedNotExpired(t *testing.T) {
	g := Rollout(t)
	root := srcpath.RepoRoot()
	callers := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".redproof-")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- walking the repository
		if err != nil || !strings.Contains(string(src), "CheckExpiry(") {
			return err
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		qual := importName(f, "github.com/keyorixhq/keyorix/internal/guardrules")
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok || !isCheckExpiry(ce.Fun, qual) {
					return true
				}
				callers++
				if !notExpiredName.MatchString(fd.Name.Name) {
					g.Errorf("%s: %s calls CheckExpiry but is not named Test*NotExpired, so the nightly job never runs it", fset.Position(ce.Pos()), fd.Name.Name)
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if callers < 5 {
		g.Fatalf("found only %d CheckExpiry call sites; the five converted expiry checks should all be here", callers)
	}
}

func isCheckExpiry(fun ast.Expr, qual string) bool {
	if sel, ok := fun.(*ast.SelectorExpr); ok && qual != "" {
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == qual && sel.Sel.Name == "CheckExpiry"
	}
	return false
}
