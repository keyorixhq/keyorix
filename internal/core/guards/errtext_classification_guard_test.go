// errtext_classification_guard_test.go -- ERRSTRING-CLASS-1 item 4.
//
// The class: a handler or mapper that decides a status class (404, 403, 400, Internal) by
// looking for words in err.Error(). The text is translated, carries whatever prefix the layer
// above added, and for an untyped storage or driver error it is not under the code's control at
// all: "permission denied for table groups" (a database-role fault) answered PermissionDenied,
// "invalid input syntax ..." answered InvalidArgument, and a caller-controlled name or ref that
// an error echoes back could pick the class (groupError, mapSecretACLError, isSafeConnectError).
// The fix is always the same: wrap or return a sentinel where the refusal is made and classify
// with errors.Is / errors.As.
//
// What it recognises (the enumeration, stated so a reviewer can check it):
//   - a call strings.Contains, ContainsAny, HasPrefix, HasSuffix, Index, EqualFold or
//     ContainsFunc (the package identifier must be `strings`), in a non-test .go file under
//     internal/core (the core family) or server/ (the REST, gRPC and wiring layers);
//   - with an argument that is error text: any expression containing a call X.Error() with no
//     arguments (so strings.Contains(err.Error(), ...), strings.Contains(strings.ToLower(err.Error()),
//     ...) and a nested form all count), OR a local identifier the same function assigned from such
//     an expression one or more steps earlier (`msg := strings.ToLower(err.Error())`, then
//     strings.Contains(msg, ...)).
//
// What it does NOT catch:
//   - an exact comparison (`err.Error() == "x"`, a switch on err.Error()), regexp or bytes
//     matching, a text probe written with strings.Split/Fields or a hand-written loop;
//   - error text carried through a struct field, a returned value or a function parameter (the
//     taint is local to one function and one assignment hop at a time);
//   - a package-level `var f = func(...)` literal (only FuncDecl bodies, including their nested
//     literals, are scanned);
//   - code outside internal/core and server/: internal/storage, internal/cli, cli/, operator/;
//   - whether the text is about a STORAGE error or about a message the same function built
//     locally. It cannot tell the two apart; the second kind goes in the exception file with
//     that reason.
// Wrong-reason exemptions are checked: an exception that no longer matches any hit fails.
//
// The exceptions are one file per function in testdata/errtext_classification_exceptions.d/,
// each holding one `path:Func<TAB>reason` row for a function that still reads error text, with
// a one-line reason (naming and families: the README.md there). A new row needs a reason a
// reviewer can check; "unmigrated" is only valid for the families named in the README.
//
// Report-only on its first day (docs/guard-rollout.d/TestNoErrorTextClassification.tsv,
// docs/guard-rollout-contract.md).

package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

var errTextStringsFuncs = map[string]bool{
	"Contains": true, "ContainsAny": true, "HasPrefix": true, "HasSuffix": true,
	"Index": true, "EqualFold": true, "ContainsFunc": true,
}

type errTextHit struct {
	File, Func, Call string
	Line             int
}

func (h errTextHit) key() string { return h.File + ":" + h.Func }

// callsErrorMethod reports whether e contains a call X.Error() with no arguments.
func callsErrorMethod(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" {
			found = true
		}
		return !found
	})
	return found
}

// scanErrTextClassification returns every recognised strings.* call on error text in f.
func scanErrTextClassification(fset *token.FileSet, f *ast.File, file string) []errTextHit {
	var out []errTextHit
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		tainted := map[string]bool{}
		// isText: e calls X.Error(), or mentions a local the function already assigned from
		// error text (so strings.ToLower(msg) of a tainted msg is tainted too).
		isText := func(e ast.Expr) bool {
			if callsErrorMethod(e) {
				return true
			}
			found := false
			ast.Inspect(e, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					// Only the operand can be a local; the selected name never is.
					ast.Inspect(sel.X, func(m ast.Node) bool {
						if id, ok := m.(*ast.Ident); ok && tainted[id.Name] {
							found = true
						}
						return !found
					})
					return false
				}
				if id, ok := n.(*ast.Ident); ok && tainted[id.Name] {
					found = true
				}
				return !found
			})
			return found
		}
		// ast.Inspect walks in source order, so an assignment is seen before the later use.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				if len(s.Lhs) == len(s.Rhs) {
					for i, l := range s.Lhs {
						if id, ok := l.(*ast.Ident); ok && isText(s.Rhs[i]) {
							tainted[id.Name] = true
						}
					}
				}
			case *ast.ValueSpec:
				if len(s.Names) == len(s.Values) {
					for i, id := range s.Names {
						if isText(s.Values[i]) {
							tainted[id.Name] = true
						}
					}
				}
			case *ast.CallExpr:
				sel, ok := s.Fun.(*ast.SelectorExpr)
				if !ok || !errTextStringsFuncs[sel.Sel.Name] {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "strings" {
					return true
				}
				if slices.ContainsFunc(s.Args, isText) {
					out = append(out, errTextHit{File: file, Func: fn.Name.Name, Call: "strings." + sel.Sel.Name, Line: fset.Position(s.Pos()).Line})
				}
			}
			return true
		})
	}
	return out
}

func scanErrTextInSource(t testing.TB, file, src string) []errTextHit {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return scanErrTextClassification(fset, f, file)
}

// The planted shapes. The first is the exact groupError this item replaced (red); the second is
// its typed replacement (green). A guard nobody has watched fail is not a guard, and one that
// always fails is as useless.
func TestErrTextScanner_Calibration(t *testing.T) {
	const oldGroupError = `package services
func groupError(err error) error {
	switch {
	case errors.Is(err, storage.ErrGroupNotFound):
		return status.Error(codes.NotFound, "group not found")
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "required") || strings.Contains(msg, "invalid") || strings.Contains(msg, "exceeds"):
		return status.Error(codes.InvalidArgument, "invalid group request")
	case strings.Contains(msg, "permission") || strings.Contains(msg, "denied"):
		return status.Error(codes.PermissionDenied, "access denied")
	default:
		return status.Error(codes.Internal, "group operation failed")
	}
}`
	const typedGroupError = `package services
func groupError(err error) error {
	switch {
	case errors.Is(err, storage.ErrGroupNotFound):
		return status.Error(codes.NotFound, "group not found")
	case errors.Is(err, storage.ErrInvalidGroupRequest):
		return status.Error(codes.InvalidArgument, "invalid group request")
	case errors.Is(err, core.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, "access denied")
	default:
		return status.Error(codes.Internal, "group operation failed")
	}
}`
	if got := scanErrTextInSource(t, "calibration-old", oldGroupError); len(got) != 5 {
		t.Errorf("old groupError shape: want 5 hits (every Contains on the lowered message), got %+v", got)
	}
	if got := scanErrTextInSource(t, "calibration-typed", typedGroupError); len(got) != 0 {
		t.Errorf("typed groupError shape: want no hit, got %+v", got)
	}

	for name, src := range map[string]string{
		"direct":              "package p\nfunc f(err error) bool { return strings.Contains(err.Error(), \"x\") }",
		"has prefix":          "package p\nfunc f(err error) bool { return strings.HasPrefix(err.Error(), \"x\") }",
		"nested lower":        "package p\nfunc f(err error) bool { return strings.Contains(strings.ToLower(err.Error()), \"x\") }",
		"one hop":             "package p\nfunc f(err error) bool {\n\tmsg := err.Error()\n\treturn strings.Contains(msg, \"x\")\n}",
		"two hops":            "package p\nfunc f(err error) bool {\n\tmsg := err.Error()\n\tlow := strings.ToLower(msg)\n\treturn strings.Contains(low, \"x\")\n}",
		"var declaration":     "package p\nfunc f(err error) bool {\n\tvar msg = err.Error()\n\treturn strings.EqualFold(msg, \"x\")\n}",
		"inside func literal": "package p\nfunc f(err error) func() bool {\n\treturn func() bool { return strings.Contains(err.Error(), \"x\") }\n}",
		"wrapped error":       "package p\nfunc f(shareErr error) bool { return strings.Contains(shareErr.Error(), \"x\") }",
	} {
		if got := scanErrTextInSource(t, "calibration-red", src); len(got) == 0 {
			t.Errorf("%s: want a hit, got none", name)
		}
	}
	for name, src := range map[string]string{
		"plain string":      "package p\nfunc f(path string) bool { return strings.Contains(path, \"x\") }",
		"errors.Is":         "package p\nfunc f(err error) bool { return errors.Is(err, ErrX) }",
		"other package":     "package p\nfunc f(err error) bool { return mystrings.Contains(err.Error(), \"x\") }",
		"error not read":    "package p\nfunc f(err error) bool { _ = err; return strings.Contains(name, \"x\") }",
		"reassigned later":  "package p\nfunc f(err error) bool {\n\tother := name\n\treturn strings.Contains(other, \"x\")\n}",
		"Error with args":   "package p\nfunc f(r Renderer) bool { return strings.Contains(r.Error(1), \"x\") }",
		"string method use": "package p\nfunc f(err error) string { return strings.TrimSpace(err.Error()) }",
	} {
		if got := scanErrTextInSource(t, "calibration-green", src); len(got) != 0 {
			t.Errorf("%s: want no hit, got %+v", name, got)
		}
	}
}

// errTextSources lists the non-test Go files the guard scans, as slash paths relative to the repo
// root: the core family and everything under server/.
func errTextSources(t testing.TB) []string {
	t.Helper()
	root := srcpath.RepoRoot()
	seen := map[string]bool{}
	for _, p := range coreFamilySources(t) {
		seen[p] = true
	}
	err := filepath.WalkDir(filepath.Join(root, "server"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			seen[p] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for p := range seen {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// errTextExceptionsDir holds one file per exception (GUARD-COLLISION-NOV-1): a PR that
// adds, migrates or deletes a function's row touches only that function's file, so two PRs
// that are each green alone cannot fail each other in the merge queue the way two edits to
// one shared TSV did. See the README.md in the directory.
const errTextExceptionsDir = "testdata/errtext_classification_exceptions.d"

// errTextExceptionFileName is the file name the row for key must live in: the key with
// "/" and ":" replaced by "__". The loader requires it, so one key cannot hide in two files.
func errTextExceptionFileName(key string) string {
	return strings.NewReplacer("/", "__", ":", "__").Replace(key) + ".tsv"
}

// parseErrTextExceptionFile parses one fragment: exactly one `path:Func<TAB>reason` row
// (blank and '#' lines ignored), in the file named for its key.
func parseErrTextExceptionFile(name string, b []byte) (key, reason string, err error) {
	var rows [][2]string
	for i, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, r, ok := strings.Cut(line, "\t")
		if !ok || strings.TrimSpace(k) == "" || strings.TrimSpace(r) == "" {
			return "", "", fmt.Errorf("%s:%d: want `path:Func<TAB>reason` with a non-empty reason, got %q", name, i+1, line)
		}
		rows = append(rows, [2]string{k, strings.TrimSpace(r)})
	}
	if len(rows) != 1 {
		return "", "", fmt.Errorf("%s: holds %d rows; a fragment holds exactly one", name, len(rows))
	}
	if want := errTextExceptionFileName(rows[0][0]); name != want {
		return "", "", fmt.Errorf("%s: the row for %q must live in a file named %s", name, rows[0][0], want)
	}
	return rows[0][0], rows[0][1], nil
}

// loadErrTextExceptionsFS reads path:Func -> reason from every *.tsv in dir of fsys.
func loadErrTextExceptionsFS(fsys fs.FS, dir string) (map[string]string, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tsv") {
			continue // README.md and friends
		}
		b, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, err
		}
		key, reason, err := parseErrTextExceptionFile(e.Name(), b)
		if err != nil {
			return nil, err
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%s: duplicate exception %q", e.Name(), key)
		}
		out[key] = reason
	}
	return out, nil
}

// loadErrTextExceptions reads path:Func -> reason.
func loadErrTextExceptions(t testing.TB) map[string]string {
	t.Helper()
	out, err := loadErrTextExceptionsFS(os.DirFS(srcpath.PkgDir()), errTextExceptionsDir)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestErrTextExceptionLoaderCalibration is the loader's red/green proof: every malformed
// fragment shape must be rejected and a well-formed directory must load, so a loader that
// accepts everything (or a layout that quietly allows one key in two files) fails here.
func TestErrTextExceptionLoaderCalibration(t *testing.T) {
	t.Parallel()
	const dir = "d"
	row := func(key, reason string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte(key + "\t" + reason + "\n")}
	}
	cases := []struct {
		name    string
		files   fstest.MapFS
		wantErr string // "" = must load
		want    int
	}{
		{name: "green: two one-row files", files: fstest.MapFS{
			dir + "/a__x.go__F.tsv": row("a/x.go:F", "DRIVER: probe"),
			dir + "/a__y.go__G.tsv": row("a/y.go:G", "HTTP: unmigrated"),
		}, want: 2},
		{name: "green: README and other non-tsv files are ignored", files: fstest.MapFS{
			dir + "/README.md":      {Data: []byte("a/x.go:F\twould be a row")},
			dir + "/a__x.go__F.tsv": row("a/x.go:F", "DRIVER: probe"),
		}, want: 1},
		{name: "green: comment and blank lines around the row", files: fstest.MapFS{
			dir + "/a__x.go__F.tsv": {Data: []byte("# why\n\na/x.go:F\tDRIVER: probe\n")},
		}, want: 1},
		{name: "red: two rows in one file", files: fstest.MapFS{
			dir + "/a__x.go__F.tsv": {Data: []byte("a/x.go:F\tr1\na/x.go:G\tr2\n")},
		}, wantErr: "holds 2 rows"},
		{name: "red: empty file", files: fstest.MapFS{
			dir + "/a__x.go__F.tsv": {Data: []byte("# nothing\n")},
		}, wantErr: "holds 0 rows"},
		{name: "red: file name does not match its key", files: fstest.MapFS{
			dir + "/other.tsv": row("a/x.go:F", "DRIVER: probe"),
		}, wantErr: "must live in a file named a__x.go__F.tsv"},
		{name: "red: a second file for the same key", files: fstest.MapFS{
			dir + "/a__x.go__F.tsv":      row("a/x.go:F", "DRIVER: probe"),
			dir + "/a__x.go__F.tsv.copy": row("a/x.go:F", "dup"), // ignored: not .tsv
			dir + "/b__x.go__F.tsv":      row("a/x.go:F", "dup"),
		}, wantErr: "must live in a file named a__x.go__F.tsv"},
		{name: "red: empty reason", files: fstest.MapFS{
			dir + "/a__x.go__F.tsv": {Data: []byte("a/x.go:F\t  \n")},
		}, wantErr: "non-empty reason"},
		{name: "red: no tab", files: fstest.MapFS{
			dir + "/a__x.go__F.tsv": {Data: []byte("a/x.go:F reason\n")},
		}, wantErr: "non-empty reason"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := loadErrTextExceptionsFS(tc.files, dir)
			if tc.wantErr == "" {
				if err != nil || len(got) != tc.want {
					t.Fatalf("want %d rows and no error, got %d rows, err=%v", tc.want, len(got), err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want an error containing %q, got rows=%v err=%v", tc.wantErr, got, err)
			}
		})
	}
}

func TestNoErrorTextClassification(t *testing.T) {
	g := guardrules.Rollout(t)
	root := srcpath.RepoRoot()
	var hits []errTextHit
	for _, path := range errTextSources(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		hits = append(hits, scanErrTextClassification(fset, f, filepath.ToSlash(rel))...)
	}
	// A floor, so a matcher that silently matches nothing fails loudly instead of leaving a green
	// guard (the exception file lists dozens of real uses today).
	if len(hits) < 20 {
		t.Fatalf("scanner found only %d error-text reads under internal/core and server; it has stopped matching", len(hits))
	}

	exceptions := loadErrTextExceptions(t)
	used := map[string]bool{}
	var msgs []string
	for _, h := range hits {
		if _, ok := exceptions[h.key()]; ok {
			used[h.key()] = true
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s:%d in %s: %s on error text", h.File, h.Line, h.Func, h.Call))
	}
	sort.Strings(msgs)
	for _, m := range msgs {
		g.Errorf("%s: classify with errors.Is / errors.As on a sentinel (wrap or return one where the refusal is made; "+
			"see storage.ErrInvalidGroupRequest and core.ErrPermissionDenied). An untyped storage or driver error can contain "+
			"any word, and the text is translated. If the text is one this function built itself, or a driver dialect probe, "+
			"add a one-row file for the function under %s/ with the reason (see its README.md)", m, errTextExceptionsDir)
	}
	var stale []string
	for key, why := range exceptions {
		if !used[key] {
			stale = append(stale, fmt.Sprintf("exception %q (%s) matches no hit any more: delete its row", key, why))
		}
	}
	sort.Strings(stale)
	for _, m := range stale {
		g.Errorf("%s", m)
	}
}
