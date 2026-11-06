// server_utc_write_guard_test.go -- UTC-STORE-SCAN-1 item 2, the server/http/handlers and
// server/grpc half of TestEveryUnhookedExpiryWriteInCoreIsUTC and
// TestEveryExpiryAssignmentAndColumnWriteInCoreIsUTC.
//
// The class is the core guards' class (a non-UTC time reaching an SQLite column). The handlers and
// the gRPC services do not write columns: they decode a client time (RFC 3339 with the client's
// offset, a protobuf Timestamp) or take the server clock and hand it to a core method, which
// normalises it where it stores it (internal/core guards, utc_writes_host_zone_test.go) or to a
// model whose BeforeSave hook does. This guard states that premise and checks it:
//
//   - every keyed expiry / last-used / last-seen field of a `models.T{...}` literal is traceably UTC
//     (scanExpiryWrites, the core guard's scanner and acceptance rule, a BeforeSave hook accepted);
//   - every assignment `x.F = v` in these files of such a field (isGuardedTimeField) or of a storage
//     filter bound (InactiveSince, ExpiresBefore) is traceably UTC (tracesToUTC), unless v is
//     response rendering, which is not a storage write: a call chain ending in `.Format(...)`,
//     `timestamppb.New(...)`, `timePtrToTs(...)`, `optStringValue(...)`, or an identifier the same
//     function assigns from one (`v := t.UTC().Format(...); item.ExpiresAt = &v`);
//   - a raw gorm write (Update, UpdateColumn, Updates, UpdateColumns, Exec with a string or map
//     literal first argument) is itself a finding in these directories: storage belongs behind core.
//
// Each exception row says where the value is normalised or why a zone cannot matter.
//
// What it does NOT catch:
//   - a time handed to a core method (`CreateRiskException(ctx, ..., expiresAt)`): whether core
//     normalises it is the core guards' and the per-entry-point tests' business, not this one's;
//   - a struct passed through a helper, a map or column name built at runtime, other time fields
//     (CreatedAt, UsedAt, ...), generated protobuf code;
//   - data flow: tracing is textual and per function.
// Wrong-reason exemptions are checked too: an exception that no longer matches any hit fails.
//
// Report-only on its first day (docs/guard-rollout.d/TestEveryServerExpiryWriteIsUTC.tsv).

package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// serverTimeWriteExceptions: "<http|grpc>:file.go:Func:Target" -> why the write is safe or tracked,
// filled by registerServerTimeWriteException from init() in server_utc_write_exception_<slug>_test.go
// files, one row each. The tag keeps same-named files of the two trees apart (audit_unavailable.go is in
// both); it also keeps the key from reading as a file path to TestNamedSourceFilesExist.
var serverTimeWriteExceptions = map[string]string{}

func registerServerTimeWriteException(key, reason string) {
	if _, dup := serverTimeWriteExceptions[key]; dup {
		panic("duplicate server time-write UTC exception " + key)
	}
	serverTimeWriteExceptions[key] = reason
}

// serverSources lists the non-test .go files of server/http/handlers and server/grpc, recursively,
// as paths relative to server/ (slash-separated), skipping generated protobuf code.
// serverFileTag: "http:name.go" or "grpc:name.go" for a path relative to server/.
func serverFileTag(rel string) string {
	if strings.HasPrefix(rel, "grpc/") {
		return "grpc:" + filepath.Base(rel)
	}
	return "http:" + filepath.Base(rel)
}

func serverSources(t testing.TB) (root string, rels []string) {
	t.Helper()
	root = filepath.Join(srcpath.RepoRoot(), "server")
	for _, sub := range []string{"http/handlers", "grpc"} {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(sub)), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") ||
				strings.HasSuffix(name, ".pb.go") || strings.HasSuffix(name, "_grpc.pb.go") || strings.HasSuffix(name, ".pb.gw.go") {
				return nil
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return rerr
			}
			rels = append(rels, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(rels) < 60 {
		t.Fatalf("only %d server handler/grpc source files: wrong root", len(rels))
	}
	sort.Strings(rels)
	return root, rels
}

type rawWrite struct {
	File, Func, Call string
	Line             int
}

func (w rawWrite) key() string { return w.File + ":" + w.Func + ":raw" }

// rawGormWrites returns the gorm-shaped writes in f: a selector call named Update, UpdateColumn,
// Updates, UpdateColumns or Exec with a first argument that is a string literal or a map literal.
// (A bare `Update(ctx, x)` on a core or storage method has a different first argument and is not one.)
func rawGormWrites(fset *token.FileSet, f *ast.File, rel string) []rawWrite {
	var out []rawWrite
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isGormWriteCall(call) {
				return true
			}
			raw := false
			switch a := call.Args[0].(type) {
			case *ast.BasicLit:
				raw = a.Kind == token.STRING
			case *ast.CompositeLit:
				_, raw = a.Type.(*ast.MapType)
			}
			if raw {
				out = append(out, rawWrite{File: rel, Func: fn.Name.Name, Call: call.Fun.(*ast.SelectorExpr).Sel.Name, Line: fset.Position(call.Pos()).Line})
			}
			return true
		})
	}
	return out
}

// serverBoundFields are storage filter fields holding a cutoff the store compares with a column.
func isServerBoundField(name string) bool { return name == "InactiveSince" || name == "ExpiresBefore" }

func isResponseEncoding(e ast.Expr, body *ast.BlockStmt, depth int) bool {
	e = stripExpr(e)
	switch x := e.(type) {
	case *ast.CallExpr:
		switch fn := x.Fun.(type) {
		case *ast.SelectorExpr:
			if fn.Sel.Name == "Format" {
				return true
			}
			if id, ok := fn.X.(*ast.Ident); ok && id.Name == "timestamppb" {
				return true
			}
		case *ast.Ident:
			return fn.Name == "timePtrToTs" || fn.Name == "optStringValue"
		}
	case *ast.Ident:
		if depth > 3 {
			return false
		}
		found := false
		ast.Inspect(body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != len(as.Rhs) {
				return !found
			}
			for i, lhs := range as.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name == x.Name && isResponseEncoding(as.Rhs[i], body, depth+1) {
					found = true
				}
			}
			return !found
		})
		return found
	}
	return false
}

// utcInChain: a `.UTC()` call anywhere in e's selector/call chain (`time.Now().UTC().Add(-d)`: Add keeps
// the location), or an identifier the same function assigns from such a chain.
func utcInChain(e ast.Expr, body *ast.BlockStmt, depth int) bool {
	for cur := stripExpr(e); cur != nil; {
		switch x := cur.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "UTC" {
					return true
				}
				cur = stripExpr(sel.X)
				continue
			}
			return false
		case *ast.SelectorExpr:
			cur = stripExpr(x.X)
			continue
		case *ast.Ident:
			if depth > 3 {
				return false
			}
			found := false
			ast.Inspect(body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != len(as.Rhs) {
					return !found
				}
				for i, lhs := range as.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == x.Name && utcInChain(as.Rhs[i], body, depth+1) {
						found = true
					}
				}
				return !found
			})
			return found
		default:
			return false
		}
	}
	return false
}

type serverAssign struct {
	File, Func, Field string
	Line              int
}

func (w serverAssign) key() string { return w.File + ":" + w.Func + ":" + w.Field }

// scanServerTimeAssignments returns the non-UTC, non-rendering assignments of tracked fields and bounds.
func scanServerTimeAssignments(fset *token.FileSet, f *ast.File, rel string) []serverAssign {
	var out []serverAssign
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != len(as.Rhs) {
				return true
			}
			for i, lhs := range as.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || !(isGuardedTimeField(sel.Sel.Name) || isServerBoundField(sel.Sel.Name)) {
					continue
				}
				v := as.Rhs[i]
				if isNilIdent(v) || isResponseEncoding(v, fn.Body, 0) || tracesToUTC(v, fn.Body, 0) || utcInChain(v, fn.Body, 0) {
					continue
				}
				out = append(out, serverAssign{File: rel, Func: fn.Name.Name, Field: sel.Sel.Name, Line: fset.Position(sel.Pos()).Line})
			}
			return true
		})
	}
	return out
}

func TestServerAssignScanner_Calibration(t *testing.T) {
	parse := func(src string) []serverAssign {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "calibration_input", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return scanServerTimeAssignments(fset, f, "calibration_input")
	}
	for name, src := range map[string]string{
		"client time into a request": "package h\nfunc f(req *R, exp time.Time) {\n\treq.Expiration = &exp\n}",
		"host-zone cutoff":           "package h\nfunc f(filter *F) {\n\tcutoff := time.Now().AddDate(0, 0, -30)\n\tfilter.InactiveSince = &cutoff\n}",
		"client bound":               "package h\nfunc f(filter *F, t time.Time) {\n\tfilter.ExpiresBefore = &t\n}",
		"UTC only to format":         "package h\nfunc f(req *R, exp time.Time) {\n\t_ = exp.UTC().Format(time.RFC3339)\n\treq.ExpiresAt = &exp\n}",
	} {
		if got := parse(src); len(got) != 1 {
			t.Errorf("%s: want one finding, got %+v", name, got)
		}
	}
	for name, src := range map[string]string{
		"UTC cutoff":             "package h\nfunc f(filter *F) {\n\tcutoff := time.Now().UTC().Add(-time.Hour)\n\tfilter.InactiveSince = &cutoff\n}",
		"rendered string":        "package h\nfunc f(resp *R, t time.Time) {\n\tresp.ExpiresAt = t.UTC().Format(time.RFC3339)\n}",
		"rendered via variable":  "package h\nfunc f(item *I, t time.Time) {\n\tv := t.Format(time.RFC3339)\n\titem.LastSeenAt = &v\n}",
		"protobuf timestamp":     "package h\nfunc f(out *O, t time.Time) {\n\tout.ExpiresAt = timestamppb.New(t)\n}",
		"timePtrToTs":            "package h\nfunc f(out *O, t *time.Time) {\n\tout.Expiration = timePtrToTs(t)\n}",
		"cleared":                "package h\nfunc f(req *R) {\n\treq.ExpiresAt = nil\n}",
		"other field, not owned": "package h\nfunc f(req *R, t time.Time) {\n\treq.CreatedAt = t\n}",
	} {
		if got := parse(src); len(got) != 0 {
			t.Errorf("%s: want none, got %+v", name, got)
		}
	}
}

func TestServerGormWriteScanner_Calibration(t *testing.T) {
	parse := func(src string) []rawWrite {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "calibration_input", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return rawGormWrites(fset, f, "calibration_input")
	}
	for name, src := range map[string]string{
		"column write":  "package h\nfunc f(db *gorm.DB) {\n\tdb.Update(\"expires_at\", e)\n}",
		"map updates":   "package h\nfunc f(db *gorm.DB) {\n\tdb.Updates(map[string]any{\"a\": 1})\n}",
		"raw exec":      "package h\nfunc f(db *gorm.DB) {\n\tdb.Exec(\"UPDATE t SET a = ?\", 1)\n}",
		"update column": "package h\nfunc f(db *gorm.DB) {\n\tdb.UpdateColumn(\"last_seen_at\", t)\n}",
	} {
		if got := parse(src); len(got) != 1 {
			t.Errorf("%s: want one raw gorm write, got %v", name, got)
		}
	}
	for name, src := range map[string]string{
		"core method":     "package h\nfunc f(c *core.Core, ctx context.Context) {\n\tc.Update(ctx, id)\n}",
		"storage Updates": "package h\nfunc f(s storage.Storage, ctx context.Context) {\n\ts.Updates(ctx, x)\n}",
	} {
		if got := parse(src); len(got) != 0 {
			t.Errorf("%s: want none, got %v", name, got)
		}
	}
}

func TestEveryServerExpiryWriteIsUTC(t *testing.T) {
	g := guardrules.Rollout(t)
	inv := modelHookInventory(t)
	root, rels := serverSources(t)

	var hits []string
	used := map[string]bool{}
	check := func(key, msg string) {
		if _, ok := serverTimeWriteExceptions[key]; ok {
			used[key] = true
			return
		}
		hits = append(hits, msg)
	}
	for _, rel := range rels {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		for _, w := range scanExpiryWrites(fset, f, serverFileTag(rel), inv) {
			if !w.UTC {
				check(w.key(), fmt.Sprintf("%s:%d in %s stores %s.%s without .UTC()", w.File, w.Line, w.Func, w.Type, w.Field))
			}
		}
		for _, w := range scanServerTimeAssignments(fset, f, serverFileTag(rel)) {
			check(w.key(), fmt.Sprintf("%s:%d in %s assigns %s without .UTC()", w.File, w.Line, w.Func, w.Field))
		}
		for _, w := range rawGormWrites(fset, f, serverFileTag(rel)) {
			check(w.key(), fmt.Sprintf("%s:%d in %s: raw gorm %s", w.File, w.Line, w.Func, w.Call))
		}
	}
	// There is no floor on hits: a clean tree has none. The scanners are held by their calibration tests
	// (TestExpiryWriteScanner_Calibration, TestServerAssignScanner_Calibration,
	// TestServerGormWriteScanner_Calibration) and the file list by the size check in serverSources.

	sort.Strings(hits)
	for _, m := range hits {
		g.Errorf("%s: a handler or gRPC service must hand a time to core, which normalises it where it stores it; a time written here "+
			"must be traceably UTC (`x = x.UTC()`), or add a server_utc_write_exceptions_test.go registerServerTimeWriteException row with the reason it is safe", m)
	}
	for key, why := range serverTimeWriteExceptions {
		if !used[key] {
			g.Errorf("exception %q (%s) matches no hit any more: delete its row", key, why)
		}
	}
}
