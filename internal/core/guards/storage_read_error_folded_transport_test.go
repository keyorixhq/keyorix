// storage_read_error_folded_transport_test.go -- STORAGE-ERR-CLASS-5 item 5.
//
// The handler pre-check class: `x, err := h.coreService.GetThing(...); if err != nil {
// sendError(w, "NotFound", ..., http.StatusNotFound, nil) }`, and its gRPC form
// `return nil, status.Error(codes.NotFound, ...)`. The core service wraps a storage read
// FAULT in the same error chain as a missing row, so a transport that answers 404 / NotFound
// for every error tells the caller "gone" during an outage (STORAGE-ERR-CLASS-4 found the
// CreateSecretAccessRequest pre-check, the gRPC authorizeScopedTarget callers and the
// anomaly acknowledge by hand). TestNoStorageReadErrorFoldedIntoNotFound read only
// internal/core and server/middleware/auth.go; it now also reads server/http/handlers and
// server/grpc/services through this scanner.
//
// What it recognises (the enumeration, stated so a reviewer can check it):
//   - an `if` whose condition contains `err != nil` (alone or OR-ed with another test), in a
//     function where the LAST assignment to `err` before it came from ONE call of a method
//     named List*, Get*, Find*, Count*, Resolve*, Lookup* or Lock* on the core service: a
//     receiver whose last name is coreService, core or cs (h.coreService.X, s.core.X, cs.X, a
//     local coreService), or on its storage (X.Storage().Y), or the if's own init statement
//     is such an assignment;
//   - whose body, anywhere in it, answers not-found: a call with the argument
//     http.StatusNotFound or codes.NotFound, or a call to a function whose name contains
//     "NotFound" (notFound(w), writeNotFound(...));
//   - and where neither the condition nor the body classifies the error: no call to
//     errors.Is / errors.As, an Is*NotFound predicate, or one of transportClassifierCalls.
//
// What it does NOT catch:
//   - data flow: "the last assignment before the if, in source order" stands in for it, so an
//     error carried through a variable, a struct field or a closure is invisible, and a
//     branchy function can attribute an `if` to the wrong assignment;
//   - a mutation whose name is not a read (RevokeOwnPAT, AcknowledgeAnomalyAlert,
//     Update*/Delete*): their error can be a read fault too (the handler then answers 404 for
//     every error after the read), and only a human reading the call finds it;
//   - the 404 chosen by a helper whose name does not say NotFound and takes no status;
//   - a receiver under another name (a local `svc`, a field `h.svc`) or a stored func value;
//   - a verdict that is not a not-found (403/400/409 for an error the handler should have
//     answered 503): the rule is about the not-found fold only;
//   - a body that classifies in an unrecognised way (a false negative of the classifier list,
//     not of the rule: add the helper's name to transportClassifierCalls).
//
// Report-only on its first day (docs/guard-rollout.d/TestNoStorageReadErrorFoldedIntoNotFound.tsv,
// docs/guard-rollout-contract.md).

package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// transportReadDirs: the server layers the transport scan reads, as repo-relative slash paths
// mapped to the key prefix their hits carry ("handlers/x.go:Func", "services/x.go:Func").
var transportReadDirs = map[string]string{
	"server/http/handlers": "handlers/",
	"server/grpc/services": "services/",
}

// transportCoreReceivers: the last name of a receiver that is the core service in the
// transports.
var transportCoreReceivers = map[string]bool{"coreService": true, "core": true, "cs": true}

// transportClassifierCalls: calls whose presence in the condition or the body means the read
// error is classified (a missing row told from a fault) before the not-found is chosen.
// IsAuthorizeTransient / authorizeRefusal are the gRPC authorize helpers that tell an outage
// (structural: context, driver and net errors) from a verdict.
var transportClassifierCalls = map[string]bool{
	"sendStorageUnavailable": true, "storageUnavailableStatus": true,
	"SecretReadVerdictFault": true, "ReadFault": true, "IsStorageReadUnavailable": true,
	"classifyReadError": true, "isPositiveNotFound": true,
	"IsAuthorizeTransient": true, "authorizeRefusal": true,
}

// isNotFoundPredicate: an unexported helper such as isSecretNotFound (containsClassifier only
// knows the exported Is*NotFound form). Its other arm is the handler's non-404 answer.
func isNotFoundPredicate(name string) bool {
	return (strings.HasPrefix(name, "is") || strings.HasPrefix(name, "Is")) && strings.HasSuffix(name, "NotFound")
}

func isTransportCoreReceiver(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return transportCoreReceivers[x.Name]
	case *ast.SelectorExpr:
		return transportCoreReceivers[x.Sel.Name]
	}
	return false
}

// transportReadCall reports the read method an expression calls on the core service or its
// storage, or "".
func transportReadCall(e ast.Expr) string {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if !isTransportCoreReceiver(sel.X) && !looksLikeStorage(sel.X) {
		return ""
	}
	for _, p := range foldedReadPrefixes {
		if strings.HasPrefix(sel.Sel.Name, p) {
			return sel.Sel.Name
		}
	}
	return ""
}

func transportLastErrFromRead(lhs, rhs []ast.Expr) (callee string, assignsErr bool) {
	if len(lhs) == 0 {
		return "", false
	}
	id, ok := lhs[len(lhs)-1].(*ast.Ident)
	if !ok || id.Name != "err" {
		return "", false
	}
	if len(rhs) != 1 {
		return "", true
	}
	return transportReadCall(rhs[0]), true
}

// answersNotFound reports whether n contains a call that answers the transport's not-found:
// an argument http.StatusNotFound or codes.NotFound, or a callee named *NotFound*.
func answersNotFound(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return !found
		}
		name := ""
		switch f := call.Fun.(type) {
		case *ast.Ident:
			name = f.Name
		case *ast.SelectorExpr:
			name = f.Sel.Name
		}
		if strings.Contains(name, "NotFound") || strings.Contains(name, "notFound") {
			found = true
		}
		for _, a := range call.Args {
			if sel, ok := a.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok &&
					((id.Name == "http" && sel.Sel.Name == "StatusNotFound") || (id.Name == "codes" && sel.Sel.Name == "NotFound")) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

func containsTransportClassifier(n ast.Node) bool {
	if containsClassifier(n) {
		return true
	}
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return !found
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			found = found || transportClassifierCalls[f.Name] || isNotFoundPredicate(f.Name)
		case *ast.SelectorExpr:
			found = found || transportClassifierCalls[f.Sel.Name] || isNotFoundPredicate(f.Sel.Name)
		}
		return !found
	})
	return found
}

// scanTransportFolds returns every recognised handler / service pre-check fold in f.
func scanTransportFolds(fset *token.FileSet, f *ast.File, file string) []foldedRead {
	var out []foldedRead
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		lastRead := ""
		classified := false
		check := func(ifs *ast.IfStmt, callee string) {
			if callee == "" || !condMentionsErrNotNil(ifs.Cond) {
				return
			}
			if containsTransportClassifier(ifs.Cond) || containsTransportClassifier(ifs.Body) {
				classified = true
				return
			}
			if classified {
				return
			}
			if answersNotFound(ifs.Body) {
				out = append(out, foldedRead{File: file, Func: fn.Name.Name, Callee: callee, Line: fset.Position(ifs.Pos()).Line})
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				if callee, assigns := transportLastErrFromRead(s.Lhs, s.Rhs); assigns {
					lastRead, classified = callee, false
				}
			case *ast.IfStmt:
				if as, ok := s.Init.(*ast.AssignStmt); ok {
					if callee, assigns := transportLastErrFromRead(as.Lhs, as.Rhs); assigns {
						lastRead, classified = callee, false
					}
				}
				check(s, lastRead)
			}
			return true
		})
	}
	return out
}

func scanTransportFoldsInSource(t testing.TB, file, src string) []foldedRead {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return scanTransportFolds(fset, f, filepath.Base(file))
}

// scanTransportSources scans every non-test file of the transport dirs. A directory that no
// longer exists fails the glob floor, so a move cannot leave the widening silently empty.
func scanTransportSources(t testing.TB) []foldedRead {
	t.Helper()
	var hits []foldedRead
	for dir, prefix := range transportReadDirs {
		paths, err := filepath.Glob(filepath.Join(srcpath.RepoRoot(), filepath.FromSlash(dir), "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(paths)
		files := 0
		for _, path := range paths {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			files++
			hits = append(hits, scanTransportFolds(fset, f, prefix+filepath.Base(path))...)
		}
		if files < 10 {
			t.Fatalf("scanned only %d files under %s; the source walk has stopped matching", files, dir)
		}
	}
	return hits
}

// The planted shapes. Red: the CreateSecretAccessRequest pre-check and the gRPC form as they
// were before STORAGE-ERR-CLASS-4; green: the classified shapes and every non-fold.
func TestFoldedReadTransportScanner_Calibration(t *testing.T) {
	red := map[string]string{
		"handler pre-check answers 404 for every error": `package handlers
func (h *H) CreateSecretAccessRequest(w http.ResponseWriter, r *http.Request) {
	if _, err := h.coreService.GetSecretWithPermissionCheck(r.Context(), id, uid); err != nil {
		sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		return
	}
}`,
		"handler read into err, then 404": `package handlers
func (h *H) Get(w http.ResponseWriter, r *http.Request) {
	p, err := h.coreService.GetAlertEscalationPolicy(r.Context(), id)
	if err != nil {
		sendError(w, "NotFound", "no such policy", http.StatusNotFound, nil)
		return
	}
	_ = p
}`,
		"gRPC read, then codes.NotFound": `package services
func (s *S) GetThing(ctx context.Context, req *R) (*T, error) {
	t, err := s.core.GetThing(ctx, req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "thing not found")
	}
	_ = t
	return nil, nil
}`,
		"helper named notFound": `package handlers
func (h *H) Get(w http.ResponseWriter, r *http.Request) {
	x, err := cs.GetThing(ctx, id)
	if err != nil {
		notFound(w)
		return
	}
	_ = x
}`,
		"err OR mismatch": `package handlers
func (h *H) Get(w http.ResponseWriter, r *http.Request) {
	x, err := h.coreService.Storage().GetThing(ctx, id)
	if err != nil || x.ProjectID != pid {
		sendError(w, "NotFound", "gone", http.StatusNotFound, nil)
		return
	}
}`,
	}
	for name, src := range red {
		if got := scanTransportFoldsInSource(t, "catalog.go", src); len(got) != 1 {
			t.Errorf("%s: want exactly one fold hit, got %+v", name, got)
		}
	}
	green := map[string]string{
		"classified with sendStorageUnavailable": `package handlers
func (h *H) Get(w http.ResponseWriter, r *http.Request) {
	p, err := h.coreService.GetThing(r.Context(), id)
	if err != nil {
		if sendStorageUnavailable(w, err) {
			return
		}
		sendError(w, "NotFound", "gone", http.StatusNotFound, nil)
		return
	}
	_ = p
}`,
		"classified with errors.Is": `package handlers
func (h *H) Get(w http.ResponseWriter, r *http.Request) {
	p, err := h.coreService.GetThing(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrThingNotFound) {
			sendError(w, "NotFound", "gone", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "failed", http.StatusInternalServerError, nil)
		return
	}
	_ = p
}`,
		"gRPC classified with storageUnavailableStatus": `package services
func (s *S) GetThing(ctx context.Context, req *R) (*T, error) {
	t, err := s.core.GetThing(ctx, req.Id)
	if err != nil {
		if out, ok := storageUnavailableStatus(err); ok {
			return nil, out
		}
		return nil, status.Error(codes.NotFound, "thing not found")
	}
	_ = t
	return nil, nil
}`,
		"verdict is not a not-found": `package handlers
func (h *H) Get(w http.ResponseWriter, r *http.Request) {
	p, err := h.coreService.GetThing(r.Context(), id)
	if err != nil {
		sendError(w, "InternalError", "failed", http.StatusInternalServerError, nil)
		return
	}
	_ = p
}`,
		"err is not from a core read": `package handlers
func (h *H) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "NotFound", "bad id", http.StatusNotFound, nil)
		return
	}
	_ = id
}`,
		"a mutation is outside the enumeration": `package handlers
func (h *H) Revoke(w http.ResponseWriter, r *http.Request) {
	_, err := h.coreService.RevokeOwnPAT(r.Context(), uid, id)
	if err != nil {
		sendError(w, "NotFound", "gone", http.StatusNotFound, nil)
		return
	}
}`,
	}
	for name, src := range green {
		if got := scanTransportFoldsInSource(t, "catalog.go", src); len(got) != 0 {
			t.Errorf("%s: want no hit, got %+v", name, got)
		}
	}
}
