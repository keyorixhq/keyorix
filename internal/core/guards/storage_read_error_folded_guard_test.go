// storage_read_error_folded_guard_test.go -- STORAGE-ERR-CLASS-1 item 6.
//
// The class: `m, err := c.storage.GetMachineIdentity(...); if err != nil || m.ProjectID != p
// { return fmt.Errorf("machine identity not found") }`. A storage READ error of any kind
// (connection refused, timeout, scan error) is reported as "<thing> not found", so during an
// outage a revoke answers 404 and the operator concludes the principal is already gone while the
// revoke was never applied. A positive "no such row" keeps the not-found answer; anything else is
// a storage fault (classifyReadError / credentialLookupError, internal/core/storage_read_class.go).
//
// What it recognises (the enumeration, stated so a reviewer can check it):
//   - an `if` whose condition contains `err != nil` (alone or OR-ed with another test), in a
//     function where the LAST assignment to `err` before it came from ONE call of a method named
//     List*, Get*, Find*, Count*, Resolve*, Lookup* or Lock* on a receiver that looks like the
//     storage layer (the receiver rules of discarded_list_error_guard_test.go), or the if's own
//     init statement is such an assignment;
//   - whose body returns a fmt.Errorf (or errors.New) whose constant text contains "not found",
//     "no longer exists", or the i18n "ErrorNotFound"/"ErrorValidation" key, i.e. a not-found /
//     validation verdict;
//   - and where neither the condition nor the body classifies the error: no call to
//     classifyReadError, credentialLookupError, isPositiveNotFound, errors.Is, errors.As or an
//     Is*NotFound predicate, and the Errorf does not wrap err with %w.
//
// STORAGE-ERR-CLASS-3 widened it to the REST scope resolvers: it also reads server/middleware/auth.go
// (keys "middleware/auth.go:Func"), where the core service is the receiver `cs` (cs.Storage().X
// and cs.X pass-through getters) and the not-found verdict is the sentinel errTargetNotFound,
// returned or handed to handleScopeResolutionError anywhere in the if body. There the classifier
// is core.ReadFault (a fault becomes errTargetReadFault).
//
// What it does NOT catch:
//   - data flow: "the last assignment before the if, in source order" stands in for it, so an
//     error carried through a variable, a struct field or a closure is invisible, and a branchy
//     function can attribute an `if` to the wrong assignment;
//   - the verdict built elsewhere (`return notFound` where notFound is a variable built earlier,
//     as WithdrawAccessRequest does: its constant is looked at only when it is an Errorf in the
//     if body);
//   - folds in `switch`/`else` arms, and in the server layers other than server/middleware/auth.go
//     (other middleware files, server/http handlers, gRPC services);
//   - a middleware fold whose body ALSO classifies something else with errors.Is (e.g.
//     RequireScopedSecretRefPermission's errors.Is(err, core.ErrSecretRefInvalid)): any errors.Is
//     counts as classifying;
//   - reads through an unrecognised receiver name, a stored func value or an interface helper;
//   - a body that classifies in an unrecognised way (it is then a false negative of the
//     classifier list, not of the rule: add the helper's name to classifierCalls).
//
// STORAGE-ERR-CLASS-4 added the identifier ErrSecretRefNotFound to the not-found sentinels, so
// a fold of the shape ResolveSecretRef had before ERR-FOLD-HANDLERS-1 (#3903) fixed it
// (internal/core/secret_ref.go) is recognised; the widening found stageRenderRef
// (secret_render.go). The other folds STORAGE-ERR-CLASS-4 fixed (the handler pre-checks in
// server/http/handlers, the gRPC authorizeScopedTarget callers) are outside what it can see.
//
// Report-only on its first day, and again for the server/middleware widening
// (docs/guard-rollout.d/TestNoStorageReadErrorFoldedIntoNotFound.tsv, docs/guard-rollout-contract.md).

package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

var foldedReadPrefixes = append(append([]string{}, storageReadPrefixes...), "Lock")

// foldedReadCoreReceivers: receivers that are the core service in the server layers, whose
// pass-through getters (GetDynamicSecretConfig, GetDynamicSecretLease) return the raw storage
// error. Only the fold scanner uses them.
var foldedReadCoreReceivers = map[string]bool{"cs": true}

// notFoundSentinels: package-level not-found verdicts that are an identifier, not an Errorf.
// ErrSecretRefNotFound is core.ResolveSecretRef's verdict (STORAGE-ERR-CLASS-4).
var notFoundSentinels = map[string]bool{"errTargetNotFound": true, "ErrSecretRefNotFound": true}

// foldedReadMiddlewareDir / foldedReadMiddlewareFiles: the server-layer files the scan also
// reads (the REST scope resolvers and the per-secret gates live in auth.go). A missing file
// fails the parse, so a move cannot leave the widening silently empty.
const foldedReadMiddlewareDir = "server/middleware"

var foldedReadMiddlewareFiles = []string{"auth.go"}

// classifierCalls: calls whose presence in the condition or the body means the error is
// classified (a positive not-found is told from a fault) before the verdict is chosen.
var classifierCalls = map[string]bool{
	"classifyReadError": true, "credentialLookupError": true, "isPositiveNotFound": true,
	"ReadFault": true, "secretReadFault": true,
}

// foldedReadExceptions: "file.go:FuncName" -> why the fold is safe or deferred. Filled one
// file per row by registerFoldedReadException from storage_read_error_folded_exception_*_test.go.
var foldedReadExceptions = map[string]string{}

func registerFoldedReadException(key, reason string) {
	if _, dup := foldedReadExceptions[key]; dup {
		panic("duplicate folded-read exception " + key)
	}
	foldedReadExceptions[key] = reason
}

type foldedRead struct {
	File, Func, Callee string
	Line               int
}

func (d foldedRead) key() string { return d.File + ":" + d.Func }

func isStorageReadCall(e ast.Expr) (string, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	if id, isIdent := sel.X.(*ast.Ident); !looksLikeStorage(sel.X) && (!isIdent || !foldedReadCoreReceivers[id.Name]) {
		return "", false
	}
	for _, p := range foldedReadPrefixes {
		if strings.HasPrefix(sel.Sel.Name, p) {
			return sel.Sel.Name, true
		}
	}
	return "", false
}

// lastErrFromRead reports the storage read call that an assignment's `err` came from ("" when
// it is not a recognised storage read), and whether the statement assigns err at all.
func lastErrFromRead(lhs, rhs []ast.Expr) (callee string, assignsErr bool) {
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
	name, _ := isStorageReadCall(rhs[0])
	return name, true
}

func condMentionsErrNotNil(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if b, ok := n.(*ast.BinaryExpr); ok && b.Op == token.NEQ {
			if x, ok := b.X.(*ast.Ident); ok && x.Name == "err" {
				if y, ok := b.Y.(*ast.Ident); ok && y.Name == "nil" {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

func constText(e ast.Expr) string {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return s
}

// notFoundVerdict reports whether n is a fmt.Errorf / errors.New whose constant text (any
// argument) is a not-found / validation verdict, and whether it wraps an error with %w.
func notFoundVerdict(call *ast.CallExpr) (verdict, wraps bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false, false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || !((pkg.Name == "fmt" && sel.Sel.Name == "Errorf") || (pkg.Name == "errors" && sel.Sel.Name == "New")) {
		return false, false
	}
	var text strings.Builder
	var hasKey bool
	ast.Inspect(call, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BasicLit:
			text.WriteString(constText(x))
			text.WriteByte(' ')
		case *ast.CallExpr:
			// i18n.T("ErrorNotFound", nil)
			if s, ok := x.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "T" && len(x.Args) > 0 {
				if k := constText(x.Args[0]); k == "ErrorNotFound" || k == "ErrorValidation" {
					hasKey = true
				}
			}
		}
		return true
	})
	s := strings.ToLower(text.String())
	verdict = hasKey || strings.Contains(s, "not found") || strings.Contains(s, "no longer exists")
	return verdict, strings.Contains(s, "%w")
}

func containsClassifier(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return !found
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			found = found || classifierCalls[f.Name]
		case *ast.SelectorExpr:
			name := f.Sel.Name
			if id, ok := f.X.(*ast.Ident); ok && id.Name == "errors" && (name == "Is" || name == "As") {
				found = true
			}
			if classifierCalls[name] || (strings.HasPrefix(name, "Is") && strings.HasSuffix(name, "NotFound")) {
				found = true
			}
		}
		return !found
	})
	return found
}

// mentionsNotFoundSentinel reports whether body uses a notFoundSentinels identifier (returned,
// passed to a call or assigned): the verdict "no such target" chosen without classifying err.
func mentionsNotFoundSentinel(body ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && notFoundSentinels[id.Name] {
			found = true
		}
		return !found
	})
	return found
}

// scanFoldedReads returns every recognised fold in f (file name file).
func scanFoldedReads(fset *token.FileSet, f *ast.File, file string) []foldedRead {
	var out []foldedRead
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		lastRead := ""      // callee of the storage read the current `err` came from
		classified := false // an earlier `if err != nil` already classified the current `err`
		check := func(ifs *ast.IfStmt, callee string) {
			if callee == "" || !condMentionsErrNotNil(ifs.Cond) {
				return
			}
			// An `if err != nil` that classifies (a fault returns there) covers the later
			// `if err != nil || mismatch` that only a positive not-found can still reach.
			if containsClassifier(ifs.Cond) || containsClassifier(ifs.Body) {
				classified = true
				return
			}
			if classified {
				return
			}
			if mentionsNotFoundSentinel(ifs.Body) {
				out = append(out, foldedRead{File: file, Func: fn.Name.Name, Callee: callee, Line: fset.Position(ifs.Pos()).Line})
				return
			}
			ast.Inspect(ifs.Body, func(n ast.Node) bool {
				ret, ok := n.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, r := range ret.Results {
					if call, ok := r.(*ast.CallExpr); ok {
						if verdict, wraps := notFoundVerdict(call); verdict && !wraps {
							out = append(out, foldedRead{File: file, Func: fn.Name.Name, Callee: callee, Line: fset.Position(ifs.Pos()).Line})
							return false
						}
					}
				}
				return true
			})
		}
		// Source order: ast.Inspect visits statements in order, so an assignment is seen
		// before the `if` that follows it.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				if callee, assigns := lastErrFromRead(s.Lhs, s.Rhs); assigns {
					lastRead, classified = callee, false
				}
			case *ast.IfStmt:
				if as, ok := s.Init.(*ast.AssignStmt); ok {
					if callee, assigns := lastErrFromRead(as.Lhs, as.Rhs); assigns {
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

func scanFoldedReadsInSource(t testing.TB, file, src string) []foldedRead {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return scanFoldedReads(fset, f, filepath.Base(file))
}

// The planted shapes. Red: the exact machineInProject shape origin/main had and its siblings;
// green: the helper shape and every legitimate non-fold. "A guard nobody has watched fail is
// not a guard", and one that always fails is as useless.
func TestFoldedReadScanner_Calibration(t *testing.T) {
	red := map[string]string{
		// machineInProject as it was before STORAGE-ERR-CLASS-1.
		"machineInProject (err || mismatch)": `package core
func (c *K) machineInProject(ctx context.Context, projectID, machineID uint) (*M, error) {
	m, err := c.storage.GetMachineIdentity(ctx, machineID)
	if err != nil || m.ProjectID != projectID {
		return nil, fmt.Errorf("machine identity not found")
	}
	return m, nil
}`,
		"bare fold": `package core
func (c *K) RevokeInvitation() error {
	inv, err := c.storage.GetProjectInvitation(ctx, id)
	if err != nil {
		return fmt.Errorf("invitation not found")
	}
	_ = inv
	return nil
}`,
		"lock read inside a transaction": `package core
func (c *K) transitionInTx(tx S) error {
	m, err := tx.LockMachineIdentityForUpdate(ctx, id)
	if err != nil {
		return fmt.Errorf("machine identity not found")
	}
	_ = m
	return nil
}`,
		"ResolveSecretRef folds GetSecretByName into ErrSecretRefNotFound": `package core
func (c *K) ResolveSecretRef(ctx context.Context, ref string) (*M, error) {
	secret, err := c.storage.GetSecretByName(ctx, name, projectID, envID)
	if err != nil || secret == nil {
		return nil, ErrSecretRefNotFound
	}
	return secret, nil
}`,
		"if-init read with i18n verdict": `package core
func (c *K) attest() error {
	if s, err := c.storage.GetSecret(ctx, id); err != nil {
		return fmt.Errorf("%s: %s", i18n.T("ErrorNotFound", nil), "stale")
	} else {
		_ = s
	}
	return nil
}`,
	}
	for name, src := range red {
		if got := scanFoldedReadsInSource(t, "machine_token.go", src); len(got) != 1 {
			t.Errorf("%s: want exactly one fold hit, got %+v", name, got)
		}
	}
	// The REST scope resolvers and the per-secret gate as they were before STORAGE-ERR-CLASS-3.
	middlewareRed := map[string]string{
		"resolver returns errTargetNotFound": `package middleware
func ScopeFromRotationPolicyParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		policy, err := cs.Storage().GetRotationPolicy(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: derefUint(policy.ProjectID)}, nil
	}
}`,
		"core pass-through getter": `package middleware
func ScopeFromDynamicSecretConfigParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		cfg, err := cs.GetDynamicSecretConfig(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: cfg.ProjectID}, nil
	}
}`,
		"gate hands errTargetNotFound on": `package middleware
func handleScopedSecretPermissionRequest(w http.ResponseWriter, r *http.Request) {
	secret, err := cs.Storage().GetSecret(r.Context(), secretID)
	if err != nil {
		if authorizeLookupUnavailable(w, r, err) {
			return
		}
		handleScopeResolutionError(w, r, cs, userCtx, permission, errTargetNotFound, defaultDenyMessage)
		return
	}
	_ = secret
}`,
	}
	for name, src := range middlewareRed {
		if got := scanFoldedReadsInSource(t, "auth.go", src); len(got) != 1 {
			t.Errorf("middleware %s: want exactly one fold hit, got %+v", name, got)
		}
	}

	green := map[string]string{
		// The fixed machineInProject: the helper classifies, the mismatch is its own branch.
		"helper shape": `package core
func (c *K) machineInProject(ctx context.Context, projectID, machineID uint) (*M, error) {
	m, err := c.storage.GetMachineIdentity(ctx, machineID)
	if err != nil {
		return nil, classifyReadError(err, "machine identity not found")
	}
	if m.ProjectID != projectID {
		return nil, fmt.Errorf("machine identity not found")
	}
	return m, nil
}`,
		// verifyAccessReviewGrantExists after the fix: the first if classifies and returns the
		// fault; the second can only be reached by a positive not-found or a mismatch.
		"classified first, verdict second": `package core
func (c *K) verify() error {
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil && !isPositiveNotFound(err) {
		return classifyReadError(err, "could not be read")
	}
	if err != nil || secret == nil || secret.ProjectID != projectID {
		return fmt.Errorf("%s: %s", i18n.T("ErrorNotFound", nil), "stale")
	}
	return nil
}`,
		// ResolveSecretRef since STORAGE-ERR-CLASS-4.
		"ResolveSecretRef classifies with isPositiveNotFound": `package core
func (c *K) ResolveSecretRef(ctx context.Context, ref string) (*M, error) {
	secret, err := c.storage.GetSecretByName(ctx, name, projectID, envID)
	if err != nil {
		if isPositiveNotFound(err) {
			return nil, ErrSecretRefNotFound
		}
		return nil, err
	}
	return secret, nil
}`,
		"errors.Is classification": `package core
func (c *K) get() error {
	_, err := c.storage.GetThing(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("thing not found")
		}
		return err
	}
	return nil
}`,
		"typed predicate": `package core
func (c *K) get() error {
	_, err := c.storage.GetUser(ctx, id)
	if err != nil {
		if storage.IsUserNotFound(err) {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("lookup failed: %w", err)
	}
	return nil
}`,
		"error wrapped with %w": `package core
func (c *K) get() error {
	_, err := c.storage.GetProject(ctx, id)
	if err != nil {
		return fmt.Errorf("project %d not found: %w", id, err)
	}
	return nil
}`,
		"verdict is not a not-found": `package core
func (c *K) get() error {
	_, err := c.storage.GetThing(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to read thing")
	}
	return nil
}`,
		"err is not from a storage read": `package core
func (c *K) parse() error {
	_, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("value not found")
	}
	return nil
}`,
		"err reassigned by a non-read": `package core
func (c *K) get() error {
	_, err := c.storage.GetThing(ctx, id)
	_ = err
	err = validate(x)
	if err != nil {
		return fmt.Errorf("thing not found")
	}
	return nil
}`,
	}
	for name, src := range green {
		if got := scanFoldedReadsInSource(t, "machine_token.go", src); len(got) != 0 {
			t.Errorf("%s: want no hit, got %+v", name, got)
		}
	}
	middlewareGreen := map[string]string{
		// ScopeFromDynamicSecretLeaseParam since STORAGE-ERR-CLASS-2.
		"resolver classifies with core.ReadFault": `package middleware
func ScopeFromDynamicSecretLeaseParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		lease, err := cs.GetDynamicSecretLease(r.Context(), leaseID)
		if err != nil {
			if fault := core.ReadFault(err); fault != nil {
				return core.Scope{}, fmt.Errorf("%w: %w", errTargetReadFault, fault)
			}
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: lease.ProjectID}, nil
	}
}`,
		"gate classifies before handing the verdict on": `package middleware
func handleScopedSecretPermissionRequest(w http.ResponseWriter, r *http.Request) {
	secret, err := cs.Storage().GetSecret(r.Context(), secretID)
	if err != nil {
		resolveErr := errTargetNotFound
		if fault := core.ReadFault(err); fault != nil {
			resolveErr = fmt.Errorf("%w: %w", errTargetReadFault, fault)
		}
		handleScopeResolutionError(w, r, cs, userCtx, permission, resolveErr, defaultDenyMessage)
		return
	}
	_ = secret
}`,
		"unparseable target is not a read": `package middleware
func ScopeFromEnvParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{EnvironmentID: id}, nil
	}
}`,
	}
	for name, src := range middlewareGreen {
		if got := scanFoldedReadsInSource(t, "auth.go", src); len(got) != 0 {
			t.Errorf("middleware %s: want no hit, got %+v", name, got)
		}
	}
}

func TestNoStorageReadErrorFoldedIntoNotFound(t *testing.T) {
	g := guardrules.Rollout(t)
	var hits []foldedRead
	files := 0
	for _, path := range coreFamilySources(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files++
		hits = append(hits, scanFoldedReads(fset, f, srcpath.CoreFamilyRel(path))...)
	}
	// A floor on what the scanner walks, so a matcher that silently stops matching cannot
	// leave a green guard: the registered exceptions are folds the scanner must still see.
	if files < 50 {
		t.Fatalf("scanned only %d core-family files; the source walk has stopped matching", files)
	}
	// The REST scope resolvers (STORAGE-ERR-CLASS-3), named file by file: a directory listing
	// here would be an ad-hoc core-dir walk (TestNoAdHocCoreDirListing).
	for _, rel := range foldedReadMiddlewareFiles {
		path := filepath.Join(srcpath.RepoRoot(), filepath.FromSlash(foldedReadMiddlewareDir), rel)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		hits = append(hits, scanFoldedReads(fset, f, "middleware/"+rel)...)
	}

	used := map[string]bool{}
	var msgs []string
	for _, d := range hits {
		if _, ok := foldedReadExceptions[d.key()]; ok {
			used[d.key()] = true
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s:%d in %s reports a failed %s as a not-found verdict", d.File, d.Line, d.Func, d.Callee))
	}
	sort.Strings(msgs)
	for _, m := range msgs {
		g.Errorf("%s: a storage fault (outage, timeout, scan error) then reads as \"already gone\" and the operator does not retry. "+
			"Classify it with classifyReadError / credentialLookupError (a positive not-found keeps the verdict, anything else is "+
			"ErrStorageReadUnavailable; in server/middleware, core.ReadFault -> errTargetReadFault), or add a storage_read_error_folded_exception_<name>_test.go calling "+
			"registerFoldedReadException with the reason the fold is safe", m)
	}
	for key, why := range foldedReadExceptions {
		if !used[key] {
			g.Errorf("exception %q (%s) matches no fold any more: delete its file", key, why)
		}
	}
}
