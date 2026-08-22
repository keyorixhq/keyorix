// remote_wire_route_coverage_test.go — G80 follow-up (issue tracked separately, see
// the PR description): CreateSecretVersion's wire target (POST /api/v1/secrets/{id}/
// versions) turned out to have no matching router.go registration at all — a RemoteStorage
// call that 404/405s on every attempt, discovered only by accident while testing G80 Phase
// 0. This guard statically cross-checks EVERY RemoteStorage wire call's (method, path
// template) against router.go's actual route registrations, so a missing route is a build-
// time test failure instead of a silent runtime 404/405 the next person finds by accident.
//
// This is a coverage guard, not a correctness guard: a route existing doesn't mean it does
// the right thing (see G80 Phase 0 itself — the route existed but silently dropped fields).
// It only proves the wire call has SOMEWHERE to land.
//
// Fail-closed on the tool's own blind spot: a wire call whose path this AST-based
// extractor cannot statically resolve (string concatenation, a url.Values query builder,
// a caller-supplied parameter — see knownUnresolvedWireCalls) is NOT silently skipped.
// Skipping would let the guard stay green while its coverage quietly shrank as new
// dynamic-path calls were added — exactly the kind of gap that let 13+ missing routes go
// unnoticed in the first place. Every unresolvable call must be named in
// knownUnresolvedWireCalls (visible backlog under #1511) or the test fails.
package store_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// routeKey is a normalized (HTTP method, path template) pair. Path parameters are
// collapsed to "*" so a chi pattern ("/{id}/versions") and a Sprintf-built client path
// ("/api/v1/secrets/%d/versions") compare equal once normalized.
type routeKey struct {
	Method string
	Path   string
}

func (k routeKey) String() string { return k.Method + " " + k.Path }

var (
	chiParamRe    = regexp.MustCompile(`\{[^}]+\}`)
	sprintfVerbRe = regexp.MustCompile(`%[a-zA-Z0-9.]*[a-zA-Z]`)
	httpMethods   = map[string]bool{"Get": true, "Post": true, "Put": true, "Patch": true, "Delete": true}
)

// stripTrailingSlash drops a single trailing "/" (but never reduces a path to empty) —
// chi treats r.Get("/", h) inside Route("/roles", ...) as matching "/roles" itself, not
// a distinct "/roles/" segment, so "/api/v1/roles/" and "/api/v1/roles" must normalize
// to the same key or every group's own index route (GET/POST "/") false-positives as
// missing.
func stripTrailingSlash(p string) string {
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		return p[:len(p)-1]
	}
	return p
}

// stripQuery drops a "?..." suffix — chi route patterns never include query strings
// (query params are read separately via r.URL.Query()), but several RemoteStorage wire
// calls build their path with the query string baked directly into the same fmt.Sprintf
// (e.g. GetSecretByName's "/api/v1/secrets/by-name?name=%s&project_id=%d..."). Without
// stripping this, every such call false-positives as a missing route.
func stripQuery(p string) string {
	before, _, _ := strings.Cut(p, "?")
	return before
}

func normalizeChiPath(p string) string {
	return stripTrailingSlash(stripQuery(chiParamRe.ReplaceAllString(p, "*")))
}
func normalizeSprintfPath(f string) string {
	return stripTrailingSlash(stripQuery(sprintfVerbRe.ReplaceAllString(f, "*")))
}

// extractRouterRoutes parses server/http/router.go and returns every (method, path)
// pair actually registered with chi, resolving nested r.Route("/prefix", func(r
// chi.Router) {...}) groups (and prefix-less r.Group(func(r chi.Router) {...}) groups)
// to their full absolute path. Path arguments given as a package-level const
// (router.go declares a block of shared fragments — pathIDRoles, pathProjectsID, etc.
// — reused across many registrations) are resolved via constPaths, not just inline
// string literals.
func extractRouterRoutes(t *testing.T, path string) map[routeKey]bool {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	constPaths := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			s, _ := unquote(lit.Value)
			constPaths[vs.Names[0].Name] = s
		}
	}
	// resolvePathArg resolves a call argument to its literal string: a direct BasicLit,
	// an Ident referring to one of router.go's own path constants, or a "left + right"
	// concatenation of two further-resolvable expressions (e.g.
	// pathRiskExceptionsID+"/revoke" — router.go:1684/1685, the exact shape that hid
	// RevokeRiskExceptionProxy/ApproveRiskExceptionProxy from this guard entirely: a
	// route registered with a real, correct path was invisible here because the argument
	// wasn't a literal or a bare constant reference. Recursive so a chain of more than
	// two operands still resolves.
	var resolvePathArg func(arg ast.Expr) (string, bool)
	resolvePathArg = func(arg ast.Expr) (string, bool) {
		switch e := arg.(type) {
		case *ast.BasicLit:
			if e.Kind != token.STRING {
				return "", false
			}
			return unquote(e.Value)
		case *ast.Ident:
			s, ok := constPaths[e.Name]
			return s, ok
		case *ast.BinaryExpr:
			if e.Op != token.ADD {
				return "", false
			}
			left, ok := resolvePathArg(e.X)
			if !ok {
				return "", false
			}
			right, ok := resolvePathArg(e.Y)
			if !ok {
				return "", false
			}
			return left + right, true
		}
		return "", false
	}

	routes := map[routeKey]bool{}

	var walkBlock func(prefix string, body *ast.BlockStmt)
	var walkCall func(prefix string, expr ast.Expr)

	walkBlock = func(prefix string, body *ast.BlockStmt) {
		if body == nil {
			return
		}
		for _, stmt := range body.List {
			exprStmt, ok := stmt.(*ast.ExprStmt)
			if !ok {
				continue
			}
			walkCall(prefix, exprStmt.X)
		}
	}

	// walkCall inspects one top-level call expression in a router-setup block: either a
	// nested r.Route/r.Group, or a (possibly r.With(...)-chained) HTTP-method registration.
	walkCall = func(prefix string, expr ast.Expr) {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}

		switch sel.Sel.Name {
		case "Route":
			// r.Route("/sub", func(r chi.Router) { ... })
			if len(call.Args) != 2 {
				return
			}
			sub, ok := resolvePathArg(call.Args[0])
			if !ok {
				return
			}
			fn, ok := call.Args[1].(*ast.FuncLit)
			if !ok {
				return
			}
			walkBlock(prefix+sub, fn.Body)
			return
		case "Group":
			// r.Group(func(r chi.Router) { ... }) — no path segment added.
			if len(call.Args) != 1 {
				return
			}
			fn, ok := call.Args[0].(*ast.FuncLit)
			if !ok {
				return
			}
			walkBlock(prefix, fn.Body)
			return
		}

		if httpMethods[sel.Sel.Name] {
			if len(call.Args) < 1 {
				return
			}
			p, ok := resolvePathArg(call.Args[0])
			if !ok {
				return
			}
			method := strings.ToUpper(sel.Sel.Name)
			routes[routeKey{Method: method, Path: normalizeChiPath(prefix + p)}] = true
			return
		}

		// Not a leaf registration or a recognized group — the receiver might itself be a
		// chained call (r.With(...).Patch(...)); recurse into it in case Sel.X hides
		// another Route/Group we should still walk (defensive; chi's fluent API rarely
		// nests this way for Route/Group specifically, but costs nothing to check).
		walkCall(prefix, sel.X)
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// walkBlock (not ast.Inspect) at the top level: walkBlock/walkCall already
		// recurse into nested r.Route/r.Group func literals with the correctly
		// accumulated prefix. Using ast.Inspect here too would ALSO independently
		// descend into those same nested literals with an empty prefix, producing
		// bogus truncated-prefix "routes" (e.g. "/*/versions" instead of
		// "/api/v1/secrets/*/versions") that can accidentally collide with a wire
		// call's normalized template and mask a genuinely missing route.
		walkBlock("", fn.Body)
	}
	return routes
}

// wireCall records one RemoteStorage wire call site, for failure reporting.
type wireCall struct {
	File   string
	Line   int
	Method string
	Path   string // normalized template; empty when Resolved is false
	// Resolved is false when the call was found (rs.client.<Method>(...) or a
	// staticMethod-resolvable Request(...)) but its path argument could not be
	// statically resolved to a literal/Sprintf/local-var template — e.g. a path built
	// via string concatenation, a helper function's return value, or a struct field.
	// These are NOT skipped silently (see extractWireCallsInFunc's doc comment): they
	// are exactly the calls a coverage check is most likely to miss a genuine route
	// gap on, since nobody can eyeball-verify a dynamically-built path the way a
	// literal one can be. TestRemoteStorageWireCalls_HaveMatchingRoute fails on any
	// unresolved call not already named in knownUnresolvedWireCalls.
	Resolved bool
}

// storeGoFiles globs every non-test .go file directly in dir (internal/storage/store,
// no recursion needed — the package has no subdirectories of its own source). Broadened
// from a "remote_*.go" glob (2026-08 hardening, #1511): entry.go defines
// putConditionalTransition, a helper RemoteStorage.RevokeRiskExceptionIfNotRevoked/
// ApproveRiskExceptionIfPending call instead of rs.client.Put directly -- a
// "remote_*.go"-only glob never even PARSED entry.go, so putConditionalTransition's own
// rs.client.Put call, and both of ITS callers, were invisible to this guard entirely, not
// merely "found but unresolvable". A wire-issuing helper can live in any file; only the
// rs.client.X()-shaped call-matching in extractWireCallsInFunc (and the rs.<wrapper>()
// matching added alongside it) determines what counts, so widening the glob costs
// nothing -- unrelated files (LocalStorage's ls-receiver methods, etc.) contribute no
// matches since the matcher requires a literal "rs" receiver.
func storeGoFiles(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("globbing %s: %v", dir, err)
	}
	var out []string
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		out = append(out, path)
	}
	return out
}

// wrapperInfo describes a *RemoteStorage method whose body issues exactly one
// rs.client.{Get,Post,Put,Delete,Request} call using ONE OF ITS OWN PARAMETERS as the
// path (and, for Request, possibly the method too) -- e.g. putConditionalTransition(ctx,
// path, body, opName) internally calling rs.client.Put(ctx, path, body). A call to such a
// method elsewhere (rs.putConditionalTransition(ctx, someExpr, ...)) is exactly as much a
// wire call as a direct rs.client.Put(...) would be, just one level of indirection away --
// see findWrapperMethods.
type wrapperInfo struct {
	HTTPMethod       string // fixed method the wrapper always uses ("" if MethodParamIndex >= 0 instead)
	PathParamIndex   int    // index into the wrapper's own parameter list (0-based, ctx counts)
	MethodParamIndex int    // index of a method-string parameter, or -1 if HTTPMethod is fixed
}

// findWrapperMethods scans every FuncDecl across files for a *RemoteStorage receiver
// method whose body contains exactly one rs.client.{Get,Post,Put,Delete,Request} call
// where the path argument (and, for Request, the method argument) is an *ast.Ident
// matching one of the enclosing function's OWN parameters -- i.e. the method is a thin
// forwarder, not itself hardcoding a fixed path. A function with more than one such call,
// or whose call's path isn't traceable to a parameter, is not treated as a wrapper (its
// call sites fall through to the normal "unresolvable" bucket instead, which is the safe
// default: this optimistically recognizes ONLY the unambiguous forwarding shape).
func findWrapperMethods(fset *token.FileSet, files []*ast.File) map[string]wrapperInfo {
	wrappers := map[string]wrapperInfo{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			recvType, ok := star.X.(*ast.Ident)
			if !ok || recvType.Name != "RemoteStorage" {
				continue
			}
			if len(fn.Recv.List[0].Names) != 1 || fn.Recv.List[0].Names[0].Name != "rs" {
				continue
			}

			paramIndex := map[string]int{}
			idx := 0
			for _, field := range fn.Type.Params.List {
				for _, name := range field.Names {
					paramIndex[name.Name] = idx
					idx++
				}
			}

			var found *wrapperInfo
			multiple := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv, ok := sel.X.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recvIdent, ok := recv.X.(*ast.Ident)
				if !ok || recv.Sel.Name != "client" || recvIdent.Name != "rs" {
					return true
				}
				var info wrapperInfo
				switch sel.Sel.Name {
				case "Get", "Delete", "Post", "Put":
					if len(call.Args) < 2 {
						return true
					}
					id, ok := call.Args[1].(*ast.Ident)
					if !ok {
						return true
					}
					pIdx, ok := paramIndex[id.Name]
					if !ok {
						return true
					}
					info = wrapperInfo{HTTPMethod: strings.ToUpper(sel.Sel.Name), PathParamIndex: pIdx, MethodParamIndex: -1}
				case "Request":
					if len(call.Args) < 3 {
						return true
					}
					pathID, ok := call.Args[2].(*ast.Ident)
					if !ok {
						return true
					}
					pIdx, ok := paramIndex[pathID.Name]
					if !ok {
						return true
					}
					info = wrapperInfo{PathParamIndex: pIdx, MethodParamIndex: -1}
					if methodID, ok := call.Args[1].(*ast.Ident); ok {
						if mIdx, ok := paramIndex[methodID.Name]; ok {
							info.MethodParamIndex = mIdx
						}
					}
					if info.MethodParamIndex < 0 {
						if m, ok := staticMethod(call.Args[1]); ok {
							info.HTTPMethod = m
						} else {
							return true // method neither a wrapper param nor statically known
						}
					}
				default:
					return true
				}
				if found != nil {
					multiple = true
					return true
				}
				found = &info
				return true
			})
			if found != nil && !multiple {
				wrappers[fn.Name.Name] = *found
			}
		}
	}
	return wrappers
}

// extractWireCalls parses every internal/storage/store/*.go file (see storeGoFiles) and
// returns every rs.client.{Get,Post,Put,Delete}(ctx, path, ...) / rs.client.Request(ctx,
// method, path, ...) call site, PLUS every call to a method findWrapperMethods identified
// as a thin wire-call forwarder. Resolved per FuncDecl (not blanket over the whole file)
// so a "path := fmt.Sprintf(...)" local-variable assignment — the majority shape in this
// codebase, e.g. UpdateSecret's own "path := fmt.Sprintf(\"/api/v1/secrets/%d\",
// secret.ID)" — is tracked and substituted at its later "rs.client.Post(ctx, path, ...)"
// use, not silently skipped as an unresolvable identifier.
func extractWireCalls(t *testing.T, dir string) []wireCall {
	t.Helper()
	paths := storeGoFiles(t, dir)
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(paths))
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		files = append(files, file)
	}

	wrappers := findWrapperMethods(fset, files)

	var calls []wireCall
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			calls = append(calls, extractWireCallsInFunc(fset, fn, wrappers)...)
		}
	}
	return calls
}

// extractWireCallsInFunc resolves wire calls within a single function, tracking
// "name := <resolvable path expr>" local assignments along the way. wrappers is the
// package-wide registry from findWrapperMethods, so a call to rs.<wrapperName>(...) is
// recognized as a wire call too, not just direct rs.client.X(...) calls.
func extractWireCallsInFunc(fset *token.FileSet, fn *ast.FuncDecl, wrappers map[string]wrapperInfo) []wireCall {
	localPaths := map[string]string{}
	var calls []wireCall

	resolvePath := func(arg ast.Expr) (string, bool) {
		if p, ok := pathTemplate(arg); ok {
			return p, true
		}
		if id, ok := arg.(*ast.Ident); ok {
			if p, ok := localPaths[id.Name]; ok {
				return p, true
			}
		}
		return "", false
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		// Track "name := fmt.Sprintf(...)" / "name := \"literal\"" (define only — token.DEFINE)
		// so a later rs.client.X(ctx, name, ...) can resolve it. A subsequent "name +=
		// fmt.Sprintf(...)" / "name = ..." reassignment (the query-string-building pattern
		// several ListX methods use, e.g. ListRotationPolicies' appendParam closure) is
		// deliberately NOT tracked: query strings are stripped by normalizeChiPath/
		// normalizeSprintfPath anyway, so the base path from the initial := is already the
		// correct final template — accumulating "+=" fragments naively (the first attempt
		// here) instead OVERWROTE the base path with only the LAST appended fragment
		// ("&*=*"), a wrong result, not just an incomplete one.
		if assign, ok := n.(*ast.AssignStmt); ok && assign.Tok == token.DEFINE &&
			len(assign.Lhs) == 1 && len(assign.Rhs) == 1 {
			if id, ok := assign.Lhs[0].(*ast.Ident); ok {
				if p, ok := pathTemplate(assign.Rhs[0]); ok {
					localPaths[id.Name] = p
				}
			}
		}

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		// rs.<wrapperName>(...) -- a call to a method findWrapperMethods identified as a
		// thin forwarder to rs.client.X (e.g. rs.putConditionalTransition(ctx, path, ...)).
		// Checked before the rs.client.X shape below since the receiver here is a plain
		// Ident ("rs"), not the nested rs.client SelectorExpr that shape requires.
		if recvIdent, ok := sel.X.(*ast.Ident); ok && recvIdent.Name == "rs" {
			if info, ok := wrappers[sel.Sel.Name]; ok {
				pos := fset.Position(call.Pos())
				if info.PathParamIndex >= len(call.Args) {
					return true
				}
				method := info.HTTPMethod
				if info.MethodParamIndex >= 0 {
					if info.MethodParamIndex >= len(call.Args) {
						return true
					}
					if m, ok := staticMethod(call.Args[info.MethodParamIndex]); ok {
						method = m
					} else {
						calls = append(calls, wireCall{File: pos.Filename, Line: pos.Line})
						return true
					}
				}
				if p, ok := resolvePath(call.Args[info.PathParamIndex]); ok {
					calls = append(calls, wireCall{File: pos.Filename, Line: pos.Line, Method: method, Path: p, Resolved: true})
				} else {
					calls = append(calls, wireCall{File: pos.Filename, Line: pos.Line, Method: method})
				}
				return true
			}
		}

		recv, ok := sel.X.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		recvIdent, ok := recv.X.(*ast.Ident)
		if !ok || recv.Sel.Name != "client" || recvIdent.Name != "rs" {
			return true
		}

		pos := fset.Position(call.Pos())
		switch sel.Sel.Name {
		case "Get", "Delete":
			if len(call.Args) < 2 {
				return true
			}
			method := strings.ToUpper(sel.Sel.Name)
			if p, ok := resolvePath(call.Args[1]); ok {
				calls = append(calls, wireCall{File: pos.Filename, Line: pos.Line, Method: method, Path: p, Resolved: true})
			} else {
				calls = append(calls, wireCall{File: pos.Filename, Line: pos.Line, Method: method})
			}
		case "Post", "Put":
			if len(call.Args) < 2 {
				return true
			}
			method := strings.ToUpper(sel.Sel.Name)
			if p, ok := resolvePath(call.Args[1]); ok {
				calls = append(calls, wireCall{File: pos.Filename, Line: pos.Line, Method: method, Path: p, Resolved: true})
			} else {
				calls = append(calls, wireCall{File: pos.Filename, Line: pos.Line, Method: method})
			}
		case "Request":
			// rs.client.Request(ctx, method, path, body) — method may be a string
			// literal or an http.MethodX selector; either way, an unresolvable METHOD
			// (a variable) still gets recorded (Method left blank) so it counts toward
			// the unresolved total rather than vanishing silently — only the specific
			// (method, path) pair is unknown, not the call's existence.
			if len(call.Args) < 3 {
				return true
			}
			method, methodOK := staticMethod(call.Args[1])
			p, pathOK := resolvePath(call.Args[2])
			if methodOK && pathOK {
				calls = append(calls, wireCall{File: pos.Filename, Line: pos.Line, Method: method, Path: p, Resolved: true})
			} else {
				calls = append(calls, wireCall{File: pos.Filename, Line: pos.Line, Method: method})
			}
		}
		return true
	})
	return calls
}

// pathTemplate resolves a path argument expression to a normalized template: a plain
// string literal, or fmt.Sprintf("format", ...) with its verbs collapsed to "*".
func pathTemplate(arg ast.Expr) (string, bool) {
	switch e := arg.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, _ := unquote(e.Value)
		return normalizeChiPath(s), true
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Sprintf" {
			return "", false
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "fmt" || len(e.Args) < 1 {
			return "", false
		}
		lit, ok := e.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "", false
		}
		s, _ := unquote(lit.Value)
		return normalizeSprintfPath(s), true
	}
	return "", false
}

// staticMethod resolves an HTTP-method argument to its string value: a literal
// ("GET") or a recognized http.MethodX selector.
func staticMethod(arg ast.Expr) (string, bool) {
	switch e := arg.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, _ := unquote(e.Value)
		return strings.ToUpper(s), true
	case *ast.SelectorExpr:
		pkg, ok := e.X.(*ast.Ident)
		if !ok || pkg.Name != "http" {
			return "", false
		}
		if v, ok := strings.CutPrefix(e.Sel.Name, "Method"); ok {
			return strings.ToUpper(v), true
		}
	}
	return "", false
}

func unquote(lit string) (string, bool) {
	if len(lit) < 2 {
		return lit, false
	}
	return lit[1 : len(lit)-1], true
}

// TestRemoteStorageWireCalls_HaveMatchingRoute cross-checks every statically-resolvable
// RemoteStorage wire call against router.go's registered routes. A wire call whose
// (method, normalized path) has no matching registration is guaranteed to 404/405 on
// every real attempt — exactly the CreateSecretVersion gap this guard exists to catch.
//
// Unresolvable call sites (a path built via concatenation, a helper's return value, a
// struct field — not a literal/Sprintf/local-var-from-one) are NOT silently skipped: a
// dynamically-built path is exactly where a human reviewer is LEAST likely to notice a
// route mismatch by eye, so treating "can't statically check" the same as "checked and
// fine" would leave the biggest blind spot invisible. Every unresolved call site must be
// named in knownUnresolvedWireCalls (triaged under #1511) or the test fails — this makes
// the tool's blind spot a visible, enumerated backlog instead of a silent gap that stays
// green as new dynamic-path calls are added.
func TestRemoteStorageWireCalls_HaveMatchingRoute(t *testing.T) {
	routerPath := filepath.Join("..", "..", "..", "server", "http", "router.go")
	routes := extractRouterRoutes(t, routerPath)
	if len(routes) < 50 {
		t.Fatalf("extractRouterRoutes found only %d routes — the AST walk likely broke silently "+
			"(router.go has hundreds of registrations); fix the walker before trusting this guard", len(routes))
	}

	calls := extractWireCalls(t, ".")
	if len(calls) < 50 {
		t.Fatalf("extractWireCalls found only %d wire calls — the AST walk likely broke silently; "+
			"fix the extractor before trusting this guard", len(calls))
	}

	seenMissing := map[routeKey]bool{}
	var unknownMissing []string
	seenUnresolved := map[string]bool{}
	var unknownUnresolved []string
	for _, c := range calls {
		loc := fmt.Sprintf("%s:%d", filepath.Base(c.File), c.Line)
		if !c.Resolved {
			seenUnresolved[loc] = true
			if !knownUnresolvedWireCalls[loc] {
				unknownUnresolved = append(unknownUnresolved, fmt.Sprintf("%s (method=%s, path unresolvable — "+
					"triage under https://github.com/keyorixhq/keyorix/issues/1511 and add to knownUnresolvedWireCalls, "+
					"or make the path statically resolvable)", loc, c.Method))
			}
			continue
		}
		key := routeKey{Method: c.Method, Path: c.Path}
		if routes[key] {
			continue
		}
		seenMissing[key] = true
		if !knownMissingRoutes[key] {
			unknownMissing = append(unknownMissing, fmt.Sprintf("%s:%d — %s (no matching router.go registration, "+
				"and not in knownMissingRoutes — file/update https://github.com/keyorixhq/keyorix/issues/1511)",
				filepath.Base(c.File), c.Line, key))
		}
	}
	sort.Strings(unknownMissing)
	if len(unknownMissing) > 0 {
		t.Errorf("%d NEW RemoteStorage wire call(s) have no matching route in router.go — each will "+
			"404/405 on every real attempt:\n%s", len(unknownMissing), strings.Join(unknownMissing, "\n"))
	}

	sort.Strings(unknownUnresolved)
	if len(unknownUnresolved) > 0 {
		t.Errorf("%d NEW unresolvable RemoteStorage wire call(s) — not yet triaged, cannot be checked "+
			"against router.go at all, and the dynamic path shape makes a manual miss likely:\n%s",
			len(unknownUnresolved), strings.Join(unknownUnresolved, "\n"))
	}

	var staleUnresolved []string
	for loc := range knownUnresolvedWireCalls {
		if !seenUnresolved[loc] {
			staleUnresolved = append(staleUnresolved, loc)
		}
	}
	sort.Strings(staleUnresolved)
	if len(staleUnresolved) > 0 {
		t.Errorf("%d knownUnresolvedWireCalls entries no longer reproduce (the call became statically "+
			"resolvable, or was removed/changed) — remove from the allowlist:\n%s",
			len(staleUnresolved), strings.Join(staleUnresolved, "\n"))
	}

	var stale []string
	for key := range knownMissingRoutes {
		if !seenMissing[key] {
			stale = append(stale, key.String())
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%d knownMissingRoutes entries no longer reproduce (the route now exists, or the wire call "+
			"changed/was removed) — remove from the allowlist and close the corresponding item in "+
			"https://github.com/keyorixhq/keyorix/issues/1511:\n%s", len(stale), strings.Join(stale, "\n"))
	}
}

// knownUnresolvedWireCalls is the set of RemoteStorage wire call sites (as of this
// writing) whose path argument this tool cannot statically resolve — almost entirely
// paths built via string concatenation with a caller-supplied parameter or a
// url.Values query builder, rather than a literal/fmt.Sprintf/local-var-from-one (see
// pathTemplate). NONE of these have been individually verified against router.go —
// that triage is tracked as visible backlog in
// https://github.com/keyorixhq/keyorix/issues/1511, not decided here. This allowlist
// exists so an unresolvable call is a visible, enumerated, must-be-triaged item
// instead of a silent gap: TestRemoteStorageWireCalls_HaveMatchingRoute fails on any
// NEW unresolvable call not listed here, and fails on any entry here that no longer
// reproduces (became resolvable or was removed) — so this list can't silently drift
// from reality in either direction, matching knownMissingRoutes' own discipline.
var knownUnresolvedWireCalls = map[string]bool{
	// putConditionalTransition's OWN rs.client.Put call (entry.go) — path is a plain
	// parameter, genuinely unresolvable without seeing a specific caller. Each CALLER
	// (RevokeRiskExceptionIfNotRevoked, ApproveRiskExceptionIfPending, remote_risk_
	// exceptions.go) resolves independently via the wrapper-forwarding mechanism
	// (findWrapperMethods) and is checked against router.go normally — this entry is
	// only the wrapper definition itself, not a second copy of those two calls.
	"entry.go:160":                            true,
	"remote_access_activity.go:64":            true,
	"remote_access_review_campaigns.go:210":   true,
	"remote_access_review_campaigns.go:237":   true,
	"remote_access_review_campaigns.go:263":   true,
	"remote_audit.go:28":                      true,
	"remote_audit.go:53":                      true,
	"remote_audit.go:95":                      true,
	"remote_auth.go:317":                      true,
	"remote_break_glass.go:175":               true,
	"remote_connector_project_bindings.go:63": true,
	"remote_dynamic.go:279":                   true,
	"remote_dynamic.go:387":                   true,
	"remote_dynamic.go:414":                   true,
	"remote_dynamic.go:455":                   true,
	"remote_invitations.go:229":               true,
	"remote_invitations.go:396":               true,
	"remote_login_attempts.go:52":             true,
	"remote_machine_identities.go:344":        true,
	"remote_machine_identities.go:688":        true,
	"remote_memberships.go:211":               true,
	"remote_memberships.go:230":               true,
	"remote_memberships.go:247":               true,
	"remote_memberships.go:286":               true,
	"remote_mfa.go:169":                       true,
	"remote_mfa.go:294":                       true,
	"remote_rbac.go:497":                      true,
	"remote_rbac.go:850":                      true,
	"remote_rbac.go:1148":                     true,
	"remote_secret_dependencies.go:151":       true,
	"remote_secret_dependencies.go:171":       true,
	"remote_secrets.go:126":                   true,
	"remote_secrets.go:428":                   true,
	"remote_secrets.go:448":                   true,
	"remote_users.go:225":                     true,
	"remote_users.go:558":                     true,
	"remote_users.go:594":                     true,
	"remote_users.go:1018":                    true,
	"remote_webauthn.go:192":                  true,
	"remote_webauthn.go:222":                  true,
	"remote_webauthn.go:328":                  true,
}

// knownMissingRoutes is the set of RemoteStorage wire calls confirmed (as of this
// writing) to have no matching router.go route — tracked in
// https://github.com/keyorixhq/keyorix/issues/1511, triage and fix there, not here.
// A wire call must be REMOVED from this map once its route is registered (or the
// method is changed to return a clear "not supported" error) — TestRemoteStorageWireCalls_
// HaveMatchingRoute fails on any entry that no longer reproduces, so this can't silently
// go stale. Do not add a new entry here to silence a genuinely new gap — file it as its
// own issue-1511 item first.
var knownMissingRoutes = map[routeKey]bool{
	{Method: "POST", Path: "/api/v1/secrets/*/versions"}:                     true, // CreateSecretVersion — the G80 Phase 0 discovery
	{Method: "POST", Path: "/api/v1/sessions/cleanup"}:                       true,
	{Method: "POST", Path: "/api/v1/rbac/assign-role"}:                       true,
	{Method: "POST", Path: "/api/v1/rbac/remove-role"}:                       true,
	{Method: "PUT", Path: "/api/v1/system/risk-exceptions/*"}:                true,
	{Method: "POST", Path: "/api/v1/shares"}:                                 true, // confirmed real: /shares group has no POST
	{Method: "GET", Path: "/api/v1/shares/*"}:                                true, // confirmed real: /shares group has no GET/{id}
	{Method: "GET", Path: "/api/v1/stats"}:                                   true, // confirmed real: only scoped */stats variants exist
	{Method: "GET", Path: "/api/v1/secrets/*/versions/*"}:                    true,
	{Method: "GET", Path: "/api/v1/secrets/*/versions/latest"}:               true,
	{Method: "POST", Path: "/api/v1/secret-versions/*/increment-read-count"}: true,
	{Method: "GET", Path: "/api/v1/users/*/shared-secrets"}:                  true, // confirmed real: only GET /shared-secrets (caller's own) exists
	{Method: "GET", Path: "/api/v1/secrets/*/permissions"}:                   true,
}
