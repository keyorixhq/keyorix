// raw_audit_access_model_response_guard_test.go — structural guard for #2733
// (FIX-1): a handler must never marshal a raw internal/storage/models audit
// or access-log struct straight into an HTTP response. The historical bug
// (docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md, fixed by
// #2088) never named the raw type in the handler file at all — the leak was
// a field read (result.Events, already typed []*models.AuditEvent one layer
// up in internal/core) passed straight through. A plain text/AST-name sweep
// would not have caught that shape; this uses real type information
// (go/types, via golang.org/x/tools/go/packages) on every argument expression
// reaching sendSuccess/sendCreated, so it flags the VALUE'S STATIC TYPE
// regardless of how it got there — a field selector, a bare variable, a
// composite literal, or a map value.
//
// What this does NOT cover (stated per CLAUDE.md's "say what a mechanism
// silently skips"): gRPC responses (no production RPC returns either
// sensitiveRawModelTypes entry today — grep confirms zero non-test
// references in server/grpc) and sendError's `details` argument (error
// payloads have never carried either of these two types in this codebase;
// adding it in scope was more surface than this specific finding warranted).
// If either changes, this guard should be extended to match.
package handlers

import (
	"go/ast"
	"go/types"
	"sort"
	"testing"

	"golang.org/x/tools/go/packages"
)

// sensitiveRawModelTypes are the fully-qualified type names that must never
// be the static type of a value reaching sendSuccess/sendCreated. Scoped to
// #2733's two confirmed PII-leaking types, not the full 26-route casing/
// hygiene inventory in the finding doc (deliberately out of scope — see the
// issue's own "Scope note").
var sensitiveRawModelTypes = map[string]bool{
	"github.com/keyorixhq/keyorix/internal/storage/models.AuditEvent":      true,
	"github.com/keyorixhq/keyorix/internal/storage/models.SecretAccessLog": true,
}

// responseSendFuncNames are every function/method the handler family uses to
// write a success response body — httpx's SendSuccess/SendCreated (called
// qualified, httpx.SendSuccess, from the handler subpackages), their
// sendSuccess/sendCreated aliases in this package (httpx_aliases.go), and the
// per-handler-struct re-implementations (FolderHandler, RotationPolicyHandler,
// SecretHandler, ShareHandler) that shadow them with the identical
// (w, data, message) signature.
var responseSendFuncNames = map[string]bool{
	"sendSuccess": true,
	"sendCreated": true,
	"SendSuccess": true,
	"SendCreated": true,
}

// unwrapToNamed strips pointer/slice/array/map-value layers to reach the
// underlying named type, mirroring how a raw model struct is actually
// exposed in practice: directly, as *T, or as []T/[]*T.
func unwrapToNamed(t types.Type) *types.Named {
	for {
		switch x := t.(type) {
		case *types.Pointer:
			t = x.Elem()
		case *types.Slice:
			t = x.Elem()
		case *types.Array:
			t = x.Elem()
		case *types.Map:
			t = x.Elem()
		case *types.Named:
			return x
		default:
			return nil
		}
	}
}

func namedTypeFullName(n *types.Named) string {
	obj := n.Obj()
	if obj == nil || obj.Pkg() == nil {
		return obj.Name()
	}
	return obj.Pkg().Path() + "." + obj.Name()
}

// TestNoRawAuditOrAccessModelInHandlerResponse type-checks
// server/http/handlers and every handlerFamilySubdirs subpackage (httpx,
// reports) and fails if any expression reaching a sendSuccess/sendCreated
// (or httpx.SendSuccess/SendCreated) call has a static type (after stripping
// pointer/slice/array/map layers) matching sensitiveRawModelTypes.
func TestNoRawAuditOrAccessModelInHandlerResponse(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax,
		Dir:  ".",
	}
	patterns := []string{"."}
	for _, sub := range handlerFamilySubdirs {
		patterns = append(patterns, "./"+sub)
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatalf("package %v failed to type-check", pkgs)
	}
	if len(pkgs) != len(patterns) {
		t.Fatalf("expected %d packages (%v), got %d", len(patterns), patterns, len(pkgs))
	}

	var violations []string
	sendCalls := 0
	for _, pkg := range pkgs {
		sendCalls += rawModelResponseViolations(pkg, &violations)
	}
	// Population tripwire: the handler family writes hundreds of success
	// responses; a scan that sees almost none is looking in the wrong place.
	t.Logf("checked %d sendSuccess/sendCreated calls across %v", sendCalls, patterns)
	if sendCalls < 100 {
		t.Fatalf("saw only %d sendSuccess/sendCreated calls across %v: the scan is broken", sendCalls, patterns)
	}

	sort.Strings(violations)
	for _, v := range violations {
		t.Error(v)
	}
}

// rawModelResponseViolations appends to violations each response-send call in
// pkg with an argument whose static type is in sensitiveRawModelTypes, and
// returns how many response-send calls it saw.
func rawModelResponseViolations(pkg *packages.Package, violations *[]string) int {
	sendCalls := 0
	for _, file := range pkg.Syntax {
		fset := pkg.Fset
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var fname string
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				fname = fn.Name
			case *ast.SelectorExpr:
				fname = fn.Sel.Name
			}
			if !responseSendFuncNames[fname] {
				return true
			}
			sendCalls++
			for _, arg := range call.Args {
				ast.Inspect(arg, func(sub ast.Node) bool {
					expr, ok := sub.(ast.Expr)
					if !ok {
						return true
					}
					tv := pkg.TypesInfo.TypeOf(expr)
					if tv == nil {
						return true
					}
					named := unwrapToNamed(tv)
					if named == nil {
						return true
					}
					if sensitiveRawModelTypes[namedTypeFullName(named)] {
						pos := fset.Position(call.Pos())
						*violations = append(*violations, pos.String()+": "+fname+"(...) argument has static type "+namedTypeFullName(named))
					}
					return true
				})
			}
			return true
		})
	}
	return sendCalls
}
