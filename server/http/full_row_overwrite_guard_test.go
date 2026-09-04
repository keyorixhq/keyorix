// full_row_overwrite_guard_test.go — structural guard closing the class of
// bug UpdateUserIfActiveStateMatchesProxy and UpdateWebAuthnCredentialProxy
// both turned out to have: a caller-facing handler builds a *models.X struct
// LITERAL directly from a request body (a fresh, never-fetched struct with
// every field the request doesn't carry left at Go's zero value) and passes
// it straight into a storage-layer method that does an unconditional
// full-row overwrite (Select("*").Updates(...) or a plain Save(...)). Every
// field the request doesn't carry gets silently zeroed on persist -- this
// was PasswordHash and AccountState in the confirmed instance, and account
// takeover, not just data loss, once AccountState was one of them.
//
// Population derivation (a full repo sweep, not just this package's own
// prior narrower one): every internal/storage/store method whose GORM call
// combines Select("*") with .Updates(...), plus every method whose GORM call
// is a plain, unconditional .Save(...) on a caller-supplied struct -- 9 of
// the former, ~15 of the latter (three of those, UpdateProjectMembership/
// UpdateMachineIdentity/UpdateRiskException, are dead code with zero live
// callers and excluded here; they're covered by unsafeSiblingPairs above
// instead). Every current caller of every one of these methods, repo-wide,
// was individually read and confirmed fetch-first (SAFE) except exactly one:
// UpdateAnomalyConfig, an already-accepted, documented, non-security-critical
// design tradeoff (see anomaly_config.go's own comment) -- NOT caught by this
// guard's own detection; see "What this guard does not catch" below for why.
//
// Scope: server/http/handlers/*.go and server/grpc/services/*.go -- the
// caller-facing boundary layer where untrusted wire input first becomes a
// Go struct, which is where both real instances of this bug were found.
//
// Detection: a call of the form X.Storage().Method(ctx, &models.Y{...}) (or
// the "storage := ...Storage()" aliased form handlerBodyStorageCalls above
// already recognizes) where the argument is a composite-literal address
// expression, not an identifier -- UpdateWebAuthnCredentialProxy's and
// UpdateUserIfActiveStateMatchesProxy's original, real shape: a fresh
// &models.X{...} literal built directly from a decoded request body, passed
// straight into a full-row-overwrite call. A fetched-then-patched row is
// NEVER built as a literal at the call site -- it's always a variable
// (existing/row/etc.) by the time it reaches the call. Verified zero false
// positives against the current, fully-fixed tree.
//
// What this guard does NOT catch, and why not: an earlier draft also tried
// to flag a bare-identifier argument whenever the enclosing function
// contained no Get-/Find-/List-prefixed storage call anywhere in its own
// body (aimed at UpdateAnomalyConfig's shape: cfg arrives as a parameter,
// decoded from the wire two calls up, never fetched anywhere in the chain).
// That heuristic produced 7 false positives on the first real run --
// ClassifyMachineIdentity, ExtendExpiringSecrets, UpdateRole,
// expireInvitationIfOverdue, finalizeAccessRequestApproval,
// markWebAuthnCredentialClonedDisabled, revertFailedActivation -- every one
// a legitimate small helper that receives an ALREADY-fetched row as a
// parameter from a caller elsewhere in the same file that fetched it first.
// Distinguishing "helper receiving a caller's already-fetched row" from
// "wrapper blindly relaying an unfetched wire value" requires real call-graph
// tracing (does ANY caller, at any depth, fetch before calling this
// function?), not a single-function-body syntactic check -- exactly the kind
// of unreliable heuristic CLAUDE.md's own standing rule warns against ("a
// check that always fails is as useless as one that always passes... confirm
// it is green on a known-good case as well as red on a known-bad one"; this
// one wasn't green on seven known-good cases). Rather than ship a guard that
// forces workarounds for legitimate code, that pattern was dropped entirely.
// UpdateAnomalyConfig's own gap stays documented in anomaly_config.go, found
// and verified by hand (the repo-wide sweep this guard's population is
// derived from), not structurally enforced -- a real, acknowledged limit of
// this guard's coverage, not a silent gap.
package http

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fullRowOverwriteMethods is the storage.Storage method set whose
// implementation does NOT preserve unset fields on write -- passing a
// caller-built struct literal (rather than an existing, fetched row) is
// unsafe for every one of these, regardless of which specific fields the
// caller happened to populate.
var fullRowOverwriteMethods = map[string]bool{
	// Select("*") + .Updates(...) (conditional CAS writes, still full-row).
	"UpdateAccessReviewCampaign":       true,
	"UpdateAccessReviewItem":           true,
	"TransitionProjectMembershipState": true,
	"UpdateProjectInvitation":          true,
	"UpdateAccessRequest":              true,
	"TransitionMachineIdentityState":   true,
	"ApproveRiskExceptionIfPending":    true,
	"TransitionSecretStatus":           true,
	"UpdateUserIfActiveStateMatches":   true,
	// Plain, unconditional .Save(...).
	"UpdateMachineIdentityCredential": true,
	"UpdateRole":                      true,
	"UpdateBreakGlassActivation":      true,
	"UpdateProject":                   true,
	"UpdateWebAuthnCredential":        true,
	"UpdateSecretTemplate":            true,
	"UpdateRotationPolicy":            true,
	"UpdateLegalHold":                 true,
	"UpdateDynamicSecretConfig":       true,
	"UpdateDynamicSecretLease":        true,
	"UpdateSecret":                    true,
	"UpdateUser":                      true,
	"UpdateGroup":                     true,
	"SaveAnomalyConfig":               true,
}

// fullRowOverwriteAllowlist is the exhaustive, reasoned inventory of every
// caller-facing site that passes a struct literal directly into a
// fullRowOverwriteMethods call and has been individually verified safe
// despite that. Each entry needs a real reason;
// TestNoUnfetchedStructIntoFullRowOverwrite fails if a NEW site not in this
// list is found, or if a listed entry no longer reproduces.
// UpdateAnomalyConfig is NOT seeded here: this guard's detection (composite-
// literal or non-fetch-call-derived local arguments -- see the package doc's
// "What this guard does not catch" section) doesn't flag it, so an entry for
// it here would itself go stale (this guard's own staleness check below
// would flag it as "no longer makes a flagged call").
var fullRowOverwriteAllowlist = map[string]string{
	// TransitionMachineIdentityStateProxy: m := body.MachineIdentity.toModel()
	// is flagged because toModel() is a non-fetch call, but this is the
	// RemoteStorage HTTP-relay proxy (router.go's machine-identity storage-
	// primitive group, system.write-gated, internal server-to-server only --
	// see this file's own package doc and router.go:1284). The wire body it
	// decodes is NOT attacker-authored from scratch: it is the full row the
	// CALLING server's own internal/core.KeyorixCore already fetched via
	// LockMachineIdentityForUpdate (transitionMachineInTx, machine_identities.go)
	// or machineInProject (ClassifyMachineIdentity, machine_identities.go),
	// mutated only the fields that call legitimately changes, then serialized
	// whole over the wire for this proxy to relay onto local storage --
	// exactly the same "helper receiving a caller's already-fetched row"
	// shape as the 7 documented same-process false positives, one HTTP hop
	// removed. Unlike models.User's wire type (which deliberately omits
	// PasswordHash/AccountState), machineIdentityProxyWire.toModel() is a
	// verified 1:1 field mirror of models.MachineIdentity (machine_identities_
	// proxy.go) -- no field is silently dropped/zeroed by the relay itself.
	// Re-verified by hand during this guard's construction (2026-09-04).
	"TransitionMachineIdentityStateProxy": "RemoteStorage relay proxy: m is the caller's already-fetched-and-mutated row, serialized whole over the wire (1:1 field mirror, no drop), not an attacker-built struct -- see comment above.",
}

// TestNoUnfetchedStructIntoFullRowOverwrite is the preventive guard: for
// every function in server/http/handlers/*.go and server/grpc/services/*.go,
// if it calls Storage().<method>(ctx, &models.X{...}) for a method in
// fullRowOverwriteMethods with a composite-literal argument, that function
// must be in fullRowOverwriteAllowlist with a reasoned exception, or the
// test fails naming the function and the method it called unsafely.
func TestNoUnfetchedStructIntoFullRowOverwrite(t *testing.T) {
	dirs := []string{
		filepath.Join("..", "http", "handlers"),
		filepath.Join("..", "grpc", "services"),
		filepath.Join("..", "..", "internal", "core"),
	}

	flaggedFuncs := map[string]bool{}
	var flagged []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		fset := token.NewFileSet()
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", name, err)
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				for _, finding := range unfetchedStructOverwriteCalls(fd) {
					flaggedFuncs[fd.Name.Name] = true
					if _, ok := fullRowOverwriteAllowlist[fd.Name.Name]; ok {
						continue
					}
					flagged = append(flagged, fmt.Sprintf(
						"%s (%s) %s Storage().%s(...), a full-row overwrite -- fetch the existing row first and "+
							"patch only the fields this call site is legitimately allowed to change, or add a "+
							"reasoned entry to fullRowOverwriteAllowlist in this file",
						fd.Name.Name, name, finding.reason, finding.method))
				}
			}
		}
	}
	sort.Strings(flagged)
	if len(flagged) > 0 {
		t.Errorf("found %d unfetched-struct-into-full-row-overwrite site(s): %v", len(flagged), flagged)
	}

	var stale []string
	for fn := range fullRowOverwriteAllowlist {
		if !flaggedFuncs[fn] {
			stale = append(stale, fn+" (no longer makes a flagged call)")
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("fullRowOverwriteAllowlist entr(y/ies) no longer reproduce: %v\nRemove the entry -- its "+
			"exception no longer applies.", stale)
	}
}

// overwriteFinding is one flagged call: the storage method name, and a
// human-readable reason fragment describing which of the two patterns fired
// (spliced into TestNoUnfetchedStructIntoFullRowOverwrite's error message).
type overwriteFinding struct {
	method string
	reason string
}

// unfetchedStructOverwriteCalls walks fd's body for calls into a
// fullRowOverwriteMethods method, recognizing three storage-access forms:
// X.Storage().Method(...) (the handler-layer shape), storageAlias.Method(...)
// where storageAlias was assigned from X.Storage() earlier in the same body
// (handlerBodyStorageCalls's own second recognized form), and
// recv.storage.Method(...) -- the internal/core shape, a direct field access
// on the method's own receiver (no .Storage() call at all) -- so a future
// internal/core violation of this same shape is caught too, not just the
// handler-layer one.
//
// For each such call, a non-context argument is flagged if it is:
//   - a composite-literal address expression (&T{...}) inline at the call --
//     never the case for a fetched-then-patched row.
//   - a call expression that is not itself one of the three recognized
//     fetch-shaped (Get-/Find-/List-prefixed) storage-access forms above --
//     UpdateWebAuthnCredentialProxy's ORIGINAL real shape was exactly this:
//     Storage().UpdateWebAuthnCredential(ctx, body.toModel()), a wire-to-model
//     conversion call, not a fetch.
//   - a LOCAL variable (assigned somewhere in this same function body) whose
//     own most recent assignment is not one of the two safe shapes above
//     (i.e. it traces back to a composite literal or a non-fetch call, the
//     same two cases, just one assignment removed) -- UpdateUserIfActiveStateMatchesProxy's
//     ORIGINAL real shape: existing := &models.User{...} assigned first,
//     THEN existing passed by identifier.
//
// Deliberately NOT flagged: a bare identifier that is a FUNCTION PARAMETER,
// not a local variable. A parameter's provenance (was IT fetched by
// whichever caller passed it in) requires real interprocedural call-graph
// tracing, which this guard does not attempt -- see the package doc's "What
// this guard does not catch" section for why, and which known case that
// exempts.
func unfetchedStructOverwriteCalls(fd *ast.FuncDecl) []overwriteFinding {
	var recvName string
	if fd.Recv != nil && len(fd.Recv.List) == 1 && len(fd.Recv.List[0].Names) == 1 {
		recvName = fd.Recv.List[0].Names[0].Name
	}
	params := map[string]bool{}
	if fd.Type.Params != nil {
		for _, field := range fd.Type.Params.List {
			for _, n := range field.Names {
				params[n.Name] = true
			}
		}
	}

	aliases := map[string]bool{}
	isFetchCall := func(call *ast.CallExpr) bool {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if !strings.HasPrefix(sel.Sel.Name, "Get") && !strings.HasPrefix(sel.Sel.Name, "Find") && !strings.HasPrefix(sel.Sel.Name, "List") {
			return false
		}
		if inner, ok := sel.X.(*ast.CallExpr); ok {
			if innerSel, ok := inner.Fun.(*ast.SelectorExpr); ok && innerSel.Sel.Name == "Storage" {
				return true
			}
		}
		if id, ok := sel.X.(*ast.Ident); ok && aliases[id.Name] {
			return true
		}
		if recv, field, ok := identSel(sel.X); ok && field == "storage" && recv == recvName {
			return true
		}
		return false
	}

	// unfetchedLocals: local variables (never a parameter) whose most recent
	// assignment is a composite literal or a non-fetch call.
	unfetchedLocals := map[string]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, rhs := range assign.Rhs {
			id, ok := assign.Lhs[i].(*ast.Ident)
			if !ok || params[id.Name] {
				continue
			}
			switch v := rhs.(type) {
			case *ast.CallExpr:
				if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Storage" {
					aliases[id.Name] = true
					delete(unfetchedLocals, id.Name)
					continue
				}
				if isFetchCall(v) {
					delete(unfetchedLocals, id.Name)
				} else {
					unfetchedLocals[id.Name] = true
				}
			case *ast.UnaryExpr:
				if v.Op == token.AND {
					if _, ok := v.X.(*ast.CompositeLit); ok {
						unfetchedLocals[id.Name] = true
					}
				}
			}
		}
		return true
	})

	var found []overwriteFinding
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !fullRowOverwriteMethods[sel.Sel.Name] {
			return true
		}
		isStorageCall := false
		if inner, ok := sel.X.(*ast.CallExpr); ok {
			if innerSel, ok := inner.Fun.(*ast.SelectorExpr); ok && innerSel.Sel.Name == "Storage" {
				isStorageCall = true
			}
		}
		if id, ok := sel.X.(*ast.Ident); ok && aliases[id.Name] {
			isStorageCall = true
		}
		if recv, field, ok := identSel(sel.X); ok && field == "storage" && recv == recvName {
			isStorageCall = true
		}
		if !isStorageCall {
			return true
		}
		// call.Args[0] is always ctx context.Context on every fullRowOverwriteMethods
		// signature -- skip it, or every single call site would be flagged on its
		// context argument alone (r.Context()/ctx is always either a bare
		// identifier or a non-fetch call, neither of which says anything about
		// whether the ROW argument was fetched).
		for _, arg := range call.Args[minInt(1, len(call.Args)):] {
			switch v := arg.(type) {
			case *ast.UnaryExpr:
				if v.Op == token.AND {
					if _, ok := v.X.(*ast.CompositeLit); ok {
						found = append(found, overwriteFinding{sel.Sel.Name,
							"passes a freshly-built struct literal directly into"})
						return true
					}
				}
			case *ast.Ident:
				if unfetchedLocals[v.Name] {
					found = append(found, overwriteFinding{sel.Sel.Name,
						"passes a local variable that was never fetched from storage into"})
					return true
				}
			case *ast.CallExpr:
				if !isFetchCall(v) {
					found = append(found, overwriteFinding{sel.Sel.Name,
						"passes the result of a non-fetch call directly into"})
					return true
				}
			}
		}
		return true
	})
	return found
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
