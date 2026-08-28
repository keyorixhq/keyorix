//go:build ignore

// remote_storage_classify.go — mechanical LIVE/DEAD/UNRESOLVED classifier for
// RemoteStorage's structurally-stub-shaped methods (see
// internal/storage/store/remote_unsupported_completeness_test.go's
// actualRemoteUnsupportedStubs for the same "does it ever reach
// rs.client.<Verb>" definition this reuses).
//
// G80: 171 (later 183, after the #1583 deletion pass converted 12 more)
// stub-shaped RemoteStorage methods exist. Wave 0 individually classified 13
// of them by hand-tracing; the rest were never examined for LIVE/DEAD/
// UNRESOLVED at all. Wave 0's own hand-tracing missed an idiom (ResolveRemote)
// on its first pass — proof that a manual sweep over this many methods is
// exactly how that class of miss happens. This tool makes the tracing
// mechanical and repeatable instead.
//
// What it computes, per storage method name in a target list read from stdin
// (one name per line):
//
//  1. Every internal/core (*KeyorixCore) method that can reach it, by full
//     transitive same-package call-graph closure (not the one-hop-only
//     wrapper detection raw_storage_bypass_enumerate.go uses for a different
//     question) — cycle-safe, memoized.
//  2. Of those, the EXPORTED ones (only an exported method is callable from
//     outside internal/core at all).
//  3. For each exported entry point, every file under internal/cli, that
//     references it as `<recv>.<Method>(` — i.e. a plausible CLI caller.
//  4. Whether each such CLI file contains one of the four established guard
//     idioms (NewRemoteClient/NewRemoteClientWithCredentials/ResolveRemote/
//     IsClientMode) anywhere in its source — the same idiom set and the same
//     file-level signal Wave 0's own re-derivation (Wave 0c) used and
//     verified complete for the 22/25-file unguarded population.
//  5. Whether each exported entry point is also referenced from
//     server/http/handlers, server/grpc/services, or server/main.go — any
//     such reference marks it server-only (ADR-083: validateRemoteStorageNotServer
//     unconditionally rejects storage.type: remote for every server process,
//     scheduler-only included, current source confirmed before this tool was
//     written).
//
// Output, per input method name, one line:
//
//	<name>\t<verdict>\t<evidence>
//
// verdict is one of:
//
//	DEAD-NO-CORE-CALLER       — zero internal/core method reaches it at all
//	DEAD-SERVER-ONLY          — every core method reaching it is only called
//	                            from server/http, server/grpc, or server/main.go
//	DEAD-CLI-ALL-GUARDED      — every CLI file referencing a reaching entry
//	                            point contains a guard idiom
//	CANDIDATE-LIVE            — at least one CLI file referencing a reaching
//	                            entry point does NOT contain a guard idiom;
//	                            REQUIRES manual verification (this tool finds
//	                            candidates, it does not confirm a deployment
//	                            path — see the report this feeds)
//	UNRESOLVED                — the tool found a core caller but could not
//	                            resolve any CLI/handler/grpc reference at all
//	                            (evidence names what's missing)
//
// evidence lists the specific core method(s) and file(s) backing the verdict.
//
// Run:
//
//	go run scripts/analysis/remote_storage_classify.go < list_of_names.txt
package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

var fset = token.NewFileSet()

func repoRoot() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

func parseDir(dir string, includeTests bool) []*ast.File {
	entries, err := os.ReadDir(dir)
	if err != nil {
		panic(err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if !includeTests && strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			panic(fmt.Sprintf("%s: %v", filepath.Join(dir, name), err))
		}
		files = append(files, f)
	}
	return files
}

func identSel(e ast.Expr) (recv, sel string, ok bool) {
	se, isSel := e.(*ast.SelectorExpr)
	if !isSel {
		return "", "", false
	}
	id, isIdent := se.X.(*ast.Ident)
	if !isIdent {
		return "", "", false
	}
	return id.Name, se.Sel.Name, true
}

func isExportedName(name string) bool {
	return len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z'
}

// ---- Phase A: internal/core call graph ----

type coreMethod struct {
	fd       *ast.FuncDecl
	recvName string
}

func loadCoreMethods(root string) map[string]coreMethod {
	methods := map[string]coreMethod{}
	for _, f := range parseDir(filepath.Join(root, "internal", "core"), false) {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 || fd.Body == nil {
				continue
			}
			star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			id, ok := star.X.(*ast.Ident)
			if !ok || id.Name != "KeyorixCore" || len(fd.Recv.List[0].Names) == 0 {
				continue
			}
			methods[fd.Name.Name] = coreMethod{fd: fd, recvName: fd.Recv.List[0].Names[0].Name}
		}
	}
	return methods
}

// storageClosureParamName returns the parameter name if fl has the shape
// `func(<name> storage.Storage) ...` -- the WithTransaction/putConditionalTransition
// closure shape used throughout internal/core (e.g.
// `c.storage.WithTransaction(ctx, func(tx storage.Storage) error { tx.UpdateX(...) })`).
// Calls made through that parameter (`tx.Method(...)`) are direct storage
// calls just as much as `c.storage.Method(...)` is -- an earlier version of
// this tool missed this shape entirely, undercounting reachability for every
// core method that uses WithTransaction (confirmed by direct grep:
// core.AnomalyDetector's CreateAnomalyAlert calls, audit_retention.go's
// DeleteAuditLogsBefore call, both invisible to the original single-shape
// check).
func storageClosureParamName(fl *ast.FuncLit) (string, bool) {
	if fl.Type == nil || fl.Type.Params == nil || len(fl.Type.Params.List) != 1 {
		return "", false
	}
	p := fl.Type.Params.List[0]
	if len(p.Names) != 1 {
		return "", false
	}
	sel, ok := p.Type.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkgID, ok := sel.X.(*ast.Ident)
	if !ok || pkgID.Name != "storage" || sel.Sel.Name != "Storage" {
		return "", false
	}
	return p.Names[0].Name, true
}

func directStorageCalls(fd *ast.FuncDecl, recvName string) []string {
	var found []string
	// closureParams: every storage.Storage-typed closure parameter name found
	// anywhere in this function body, collected in a first pass so the second
	// pass can treat `<param>.Method(...)` as a direct storage call regardless
	// of which order ast.Inspect visits the closure vs. the call.
	closureParams := map[string]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if fl, ok := n.(*ast.FuncLit); ok {
			if name, ok := storageClosureParamName(fl); ok {
				closureParams[name] = true
			}
		}
		return true
	})
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		outerSel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if innerRecv, innerSel, ok := identSel(outerSel.X); ok && innerRecv == recvName && innerSel == "storage" {
			found = append(found, outerSel.Sel.Name)
			return true
		}
		if id, ok := outerSel.X.(*ast.Ident); ok && closureParams[id.Name] {
			found = append(found, outerSel.Sel.Name)
		}
		return true
	})
	return found
}

// directSiblingCalls returns every same-receiver KeyorixCore method called
// (any hop, exported or unexported) as `<recvName>.<name>(...)`.
func directSiblingCalls(fd *ast.FuncDecl, recvName string, all map[string]coreMethod) []string {
	var found []string
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != recvName {
			return true
		}
		if _, exists := all[sel.Sel.Name]; exists {
			found = append(found, sel.Sel.Name)
		}
		return true
	})
	return found
}

// reachableStorageIndex computes, for every core method, the full transitive
// set of storage methods it can reach (through any chain of same-receiver
// sibling calls), memoized with cycle protection.
func reachableStorageIndex(all map[string]coreMethod) map[string]map[string]bool {
	memo := map[string]map[string]bool{}
	visiting := map[string]bool{}
	var compute func(name string) map[string]bool
	compute = func(name string) map[string]bool {
		if v, ok := memo[name]; ok {
			return v
		}
		if visiting[name] {
			return map[string]bool{}
		}
		visiting[name] = true
		defer delete(visiting, name)

		m := all[name]
		result := map[string]bool{}
		for _, s := range directStorageCalls(m.fd, m.recvName) {
			result[s] = true
		}
		for _, sib := range directSiblingCalls(m.fd, m.recvName, all) {
			for s := range compute(sib) {
				result[s] = true
			}
		}
		memo[name] = result
		return result
	}
	out := map[string]map[string]bool{}
	for name := range all {
		out[name] = compute(name)
	}
	return out
}

// ---- Phase B: reverse index (storage method -> exported core entry points) ----

func exportedEntryPointsFor(target string, reach map[string]map[string]bool) []string {
	var out []string
	for name, set := range reach {
		if !isExportedName(name) {
			continue
		}
		if set[target] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ---- Phase C: CLI guard-idiom classification ----

var guardIdioms = []string{"NewRemoteClient(", "NewRemoteClientWithCredentials(", "ResolveRemote(", "IsClientMode("}

func fileHasGuardIdiom(src string) bool {
	for _, idiom := range guardIdioms {
		if strings.Contains(src, idiom) {
			return true
		}
	}
	return false
}

type fileRef struct {
	path    string
	guarded bool
}

// filesReferencingMethod walks every .go file (non-test) under root and
// returns those whose source contains `.<method>(` as plain text — a
// deliberately broad, cheap signal; false positives (an unrelated type with
// the same method name) are possible and are why CANDIDATE-LIVE results are
// reported as candidates requiring manual confirmation, not final verdicts.
func filesReferencingMethod(root, method string) []string {
	var out []string
	needle := "." + method + "("
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(b), needle) {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func main() {
	root := repoRoot()

	all := loadCoreMethods(root)
	reach := reachableStorageIndex(all)

	cliRoot := filepath.Join(root, "internal", "cli")
	// serverRoot: the WHOLE server/ tree (handlers, grpc services+interceptors,
	// middleware, main.go, tools, validation, ...) -- any reference here is
	// server-only per ADR-083 (validateRemoteStorageNotServer unconditionally
	// rejects storage.type: remote for every server process). An earlier
	// version of this scan checked only server/http/handlers, server/grpc/
	// services, and server/main.go, and missed server/middleware/auth.go and
	// server/grpc/interceptors/auth.go entirely -- exactly the kind of
	// incomplete-population miss this whole classification pass exists to
	// stop repeating.
	serverRoot := filepath.Join(root, "server")

	scanner := bufio.NewScanner(os.Stdin)
	var targets []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			targets = append(targets, line)
		}
	}

	for _, target := range targets {
		entries := exportedEntryPointsFor(target, reach)
		if len(entries) == 0 {
			// Safety net: the reachability model above only follows
			// *KeyorixCore-receiver methods and storage.Storage-typed
			// WithTransaction closures. A storage call reached through some
			// OTHER helper struct KeyorixCore constructs and hands off to
			// (confirmed real: core.AnomalyDetector holds its own `.storage`
			// field, unrelated to any *KeyorixCore receiver) would be
			// invisible to that model. Before declaring zero callers, do a
			// repo-wide plain-text scan (excluding the storage-layer package
			// itself, its own interface declaration, and tests) for ANY
			// `.Method(` reference at all -- if one exists, this is NOT
			// confidently DEAD-NO-CORE-CALLER; it needs the same manual
			// tracing a CANDIDATE-LIVE result gets, so report UNRESOLVED
			// with the hit named rather than a false DEAD.
			var outsideHits []string
			needle := "." + target + "("
			filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return nil
				}
				if strings.Contains(path, filepath.Join("internal", "storage", "store")) {
					return nil // the storage-layer implementations themselves, not callers
				}
				if strings.HasSuffix(path, filepath.Join("internal", "core", "storage", "interface.go")) {
					return nil // the interface declaration, not a call
				}
				b, rerr := os.ReadFile(path)
				if rerr != nil {
					return nil
				}
				if strings.Contains(string(b), needle) {
					rel, _ := filepath.Rel(root, path)
					outsideHits = append(outsideHits, rel)
				}
				return nil
			})
			if len(outsideHits) > 0 {
				sort.Strings(outsideHits)
				fmt.Printf("%s\tUNRESOLVED\tno *KeyorixCore-receiver caller found, but a repo-wide scan found a reference outside internal/storage/store -- likely reached through a non-KeyorixCore helper type this tool's call-graph model doesn't follow; trace by hand: %s\n", target, strings.Join(outsideHits, "; "))
				continue
			}
			fmt.Printf("%s\tDEAD-NO-CORE-CALLER\tno internal/core method reaches this storage method (checked full transitive closure), and a repo-wide scan outside internal/storage/store found no reference at all\n", target)
			continue
		}

		var cliUnguarded, cliGuarded, serverHits []string
		for _, entry := range entries {
			for _, f := range filesReferencingMethod(cliRoot, entry) {
				rel, _ := filepath.Rel(root, f)
				b, _ := os.ReadFile(f)
				if fileHasGuardIdiom(string(b)) {
					cliGuarded = append(cliGuarded, rel+" (core."+entry+")")
				} else {
					cliUnguarded = append(cliUnguarded, rel+" (core."+entry+")")
				}
			}
			for _, f := range filesReferencingMethod(serverRoot, entry) {
				rel, _ := filepath.Rel(root, f)
				serverHits = append(serverHits, rel+" (core."+entry+")")
			}
		}

		sort.Strings(cliUnguarded)
		sort.Strings(cliGuarded)
		sort.Strings(serverHits)

		entryList := strings.Join(entries, ",")

		if len(cliUnguarded) > 0 {
			fmt.Printf("%s\tCANDIDATE-LIVE\tentries=[%s] unguarded_cli=[%s]\n", target, entryList, strings.Join(cliUnguarded, "; "))
			continue
		}

		if len(cliGuarded) > 0 {
			fmt.Printf("%s\tDEAD-CLI-ALL-GUARDED\tentries=[%s] guarded_cli=[%s]\n", target, entryList, strings.Join(cliGuarded, "; "))
			continue
		}

		if len(serverHits) > 0 {
			fmt.Printf("%s\tDEAD-SERVER-ONLY\tentries=[%s] server=[%s]\n", target, entryList, strings.Join(serverHits, "; "))
			continue
		}

		fmt.Printf("%s\tUNRESOLVED\tentries=[%s] reached by internal/core but no CLI/server textual reference found for any entry point -- check for reflection, interface dispatch, or a caller this tool's plain-text scan cannot see\n", target, entryList)
	}
}
