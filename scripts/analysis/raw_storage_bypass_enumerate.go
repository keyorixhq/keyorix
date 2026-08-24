//go:build ignore

// raw_storage_bypass_enumerate.go — deterministic, AST-based reimplementation of
// raw_storage_bypass_guard_test.go's detection logic (exportedCoreStorageWrappers +
// handlerStorageCalls), extended repo-wide across every registered handler in
// server/http/handlers, not just the 18-route classifiedNodeCredentialRoutes scope.
//
// Why this exists: the 2026-08-23 #1547 measurement recorded "149 flagged call sites,
// 90 read-shaped, 59 write-shaped" in docs/g80-remediation-notes.md, but that count was
// never itself checked into a reproducible artifact — only the aggregate numbers were
// written down. A same-session-but-later re-derivation (regex line-scan, then this
// AST-based version as a cross-check) produces 145/87/58 both times, NOT 149/90/59, and
// the AST version is immune to the most obvious hypothesis for the gap (multi-line
// method chains — AST doesn't see line breaks at all). Zero alias-form
// (`x := h.coreService.Storage(); x.Method(...)`) call sites were found either, ruling
// out variable-dispatch as the cause too. The 149/90/59 figures in the doc could not be
// reproduced by this tool and should be treated as the incorrect ones pending a
// concrete counter-example; 145/87/58 is what two independent implementations of the
// stated methodology agree on. See docs/g80-raw-storage-bypass-enumeration.md for the
// committed output of this exact run and docs/g80-raw-storage-bypass-blind-spots.md for
// the categories this tool structurally cannot see (mirrors
// knownUnresolvedWireCalls' treatment in remote_wire_route_coverage_test.go: name the
// blind spot, don't silently pretend coverage).
//
// This is a standalone analysis script (go:build ignore — excluded from `go build ./...`
// and `go test ./...`), not a CI guard. Run with:
//
//	go run scripts/analysis/raw_storage_bypass_enumerate.go
//
// Repo root is derived from this file's own path, not the caller's working directory,
// so it's safe to invoke via an absolute path from anywhere. Deterministic: sorts all
// output, no timestamps, no randomness.
package main

import (
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

// repoRoot is derived from this source file's own location (scripts/analysis/…go),
// not the process's working directory — `go run` does not chdir into the script's
// directory, so an os.Getwd()-based root would silently resolve against whatever
// directory the caller happened to invoke `go run` from (e.g. a different worktree),
// producing a result that looks valid but analyzes the wrong tree entirely.
func repoRoot() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

func parseDir(dir string) []*ast.File {
	entries, err := os.ReadDir(dir)
	if err != nil {
		panic(err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			panic(fmt.Sprintf("%s: %v", name, err))
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

// exportedCoreStorageWrappers: every `<recv>.storage.<Method>(...)` call inside an
// EXPORTED *KeyorixCore method body, anywhere in internal/core (excluding tests).
func exportedCoreStorageWrappers(root string) map[string]bool {
	wrapped := map[string]bool{}
	for _, f := range parseDir(filepath.Join(root, "internal", "core")) {
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
			if !ok || id.Name != "KeyorixCore" || !fd.Name.IsExported() || len(fd.Recv.List[0].Names) == 0 {
				continue
			}
			recvName := fd.Recv.List[0].Names[0].Name
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				outerSel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				innerRecv, innerSel, ok := identSel(outerSel.X)
				if ok && innerRecv == recvName && innerSel == "storage" {
					wrapped[outerSel.Sel.Name] = true
				}
				return true
			})
		}
	}
	return wrapped
}

// registeredHandlerNames: every exported method name referenced as `xxx.MethodName`
// inside an r.Get/Post/Put/Delete/Patch/Head/Options(...) call in router.go.
func registeredHandlerNames(root string) map[string]bool {
	names := map[string]bool{}
	f, err := parser.ParseFile(fset, filepath.Join(root, "server", "http", "router.go"), nil, 0)
	if err != nil {
		panic(err)
	}
	verbs := map[string]bool{"Get": true, "Post": true, "Put": true, "Delete": true, "Patch": true, "Head": true, "Options": true}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !verbs[sel.Sel.Name] {
			return true
		}
		for _, arg := range call.Args {
			if _, m, ok := identSel(arg); ok {
				names[m] = true
			}
		}
		return true
	})
	return names
}

type callSite struct {
	file, receiver, handler, method string
	line                            int
	alias                           bool
}

var readPrefixes = []string{"Get", "List", "Count", "Export"}

func isReadShaped(m string) bool {
	for _, p := range readPrefixes {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return false
}

func main() {
	root := repoRoot()
	wrapped := exportedCoreStorageWrappers(root)
	registered := registeredHandlerNames(root)

	dir := filepath.Join(root, "server", "http", "handlers")
	var sites []callSite
	for _, f := range parseDir(dir) {
		fname := filepath.Base(fset.Position(f.Package).Filename)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 || fd.Body == nil {
				continue
			}
			if !fd.Name.IsExported() || !registered[fd.Name.Name] {
				continue
			}
			var recvType string
			if star, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
				if id, ok := star.X.(*ast.Ident); ok {
					recvType = id.Name
				}
			}

			// Blind spot (b): local `alias := x.Storage()` then `alias.Method(...)`.
			aliases := map[string]bool{}

			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if assign, ok := n.(*ast.AssignStmt); ok && len(assign.Lhs) == len(assign.Rhs) {
					for i, rhs := range assign.Rhs {
						if call, ok := rhs.(*ast.CallExpr); ok {
							if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Storage" {
								if id, ok := assign.Lhs[i].(*ast.Ident); ok {
									aliases[id.Name] = true
								}
							}
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
				pos := fset.Position(sel.Pos())
				if inner, ok := sel.X.(*ast.CallExpr); ok {
					if innerSel, ok := inner.Fun.(*ast.SelectorExpr); ok && innerSel.Sel.Name == "Storage" {
						sites = append(sites, callSite{fname, recvType, fd.Name.Name, sel.Sel.Name, pos.Line, false})
						return true
					}
				}
				if id, ok := sel.X.(*ast.Ident); ok && aliases[id.Name] {
					sites = append(sites, callSite{fname, recvType, fd.Name.Name, sel.Sel.Name, pos.Line, true})
				}
				return true
			})
		}
	}

	sort.Slice(sites, func(i, j int) bool {
		if sites[i].file != sites[j].file {
			return sites[i].file < sites[j].file
		}
		return sites[i].line < sites[j].line
	})

	var reads, writes []callSite
	seen := map[string]bool{}
	for _, s := range sites {
		if !wrapped[s.method] {
			continue
		}
		key := fmt.Sprintf("%s:%d:%s", s.file, s.line, s.method)
		if seen[key] {
			continue
		}
		seen[key] = true
		if isReadShaped(s.method) {
			reads = append(reads, s)
		} else {
			writes = append(writes, s)
		}
	}

	total := len(reads) + len(writes)
	fmt.Printf("wrapped core storage methods: %d\n", len(wrapped))
	fmt.Printf("registered handler names: %d\n", len(registered))
	fmt.Printf("TOTAL flagged call sites: %d\n", total)
	fmt.Printf("READ-shaped (excluded, Get/List/Count/Export prefix): %d\n", len(reads))
	fmt.Printf("WRITE-shaped (candidates): %d\n", len(writes))
	fmt.Println()
	fmt.Println("=== WRITE-SHAPED CANDIDATES ===")
	for _, s := range writes {
		alias := ""
		if s.alias {
			alias = " [via local alias]"
		}
		fmt.Printf("server/http/handlers/%s:%d\t%s.%s\tStorage().%s(...)%s\n", s.file, s.line, s.receiver, s.handler, s.method, alias)
	}
}
