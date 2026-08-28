//go:build ignore

// remote_storage_stub_rewrite.go — mechanically converts a list of
// *RemoteStorage methods (one name per line on stdin) from their current
// (dead, per the G80 full-classification pass) wire-call/logic body into the
// standard remoteUnsupported("MethodName") stub, matching the shape every
// other classified-permanent stub in this package already uses.
//
// Surgical: replaces ONLY the parameter names (blanked to `_`, preserving
// every type exactly) and the function body's byte range in the original
// source. Everything else in the file -- the function's own doc comment,
// blank lines, unrelated functions, comments -- is untouched byte-for-byte.
// gofmt is expected to run on the result afterward (this tool does not call
// it) since blanking parameter names can change alignment.
//
// Zero-value strategy per non-error return position, chosen from the type's
// own source text (no reflection, no type-checking -- this package's storage
// method returns are exclusively pointers, slices, maps, or a small basic-type
// set, verified exhaustively against the actual 154-method target list before
// this tool was written; see remote_storage_signatures.go's dump):
//
//	*T, []T, map[K]V, chan T, interface, func(...)  -> nil
//	bool                                            -> false
//	string                                          -> ""
//	int, int8/16/32/64, uint, uint8/16/32/64,
//	  float32/64, byte, rune                        -> 0
//	anything else                                    -> panics; add a case
//	                                                     rather than guess
//
// Run:
//
//	go run scripts/analysis/remote_storage_stub_rewrite.go < list_of_names.txt
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

func repoRoot() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

func zeroLiteral(typeText string) string {
	t := strings.TrimSpace(typeText)
	if strings.HasPrefix(t, "*") || strings.HasPrefix(t, "[]") || strings.HasPrefix(t, "map[") ||
		strings.HasPrefix(t, "chan ") || strings.HasPrefix(t, "func(") || strings.HasPrefix(t, "interface{") {
		return "nil"
	}
	switch t {
	case "bool":
		return "false"
	case "string":
		return `""`
	case "int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64",
		"float32", "float64", "byte", "rune", "uintptr":
		return "0"
	}
	panic(fmt.Sprintf("zeroLiteral: unhandled type %q -- add a case, don't guess", t))
}

func main() {
	root := repoRoot()
	dir := filepath.Join(root, "internal", "storage", "store")

	scanner := bufio.NewScanner(os.Stdin)
	targets := map[string]bool{}
	var targetOrder []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			if !targets[line] {
				targetOrder = append(targetOrder, line)
			}
			targets[line] = true
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		panic(err)
	}

	found := map[string]bool{}
	changedFiles := map[string]bool{}

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		fset := token.NewFileSet()
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			panic(rerr)
		}
		f, perr := parser.ParseFile(fset, path, src, parser.ParseComments)
		if perr != nil {
			panic(fmt.Sprintf("%s: %v", path, perr))
		}

		// Collect edits as (startOffset, endOffset, replacement), applied
		// back-to-front so earlier offsets stay valid as later ones are cut.
		type edit struct {
			start, end int
			repl       string
		}
		var edits []edit

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
			if !ok || id.Name != "RemoteStorage" {
				continue
			}
			if !targets[fd.Name.Name] {
				continue
			}
			found[fd.Name.Name] = true

			// Blank every parameter name (types untouched).
			if fd.Type.Params != nil {
				for _, p := range fd.Type.Params.List {
					if len(p.Names) == 0 {
						continue
					}
					typeText := string(src[fset.Position(p.Type.Pos()).Offset:fset.Position(p.Type.End()).Offset])
					var blanked []string
					for range p.Names {
						blanked = append(blanked, "_")
					}
					repl := strings.Join(blanked, ", ") + " " + typeText
					edits = append(edits, edit{
						start: fset.Position(p.Pos()).Offset,
						end:   fset.Position(p.Type.End()).Offset,
						repl:  repl,
					})
				}
			}

			// Build the replacement body: zero-value each non-error result,
			// then the stub call.
			var zeros []string
			if fd.Type.Results != nil {
				list := fd.Type.Results.List
				for i, r := range list {
					isLast := i == len(list)-1
					n := len(r.Names)
					if n == 0 {
						n = 1
					}
					typeText := string(src[fset.Position(r.Type.Pos()).Offset:fset.Position(r.Type.End()).Offset])
					for j := 0; j < n; j++ {
						if isLast && j == n-1 && typeText == "error" {
							continue // the trailing error -- filled by remoteUnsupported(...)
						}
						zeros = append(zeros, zeroLiteral(typeText))
					}
				}
			}
			var bodyText string
			stubCall := fmt.Sprintf("remoteUnsupported(%q)", fd.Name.Name)
			if len(zeros) == 0 {
				bodyText = fmt.Sprintf("{\n\treturn %s\n}", stubCall)
			} else {
				bodyText = fmt.Sprintf("{\n\treturn %s, %s\n}", strings.Join(zeros, ", "), stubCall)
			}
			edits = append(edits, edit{
				start: fset.Position(fd.Body.Pos()).Offset,
				end:   fset.Position(fd.Body.End()).Offset,
				repl:  bodyText,
			})
		}

		if len(edits) == 0 {
			continue
		}

		sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
		out := make([]byte, 0, len(src))
		cursor := 0
		for _, ed := range edits {
			out = append(out, src[cursor:ed.start]...)
			out = append(out, []byte(ed.repl)...)
			cursor = ed.end
		}
		out = append(out, src[cursor:]...)

		if err := os.WriteFile(path, out, 0o644); err != nil {
			panic(err)
		}
		changedFiles[path] = true
	}

	var missing []string
	for _, name := range targetOrder {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: %d target(s) not found as a *RemoteStorage method: %v\n", len(missing), missing)
	}

	var files []string
	for f := range changedFiles {
		rel, _ := filepath.Rel(root, f)
		files = append(files, rel)
	}
	sort.Strings(files)
	fmt.Printf("Rewrote %d method(s) across %d file(s):\n", len(found), len(files))
	for _, f := range files {
		fmt.Println("  " + f)
	}
}
