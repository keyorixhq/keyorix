// shadowprobe: an independent reachability oracle for coverage-shadow.py's
// SKIPPABLE verdicts (research tool, not run by CI).
//
// The shadow decides "no changed line ran" from Go's cover profile. This tool
// asks the same question by a different mechanism: it rewrites the checked-out
// HEAD tree so that, immediately before the statement that holds each changed
// line, a probe records that it was reached; the caller then runs the
// dependent's tests and reads the probe file. A recorded probe means the
// SKIPPABLE verdict was wrong (a false negative).
//
// usage: shadowprobe -root DIR -file REL -lines 10-12,20 [-entry 30,31]
//
//	-lines  changed lines (new side) to probe at statement level
//	-entry  lines whose enclosing function is probed at its entry instead
//	        (a deleted-code cut: the removed statements are not in the tree)
//
// It edits REL in place and writes cs23_probe.go next to it. The probe appends
// "<file>:<line>" to the file named by $CS23_PROBE_FILE (no control-flow
// change; a recover() in the code under test cannot hide it). A line that is
// not inside any function body (a const/type/var/import line) cannot be probed
// this way: it is listed on stdout as UNPROBED so the caller treats it as
// inconclusive, never as clean. Output: one line per requested line.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const probeFile = `package %s

import (
	"os"
	"sync"
)

var cs23Mu sync.Mutex

func cs23Hit(id string) {
	p := os.Getenv("CS23_PROBE_FILE")
	if p == "" {
		return
	}
	cs23Mu.Lock()
	defer cs23Mu.Unlock()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(id + "\n")
}
`

func parseLines(s string) ([]int, error) {
	var out []int
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				return nil, err
			}
		}
		for l := a; l <= b; l++ {
			out = append(out, l)
		}
	}
	return out, nil
}

// instrument returns the rewritten source and a per-line report.
func instrument(src []byte, name string, lines, entry []int) ([]byte, map[int]string, string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		return nil, nil, "", err
	}
	line := func(p token.Pos) int { return fset.Position(p).Line }
	report := map[int]string{}
	// target statement per line (innermost statement in some statement list covering the line)
	picked := map[ast.Stmt]string{} // stmt -> probe id
	var funcs []*ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
			funcs = append(funcs, fd)
		}
	}
	enclosing := func(ln int) *ast.FuncDecl {
		for _, fd := range funcs {
			if ln >= line(fd.Pos()) && ln <= line(fd.End()) {
				return fd
			}
		}
		return nil
	}
	for _, ln := range entry {
		fd := enclosing(ln)
		if fd == nil || len(fd.Body.List) == 0 {
			report[ln] = "UNPROBED (not in a function with statements)"
			continue
		}
		picked[fd.Body.List[0]] = fmt.Sprintf("%s:%d(entry)", name, ln)
		report[ln] = "probed at function entry " + fd.Name.Name
	}
	for _, ln := range lines {
		fd := enclosing(ln)
		if fd == nil {
			report[ln] = "UNPROBED (outside any function body)"
			continue
		}
		var best ast.Stmt
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			s, ok := n.(ast.Stmt)
			if !ok {
				return true
			}
			switch s.(type) {
			case *ast.BlockStmt, *ast.CaseClause, *ast.CommClause:
				return true // containers, not statements a probe can precede
			}
			if ln >= line(s.Pos()) && ln <= line(s.End()) {
				best = s // later (deeper) hits overwrite: innermost wins
			}
			return true
		})
		if best == nil {
			// a brace/blank/comment line inside the body: probe the function entry (stronger claim)
			if len(fd.Body.List) == 0 {
				report[ln] = "UNPROBED (empty function)"
				continue
			}
			best = fd.Body.List[0]
			report[ln] = "probed at function entry " + fd.Name.Name
		} else {
			report[ln] = "probed"
		}
		if _, ok := picked[best]; !ok {
			picked[best] = fmt.Sprintf("%s:%d", name, ln)
		}
	}
	// insert before each picked statement, in whatever list holds it
	ast.Inspect(f, func(n ast.Node) bool {
		var list *[]ast.Stmt
		switch b := n.(type) {
		case *ast.BlockStmt:
			list = &b.List
		case *ast.CaseClause:
			list = &b.Body
		case *ast.CommClause:
			list = &b.Body
		default:
			return true
		}
		var out []ast.Stmt
		changed := false
		for _, s := range *list {
			if id, ok := picked[s]; ok {
				out = append(out, &ast.ExprStmt{X: &ast.CallExpr{Fun: ast.NewIdent("cs23Hit"), Args: []ast.Expr{&ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(id)}}}})
				changed = true
			}
			out = append(out, s)
		}
		if changed {
			*list = out
		}
		return true
	})
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, f); err != nil {
		return nil, nil, "", err
	}
	return buf.Bytes(), report, f.Name.Name, nil
}

func main() {
	root := flag.String("root", ".", "tree root")
	file := flag.String("file", "", "file relative to root")
	ls := flag.String("lines", "", "changed lines to probe")
	es := flag.String("entry", "", "lines probed at function entry")
	flag.Parse()
	lines, err1 := parseLines(*ls)
	entry, err2 := parseLines(*es)
	if *file == "" || err1 != nil || err2 != nil {
		fmt.Fprintln(os.Stderr, "usage: shadowprobe -root DIR -file REL -lines 1-2,5 [-entry 9]")
		os.Exit(2)
	}
	path := filepath.Join(*root, *file)
	src, err := os.ReadFile(path) // #nosec G304 -- CI-only tool: path is the -root/-file flags of a throwaway checkout
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out, report, pkg, err := instrument(src, *file, lines, entry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil { // #nosec G306 G703 -- rewrites a source file in a throwaway checkout; keeps its normal mode
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "cs23_probe.go"), []byte(fmt.Sprintf(probeFile, pkg)), 0o644); err != nil { // #nosec G306 G703 -- probe file lands next to the instrumented source in a throwaway checkout
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var keys []int
	for k := range report {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		fmt.Printf("%s:%d %s\n", *file, k, report[k])
	}
}
