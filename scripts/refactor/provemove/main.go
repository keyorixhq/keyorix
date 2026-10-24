// Command provemove proves that a refactor only MOVED Go declarations: every
// top-level declaration in the given directories of the base tree exists in
// the head tree with an identical normalised body, and nothing was added.
// ADR-116 (docs/adr-116-core-package-split.md) requires its output in every
// extraction PR.
//
// Usage:
//
//	provemove -base <tree> -head <tree> -dirs internal/core,internal/core/coretests \
//	    [-strip core] [-pkgmap coretests=core] [-rename oldName=NewName,...]
//
// -base and -head are two checkouts (for example `git worktree`-free copies made
// with `git archive <sha> | tar -x -C dir`). -dirs lists the directories,
// relative to both trees, that together hold the moved code before and after:
// a file moved from internal/core to internal/anomaly needs both. Every .go file
// directly in each directory is read, test files included.
//
// A declaration is keyed by "<package>|<kind>:<name>" (kind func, method, type,
// var, const; a method's name is "(*Recv).Name" or "(Recv).Name"), so moving it
// to another file or directory of the same package keeps its key. The key ends
// in " [...]" when the file is a _test.go file or carries a GOOS/GOARCH
// file-name suffix ("x|func:TestA [test]", "x|func:F [linux amd64]"): a test
// moved into a non-test file stops running, and a suffix is a build constraint,
// so either reports MISSING and ADDED. Its body is printed with go/printer and
// compared as a token stream without comments, so formatting, alignment and
// comments never count, except the declaration's //go: directives (its doc
// comment's //go:embed, //go:noinline ..., and a //go:linkname anywhere in the
// file that names it) and the file's //go:build / +build lines, which are part
// of the body.
//
//   - -pkgmap new=old renames a package for the key (coretests=core: a test moved
//     to package coretests compares against its old self in package core).
//   - -strip core removes the qualifier from core.X (both trees), so a moved
//     test that now says core.NewKeyorixCore equals its old NewKeyorixCore.
//   - -rename old=new renames an identifier in the BASE tree before comparing (an
//     unexported name the move had to export).
//
// Output: "PURE MOVE: N declarations identical" (exit 0), or one line per
// difference, "CHANGED body: <key>", "MISSING in head: <key>", "ADDED in head:
// <key>" (exit 1). Exit 2 is a usage or parse error.
//
// It fails (exit 2) when no declaration was read at all, or when a -dirs entry
// exists in neither tree (a typo would otherwise prove nothing).
//
// What it does not check: imports (compare `go list -deps` instead), comments
// other than the directives above, a //go: directive that is neither in a
// declaration's doc comment nor a //go:linkname (for example //go:generate),
// the order of declarations, and an identifier that resolves
// to a different object after a qualifier is stripped (shadowing). Reviewers
// read the import diff. Repeated names (several init funcs, `var _ = ...`) are
// compared as a multiset of bodies.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/scanner"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type options struct {
	base, head string
	dirs       []string
	strip      map[string]bool
	pkgmap     map[string]string
	rename     map[string]string
}

// decls maps a declaration key to its normalised bodies (several for a
// repeated name such as init).
type decls map[string][]string

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "provemove:", err)
		return 2
	}
	_, _ = fmt.Fprintf(stderr, "provemove: reading %d dir(s) in %s and %s\n", len(opts.dirs), opts.base, opts.head)
	base, err := collect(opts.base, opts.dirs, opts, true)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "provemove: base:", err)
		return 2
	}
	head, err := collect(opts.head, opts.dirs, opts, false)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "provemove: head:", err)
		return 2
	}
	if len(base) == 0 && len(head) == 0 {
		_, _ = fmt.Fprintf(stderr, "provemove: no declarations read from -dirs %s in either tree: check the paths\n", strings.Join(opts.dirs, ","))
		return 2
	}
	for _, dir := range opts.dirs {
		if !isDir(opts.base, dir) && !isDir(opts.head, dir) {
			_, _ = fmt.Fprintf(stderr, "provemove: -dirs entry %s exists in neither tree: check the path\n", dir)
			return 2
		}
	}
	diffs, n := compare(base, head)
	if len(diffs) == 0 {
		_, _ = fmt.Fprintf(stdout, "PURE MOVE: %d declarations identical\n", n)
		return 0
	}
	for _, d := range diffs {
		_, _ = fmt.Fprintln(stdout, d)
	}
	_, _ = fmt.Fprintf(stdout, "NOT A PURE MOVE: %d difference(s), %d declarations identical\n", len(diffs), n)
	return 1
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("provemove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("base", "", "base tree (before the move)")
	head := fs.String("head", "", "head tree (after the move)")
	dirs := fs.String("dirs", "", "comma-separated directories, relative to both trees")
	strip := fs.String("strip", "", "comma-separated package qualifiers to strip in head (core: core.X -> X)")
	pkgmap := fs.String("pkgmap", "", "comma-separated new=old package names for the key (coretests=core)")
	rename := fs.String("rename", "", "comma-separated old=new identifier renames applied to base")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if *base == "" || *head == "" || *dirs == "" {
		return options{}, errors.New("-base, -head and -dirs are required")
	}
	opts := options{base: *base, head: *head, strip: map[string]bool{}, pkgmap: map[string]string{}, rename: map[string]string{}}
	opts.dirs = splitList(*dirs)
	for _, s := range splitList(*strip) {
		opts.strip[s] = true
	}
	var err error
	if opts.pkgmap, err = splitPairs(*pkgmap, "-pkgmap"); err != nil {
		return options{}, err
	}
	if opts.rename, err = splitPairs(*rename, "-rename"); err != nil {
		return options{}, err
	}
	return opts, nil
}

func splitList(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitPairs(s, flagName string) (map[string]string, error) {
	m := map[string]string{}
	for _, p := range splitList(s) {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("%s: %q is not name=name", flagName, p)
		}
		m[k] = v
	}
	return m, nil
}

func isDir(root, dir string) bool {
	fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(dir)))
	return err == nil && fi.IsDir()
}

// collect reads every .go file directly in each dir of root. A dir missing from
// one tree (a new package, or one the move emptied) is skipped here; run fails
// on a dir missing from both.
func collect(root string, dirs []string, opts options, isBase bool) (decls, error) {
	out := decls{}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		abs := filepath.Join(root, filepath.FromSlash(dir))
		entries, err := os.ReadDir(abs)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(abs, e.Name()), nil, parser.SkipObjectResolution|parser.ParseComments)
			if err != nil {
				return nil, err
			}
			pkg := f.Name.Name
			if mapped, ok := opts.pkgmap[pkg]; ok {
				pkg = mapped
			}
			if isBase {
				renameIdents(f, opts.rename)
			}
			class := fileClass(e.Name())
			build := buildLines(f)
			linknames := linknameDirectives(f)
			for _, d := range f.Decls {
				for key, b := range declBodies(fset, d) {
					k := pkg + "|" + key + class
					dirs := slices.Concat(build, b.directives, linknames[b.name])
					out[k] = append(out[k], strings.Join(dirs, "")+normalise(b.text, opts.strip))
				}
			}
		}
	}
	return out, nil
}

// body is one declaration's printed text, its name (for //go:linkname) and the
// //go: directive lines of its doc comments.
type body struct {
	name       string
	text       string
	directives []string
}

// declBodies returns key -> body for one top-level declaration (a GenDecl
// yields one entry per spec name; imports yield none).
func declBodies(fset *token.FileSet, d ast.Decl) map[string]body {
	res := map[string]body{}
	switch d := d.(type) {
	case *ast.FuncDecl:
		dirs := directives(d.Doc)
		d.Doc = nil
		key := "func:" + d.Name.Name
		if d.Recv != nil && len(d.Recv.List) > 0 {
			key = "method:(" + recvName(d.Recv.List[0].Type) + ")." + d.Name.Name
		}
		res[key] = body{name: d.Name.Name, text: render(fset, d), directives: dirs}
	case *ast.GenDecl:
		if d.Tok == token.IMPORT {
			return res
		}
		declDirs := directives(d.Doc)
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				dirs := slices.Concat(declDirs, directives(s.Doc))
				s.Doc, s.Comment = nil, nil
				res["type:"+s.Name.Name] = body{name: s.Name.Name, text: render(fset, &ast.GenDecl{Tok: token.TYPE, Specs: []ast.Spec{s}}), directives: dirs}
			case *ast.ValueSpec:
				dirs := slices.Concat(declDirs, directives(s.Doc))
				s.Doc, s.Comment = nil, nil
				// Each name of "var a, b = 1, 2" keeps the whole spec as its body.
				text := render(fset, &ast.GenDecl{Tok: d.Tok, Specs: []ast.Spec{s}})
				for _, n := range s.Names {
					res[strings.ToLower(d.Tok.String())+":"+n.Name] = body{name: n.Name, text: text, directives: dirs}
				}
			}
		}
	}
	return res
}

// directives returns the //go: lines of a doc comment, one "directive ...\n"
// line each, in order.
func directives(cg *ast.CommentGroup) []string {
	if cg == nil {
		return nil
	}
	var out []string
	for _, c := range cg.List {
		if strings.HasPrefix(c.Text, "//go:") {
			out = append(out, "directive "+strings.TrimSpace(c.Text)+"\n")
		}
	}
	return out
}

// linknameDirectives maps a local name to every "//go:linkname <local> ..."
// comment of the file, wherever it is (it need not be attached to the
// declaration).
func linknameDirectives(f *ast.File) map[string][]string {
	out := map[string][]string{}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			fields := strings.Fields(c.Text)
			if len(fields) >= 2 && fields[0] == "//go:linkname" {
				out[fields[1]] = append(out[fields[1]], "linkname "+strings.Join(fields[1:], " ")+"\n")
			}
		}
	}
	return out
}

// buildLines returns the file's //go:build and // +build lines (comments
// before the package clause), which apply to every declaration in it.
func buildLines(f *ast.File) []string {
	var out []string
	for _, cg := range f.Comments {
		if cg.Pos() >= f.Package {
			break
		}
		for _, c := range cg.List {
			if t := strings.TrimSpace(c.Text); strings.HasPrefix(t, "//go:build") || strings.HasPrefix(t, "// +build") {
				out = append(out, "build "+t+"\n")
			}
		}
	}
	return out
}

// knownOS and knownArch are the GOOS and GOARCH values go/build recognises in a
// file-name suffix (go/build/syslist.go).
var (
	knownOS   = setOf("aix android darwin dragonfly freebsd hurd illumos ios js linux nacl netbsd openbsd plan9 solaris wasip1 windows zos")
	knownArch = setOf("386 amd64 amd64p32 arm armbe arm64 arm64be loong64 mips mipsle mips64 mips64le mips64p32 mips64p32le " +
		"ppc ppc64 ppc64le riscv riscv64 s390 s390x sparc sparc64 wasm")
)

func setOf(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// fileClass returns the key suffix for a file name: "" for a plain non-test
// file, else " [test]", " [linux]", " [test linux amd64]" ... It follows
// go/build's goodOSArchFile: the part after the first "_", minus a trailing
// _test, ends in _GOOS_GOARCH, _GOOS or _GOARCH.
func fileClass(name string) string {
	name = strings.TrimSuffix(name, ".go")
	var tags []string
	if strings.HasSuffix(name, "_test") {
		tags = append(tags, "test")
	}
	if i := strings.Index(name, "_"); i >= 0 {
		l := strings.Split(name[i:], "_")
		if n := len(l); n > 0 && l[n-1] == "test" {
			l = l[:n-1]
		}
		n := len(l)
		switch {
		case n >= 2 && knownOS[l[n-2]] && knownArch[l[n-1]]:
			tags = append(tags, l[n-2], l[n-1])
		case n >= 1 && (knownOS[l[n-1]] || knownArch[l[n-1]]):
			tags = append(tags, l[n-1])
		}
	}
	if len(tags) == 0 {
		return ""
	}
	return " [" + strings.Join(tags, " ") + "]"
}

func recvName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return "*" + recvName(t.X)
	case *ast.IndexExpr:
		return recvName(t.X)
	case *ast.IndexListExpr:
		return recvName(t.X)
	case *ast.Ident:
		return t.Name
	default:
		return fmt.Sprintf("%T", e)
	}
}

// render prints a node on its own; comments attached to the File are not
// printed, and normalise drops any that remain.
func render(fset *token.FileSet, n ast.Node) string {
	var buf bytes.Buffer
	cfg := printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 8}
	if err := cfg.Fprint(&buf, fset, n); err != nil {
		return "<print error: " + err.Error() + ">"
	}
	return buf.String()
}

// normalise turns printed source into its token stream ("tok literal" per
// token, comments dropped), so whitespace and column alignment never count,
// and drops the "pkg." of every pkg.X with pkg in strip (not after another
// ".", so x.core.Y keeps its field).
func normalise(src string, strip map[string]bool) string {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var sc scanner.Scanner
	sc.Init(file, []byte(src), nil, 0)
	type tok struct {
		t   token.Token
		lit string
	}
	var toks []tok
	for {
		_, t, lit := sc.Scan()
		if t == token.EOF {
			break
		}
		toks = append(toks, tok{t, lit})
	}
	var out strings.Builder
	for i := 0; i < len(toks); i++ {
		tk := toks[i]
		if tk.t == token.IDENT && strip[tk.lit] && i+2 < len(toks) && toks[i+1].t == token.PERIOD &&
			toks[i+2].t == token.IDENT && (i == 0 || toks[i-1].t != token.PERIOD) {
			i++ // drop "pkg" and "."
			continue
		}
		out.WriteString(tk.t.String())
		if tk.lit != "" {
			out.WriteString(" " + tk.lit)
		}
		out.WriteByte('\n')
	}
	return out.String()
}

// renameIdents renames identifiers in place (base tree only).
func renameIdents(f *ast.File, rename map[string]string) {
	if len(rename) == 0 {
		return
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if to, ok := rename[id.Name]; ok {
				id.Name = to
			}
		}
		return true
	})
}

// compare returns the sorted differences and the number of identical keys.
func compare(base, head decls) ([]string, int) {
	var diffs []string
	same := 0
	for k, b := range base {
		h, ok := head[k]
		if !ok {
			diffs = append(diffs, "MISSING in head: "+k)
			continue
		}
		bs, hs := slices.Clone(b), slices.Clone(h)
		slices.Sort(bs)
		slices.Sort(hs)
		if slices.Equal(bs, hs) {
			same++
		} else {
			diffs = append(diffs, "CHANGED body: "+k)
		}
	}
	for k := range head {
		if _, ok := base[k]; !ok {
			diffs = append(diffs, "ADDED in head: "+k)
		}
	}
	slices.Sort(diffs)
	return diffs, same
}
