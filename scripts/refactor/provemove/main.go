// Command provemove proves that a refactor only MOVED Go declarations: every
// top-level declaration in the given directories of the base tree exists in
// the head tree with an identical normalised body, and nothing was added.
// ADR-121 (docs/adr-121-core-package-split.md) requires its output in every
// extraction PR.
//
// Usage:
//
//	provemove -base <tree> -head <tree> -dirs internal/core,internal/core/coretests \
//	    [-strip core] [-pkgmap coretests=core] [-rename oldName=NewName,...] [-alias leaf=core]
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
// so either reports MISSING and ADDED. A file whose name starts with "_" or "."
// is ignored by go build and go test, so its declarations are keyed
// " [ignored]" and a move into or out of one reports MISSING and ADDED too. Its body is printed with go/printer and
// compared as a token stream without comments, so formatting, alignment and
// comments never count, except the declaration's //go: directives (its doc
// comment's //go:embed, //go:noinline ..., and a //go:linkname anywhere in the
// file that names it) and the file's //go:build / +build lines, which are part
// of the body. A const spec's body is its value as the compiler sees it: a spec
// with no expression of its own repeats the type and expressions of the
// previous spec of its group, and a spec whose expressions use iota also
// records its index in the group, so reordering a const group is CHANGED.
//
//   - -pkgmap new=old renames a package for the key (coretests=core: a test moved
//     to package coretests compares against its old self in package core).
//   - -strip core removes the qualifier from core.X (both trees), so a moved
//     test that now says core.NewKeyorixCore equals its old NewKeyorixCore.
//   - -rename old=new renames an identifier in the BASE tree before comparing (an
//     unexported name the move had to export).
//   - -alias leaf=core proves a leaf extraction (ADR-121 decision 3): package
//     leaf is keyed as core (like -pkgmap), and a declaration of package core
//     of the form `type X = leaf.X`, `var X = leaf.X` or `const X = leaf.X`
//     (one name, same name, no type) is an alias, not a declaration. An alias
//     is compared only by its target: the target must be a declaration read
//     from package leaf, of kind type (type alias), const (const) or func or
//     var (var), in a file of the same class. Each alias new in head prints
//     "ALIAS in head: <key> = leaf.X" and is not a difference; the moved
//     declaration itself is compared against its base self like any other, so
//     a change of its body is still CHANGED. An alias whose target is not such
//     a declaration prints "UNRESOLVED alias in <tree>: ..." (a difference), and
//     an alias of base that is gone from head prints "MISSING in head: <key>
//     (alias)". Any other alias shape (a generic alias, a renamed target, a
//     typed var) is an ordinary declaration and so a difference.
//
// Output: "PURE MOVE: N declarations identical" (exit 0, followed by ", K
// alias(es) to moved declarations" when -alias found any), or one line per
// difference, "CHANGED body: <key>", "MISSING in head: <key>", "ADDED in head:
// <key>", "UNRESOLVED alias in ...: <key> = <target>" (exit 1). ALIAS lines
// come first in both cases. Exit 2 is a usage or parse error.
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
	"path"
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
	alias      map[string]string // leaf package -> package it was extracted from
}

// decls maps a declaration key to its normalised bodies (several for a
// repeated name such as init).
type decls map[string][]string

// declTree is one side's declarations, the keys read from an -alias leaf package,
// and the aliases (key -> alias) found in it.
type declTree struct {
	decls    decls
	fromLeaf map[string]bool
	aliases  map[string]alias
}

// alias is `<kind> X = leaf.X` in the package leaf was extracted from.
type alias struct {
	leaf, name, class string
	kinds             []string // the kinds the target may have
}

func (a alias) String() string { return a.leaf + "." + a.name }

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
	baseTree, err := collect(opts.base, opts.dirs, opts, true)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "provemove: base:", err)
		return 2
	}
	headTree, err := collect(opts.head, opts.dirs, opts, false)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "provemove: head:", err)
		return 2
	}
	base, head := baseTree.decls, headTree.decls
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
	aliasLines, aliasDiffs := compareAliases(baseTree, headTree)
	diffs = append(diffs, aliasDiffs...)
	slices.Sort(diffs)
	for _, l := range aliasLines {
		_, _ = fmt.Fprintln(stdout, l)
	}
	if len(diffs) == 0 {
		if len(aliasLines) > 0 {
			_, _ = fmt.Fprintf(stdout, "PURE MOVE: %d declarations identical, %d alias(es) to moved declarations\n", n, len(aliasLines))
			return 0
		}
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
	strip := fs.String("strip", "", "comma-separated package qualifiers to strip in both trees (core: core.X -> X)")
	pkgmap := fs.String("pkgmap", "", "comma-separated new=old package names for the key (coretests=core)")
	rename := fs.String("rename", "", "comma-separated old=new identifier renames applied to base")
	aliasFlag := fs.String("alias", "", "comma-separated leaf=core: leaf was extracted from core, and core's `X = leaf.X` declarations are aliases")
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
	if opts.alias, err = splitPairs(*aliasFlag, "-alias"); err != nil {
		return options{}, err
	}
	for leaf, from := range opts.alias {
		if m, ok := opts.pkgmap[leaf]; ok && m != from {
			return options{}, fmt.Errorf("-alias %s=%s contradicts -pkgmap %s=%s", leaf, from, leaf, m)
		}
		if _, ok := opts.alias[from]; ok {
			return options{}, fmt.Errorf("-alias: %s is both a leaf and the package a leaf was extracted from", from)
		}
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
func collect(root string, dirs []string, opts options, isBase bool) (declTree, error) {
	out := decls{}
	res := declTree{decls: out, fromLeaf: map[string]bool{}, aliases: map[string]alias{}}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		abs := filepath.Join(root, filepath.FromSlash(dir))
		entries, err := os.ReadDir(abs)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return declTree{}, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(abs, e.Name()), nil, parser.SkipObjectResolution|parser.ParseComments)
			if err != nil {
				return declTree{}, err
			}
			pkg := f.Name.Name
			_, isLeaf := opts.alias[pkg]
			if mapped, ok := opts.alias[pkg]; ok {
				pkg = mapped
			} else if mapped, ok := opts.pkgmap[pkg]; ok {
				pkg = mapped
			}
			if isBase {
				renameIdents(f, opts.rename)
			}
			class := fileClass(e.Name())
			build := buildLines(f)
			linknames := linknameDirectives(f)
			leaves := aliasQualifiers(f, opts.alias)
			for _, d := range f.Decls {
				for key, b := range declBodies(fset, d) {
					k := pkg + "|" + key + class
					if b.alias != nil && leaves[b.alias.leaf] && len(build) == 0 && len(b.directives) == 0 && len(linknames[b.name]) == 0 {
						if _, dup := res.aliases[k]; !dup {
							b.alias.class = class
							res.aliases[k] = *b.alias
							continue
						}
					}
					dirs := slices.Concat(build, b.directives, linknames[b.name])
					out[k] = append(out[k], strings.Join(dirs, "")+normalise(b.text, opts.strip))
					if isLeaf {
						res.fromLeaf[k] = true
					}
				}
			}
		}
	}
	return res, nil
}

// aliasQualifiers returns the -alias leaf names that f, a file of a package
// some leaf was extracted from, imports under their own name (an import whose
// last path element is the leaf, without a local name, or named the leaf).
func aliasQualifiers(f *ast.File, aliases map[string]string) map[string]bool {
	out := map[string]bool{}
	for leaf, from := range aliases {
		if f.Name.Name != from {
			continue
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, "`\"")
			if (imp.Name == nil && path.Base(p) == leaf) || (imp.Name != nil && imp.Name.Name == leaf) {
				out[leaf] = true
			}
		}
	}
	return out
}

// compareAliases returns the ALIAS lines for aliases new in head and the
// differences: an alias whose target is not a declaration read from its leaf
// (either tree), a base alias gone from head, and an alias whose target
// changed.
func compareAliases(base, head declTree) (lines, diffs []string) {
	for _, side := range []struct {
		name string
		t    declTree
	}{{"base", base}, {"head", head}} {
		for k, a := range side.t.aliases {
			if !resolves(side.t, k, a) {
				diffs = append(diffs, fmt.Sprintf("UNRESOLVED alias in %s: %s = %s (no %s %s read from package %s)",
					side.name, k, a, strings.Join(a.kinds, "/"), a.name, a.leaf))
			}
		}
	}
	for k, a := range head.aliases {
		if _, ok := base.aliases[k]; !ok && resolves(head, k, a) {
			lines = append(lines, "ALIAS in head: "+k+" = "+a.String())
		}
	}
	for k, a := range base.aliases {
		h, ok := head.aliases[k]
		switch {
		case !ok:
			diffs = append(diffs, "MISSING in head: "+k+" (alias)")
		case h.String() != a.String() || h.class != a.class:
			diffs = append(diffs, "CHANGED body: "+k+" (alias of "+a.String()+" in base, of "+h.String()+" in head)")
		}
	}
	slices.Sort(lines)
	return lines, diffs
}

// resolves reports whether alias a (key k) names a declaration of t read from
// its leaf package, of an allowed kind, in a file of the alias's class.
func resolves(t declTree, k string, a alias) bool {
	pkg, _, _ := strings.Cut(k, "|")
	for _, kind := range a.kinds {
		if target := pkg + "|" + kind + ":" + a.name + a.class; t.fromLeaf[target] {
			return true
		}
	}
	return false
}

// body is one declaration's printed text, its name (for //go:linkname) and the
// //go: directive lines of its doc comments.
type body struct {
	name       string
	text       string
	directives []string
	alias      *alias // set for `<kind> X = q.X` (q not yet checked against -alias)
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
		// The previous const spec's type and expressions, which a spec with no
		// expression of its own repeats.
		var prevType ast.Expr
		var prevValues []ast.Expr
		for i, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				dirs := slices.Concat(declDirs, directives(s.Doc))
				s.Doc, s.Comment = nil, nil
				b := body{name: s.Name.Name, text: render(fset, &ast.GenDecl{Tok: token.TYPE, Specs: []ast.Spec{s}}), directives: dirs}
				if s.Assign.IsValid() && s.TypeParams == nil {
					b.alias = aliasOf(s.Name.Name, s.Type, "type")
				}
				res["type:"+s.Name.Name] = b
			case *ast.ValueSpec:
				dirs := slices.Concat(declDirs, directives(s.Doc))
				s.Doc, s.Comment = nil, nil
				var aliasTarget *alias
				if len(s.Names) == 1 && len(s.Values) == 1 && s.Type == nil {
					kinds := map[token.Token]string{token.VAR: "func var", token.CONST: "const"}[d.Tok]
					aliasTarget = aliasOf(s.Names[0].Name, s.Values[0], kinds)
				}
				prefix := ""
				if d.Tok == token.CONST {
					if len(s.Values) > 0 {
						prevType, prevValues = s.Type, s.Values
					} else {
						s = &ast.ValueSpec{Names: s.Names, Type: prevType, Values: prevValues}
					}
					if usesIota(s.Values) {
						prefix = fmt.Sprintf("iota %d\n", i)
					}
				}
				// Each name of "var a, b = 1, 2" keeps the whole spec as its body.
				text := prefix + render(fset, &ast.GenDecl{Tok: d.Tok, Specs: []ast.Spec{s}})
				for _, n := range s.Names {
					res[strings.ToLower(d.Tok.String())+":"+n.Name] = body{name: n.Name, text: text, directives: dirs, alias: aliasTarget}
				}
			}
		}
	}
	return res
}

// aliasOf returns the alias for `name = q.name` (e is q.name, q an
// identifier), else nil. kinds is the space-separated kinds its target may have.
func aliasOf(name string, e ast.Expr, kinds string) *alias {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return nil
	}
	q, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil
	}
	return &alias{leaf: q.Name, name: name, kinds: strings.Fields(kinds)}
}

// usesIota reports whether any expression mentions the identifier iota.
func usesIota(exprs []ast.Expr) bool {
	found := false
	for _, e := range exprs {
		ast.Inspect(e, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "iota" {
				found = true
			}
			return !found
		})
	}
	return found
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
	for w := range strings.FieldsSeq(s) {
		m[w] = true
	}
	return m
}

// fileClass returns the key suffix for a file name: " [ignored]" for a name
// go/build ignores (leading "_" or "."), "" for a plain non-test file, else
// " [test]", " [linux]", " [test linux amd64]" ... It follows
// go/build's goodOSArchFile: the part after the first "_", minus a trailing
// _test, ends in _GOOS_GOARCH, _GOOS or _GOARCH.
func fileClass(name string) string {
	if strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".") {
		return " [ignored]"
	}
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
