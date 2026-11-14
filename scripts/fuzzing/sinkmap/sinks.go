// sinks.go — syntactic (AST-only) matchers for dangerous sink call sites.
//
// Every matcher is deliberately conservative and names, in the emitted
// Detail, exactly what it recognised. The matchers work on go/ast alone
// (no go/types), so where a decision would require type resolution the
// matcher says so in Detail rather than guessing — see the package doc in
// main.go for the full list of what this tool does NOT verify.
package main

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"
)

// SinkKind is one of the dangerous operation families this tool targets.
type SinkKind string

const (
	KindFSPath        SinkKind = "fs-path"
	KindExec          SinkKind = "exec"
	KindNetOut        SinkKind = "net-out"
	KindSQL           SinkKind = "sql"
	KindTemplate      SinkKind = "template-regexp"
	KindDeserialize   SinkKind = "deserialize"
	KindCryptoCompare SinkKind = "crypto-compare"
)

// kindSeverity ranks sink kinds for the output table: lower is more
// interesting to a fuzzing-targeting effort (closer to an injection /
// code-exec primitive). Used only for ordering, never as a verdict.
var kindSeverity = map[SinkKind]int{
	KindExec:          0,
	KindSQL:           1,
	KindNetOut:        2,
	KindFSPath:        3,
	KindDeserialize:   4,
	KindTemplate:      5,
	KindCryptoCompare: 6,
}

// fsPathFuncs are the os/ioutil functions that consume a filesystem path.
var fsPathFuncs = map[string]bool{
	"Open": true, "Create": true, "OpenFile": true, "ReadFile": true,
	"WriteFile": true, "Rename": true, "RemoveAll": true, "Remove": true,
	"Mkdir": true, "MkdirAll": true, "ReadDir": true, "Lstat": true,
}

// sqlQueryMethods map a db method name to the index of its query-string
// argument (Context variants take ctx first).
var sqlQueryMethods = map[string]int{
	"Exec": 0, "Query": 0, "QueryRow": 0, "Prepare": 0,
	"ExecContext": 1, "QueryContext": 1, "QueryRowContext": 1, "PrepareContext": 1,
}

// secretNameRe matches an identifier that names a credential-shaped value,
// used by the crypto-compare matcher. Word-ish, case-insensitive.
var secretNameRe = regexp.MustCompile(`(?i)(token|secret|mac\b|hmac|hash|digest|password|passwd|signature|^sig$|apikey|api_key|authtoken)`)

// matchSinks walks one FuncDecl body and appends every sink it finds.
// pkgRel is the module-relative package dir, display is the func display key.
func matchSinks(fset *token.FileSet, pkgRel, display string, fn *ast.FuncDecl, imports map[string]string, out *[]Sink) {
	if fn.Body == nil {
		return
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.CallExpr:
			matchCall(fset, pkgRel, display, e, imports, out)
		case *ast.BinaryExpr:
			matchCompare(fset, pkgRel, display, e, out)
		}
		return true
	})
}

// pkgIdent returns the left ident of a selector `x.Sel` if x is a bare
// identifier (e.g. the `os` in `os.Open`), plus the selector name.
func pkgIdent(sel *ast.SelectorExpr) (recv, name string, recvIsIdent bool) {
	name = sel.Sel.Name
	if id, ok := sel.X.(*ast.Ident); ok {
		return id.Name, name, true
	}
	return "", name, false
}

// isStringLit reports whether e is a plain string literal (a trusted,
// non-variable constant from the AST's point of view).
func isStringLit(e ast.Expr) bool {
	bl, ok := e.(*ast.BasicLit)
	return ok && bl.Kind == token.STRING
}

// callName renders a CallExpr's target for the Detail column.
func callName(e *ast.CallExpr) string {
	switch f := e.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if id, ok := f.X.(*ast.Ident); ok {
			return id.Name + "." + f.Sel.Name
		}
		return "." + f.Sel.Name
	}
	return "?"
}

func matchCall(fset *token.FileSet, pkgRel, display string, e *ast.CallExpr, imports map[string]string, out *[]Sink) {
	pos := fset.Position(e.Pos())
	add := func(kind SinkKind, detail string) {
		*out = append(*out, Sink{
			Kind: kind, File: pos.Filename, Line: pos.Line,
			Func: display, Pkg: pkgRel, Detail: detail,
		})
	}

	sel, ok := e.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	recv, name, recvIsIdent := pkgIdent(sel)

	// Resolve a bare receiver ident to its imported package path when it is
	// a package qualifier (so `os` really is "os", not a local variable).
	impPath := ""
	if recvIsIdent {
		impPath = imports[recv]
	}
	isPkg := func(p string) bool { return impPath == p || (impPath == "" && recv == lastElem(p)) }

	switch {
	// --- filesystem path use ---
	case recvIsIdent && (isPkg("os") || isPkg("io/ioutil")) && fsPathFuncs[name]:
		add(KindFSPath, callName(e)+" (filesystem path)")
	case recvIsIdent && isPkg("path/filepath") && name == "Join":
		if anyNonLit(e.Args) {
			add(KindFSPath, "filepath.Join with variable component")
		}

	// --- process execution ---
	case recvIsIdent && isPkg("os/exec") && (name == "Command" || name == "CommandContext"):
		detail := callName(e) + " (process exec)"
		if argInjectionRisk(e, name) {
			detail += " — shell-ish invocation (sh -c / bash -c style arg)"
		}
		add(KindExec, detail)

	// --- outbound network ---
	case recvIsIdent && isPkg("net/http") && (name == "NewRequest" || name == "NewRequestWithContext"):
		urlArg := 1
		if name == "NewRequestWithContext" {
			urlArg = 2
		}
		if len(e.Args) > urlArg && !isStringLit(e.Args[urlArg]) {
			add(KindNetOut, callName(e)+" with variable URL")
		} else {
			add(KindNetOut, callName(e)+" (literal URL)")
		}
	case recvIsIdent && isPkg("net/http") && (name == "Get" || name == "Post" || name == "Head" || name == "PostForm"):
		add(KindNetOut, callName(e)+" (outbound HTTP)")
	case recvIsIdent && isPkg("net") && (name == "Dial" || name == "DialTimeout" || name == "DialContext"):
		add(KindNetOut, callName(e)+" (outbound dial)")
	case name == "Do" && len(e.Args) == 1:
		// Heuristic: *http.Client.Do. Receiver type unresolved (AST-only).
		add(KindNetOut, "."+name+" (likely http.Client.Do; receiver type unresolved)")

	// --- SQL string building ---
	case sqlQueryMethods != nil && isSQLMethod(name):
		idx := sqlQueryMethods[name]
		if len(e.Args) > idx {
			q := e.Args[idx]
			if !isStringLit(q) {
				detail := "." + name + " with non-literal query string"
				if isSprintf(q, imports) {
					detail = "." + name + " built from fmt.Sprintf (string-built SQL)"
				}
				add(KindSQL, detail)
			}
		}

	// --- template / regexp compile from a variable ---
	case recvIsIdent && isPkg("regexp") && (name == "Compile" || name == "MustCompile" || name == "CompilePOSIX" || name == "MustCompilePOSIX"):
		if len(e.Args) > 0 && !isStringLit(e.Args[0]) {
			add(KindTemplate, "regexp."+name+" with variable pattern")
		}
	case name == "Parse" || name == "ParseFiles" || name == "ParseGlob":
		// template .Parse family (html/template or text/template). Receiver
		// type unresolved; only flag when the argument is a variable.
		if len(e.Args) > 0 && !isStringLit(e.Args[0]) {
			add(KindTemplate, "."+name+" with variable argument (likely template parse)")
		}

	// --- deserialization ---
	case recvIsIdent && (isPkg("gopkg.in/yaml.v3") || isPkg("gopkg.in/yaml.v2") || isPkg("sigs.k8s.io/yaml") || recv == "yaml") && name == "Unmarshal":
		add(KindDeserialize, "yaml.Unmarshal (target type unresolved)")
	case recvIsIdent && isPkg("encoding/json") && name == "Unmarshal":
		add(KindDeserialize, "json.Unmarshal (target type unresolved)")
	case recvIsIdent && isPkg("encoding/xml") && name == "Unmarshal":
		add(KindDeserialize, "xml.Unmarshal (target type unresolved)")
	}
}

func isSQLMethod(name string) bool { _, ok := sqlQueryMethods[name]; return ok }

// isSprintf reports whether e is a call to fmt.Sprintf/Sprint/Sprintln.
func isSprintf(e ast.Expr, imports map[string]string) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	if id.Name != "fmt" {
		return false
	}
	return strings.HasPrefix(sel.Sel.Name, "Sprint")
}

// argInjectionRisk flags an exec.Command whose program is a shell with a -c
// string argument (the classic argument-injection / shell-interpolation
// shape). Syntactic only.
func argInjectionRisk(e *ast.CallExpr, name string) bool {
	progIdx := 0
	if name == "CommandContext" {
		progIdx = 1
	}
	if len(e.Args) <= progIdx {
		return false
	}
	if bl, ok := e.Args[progIdx].(*ast.BasicLit); ok && bl.Kind == token.STRING {
		v := strings.Trim(bl.Value, `"`)
		if v == "sh" || v == "bash" || strings.HasSuffix(v, "/sh") || strings.HasSuffix(v, "/bash") {
			return true
		}
	}
	return false
}

func matchCompare(fset *token.FileSet, pkgRel, display string, e *ast.BinaryExpr, out *[]Sink) {
	if e.Op != token.EQL && e.Op != token.NEQ {
		return
	}
	if secretOperand(e.X) || secretOperand(e.Y) {
		pos := fset.Position(e.OpPos)
		*out = append(*out, Sink{
			Kind: KindCryptoCompare, File: pos.Filename, Line: pos.Line,
			Func: display, Pkg: pkgRel,
			Detail: "== / != on credential-named operand (operand type unresolved; may be []byte or string)",
		})
	}
}

// secretOperand reports whether an operand is an identifier/selector whose
// name looks like a credential. Name heuristic only — no type resolution.
func secretOperand(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return secretNameRe.MatchString(x.Name)
	case *ast.SelectorExpr:
		return secretNameRe.MatchString(x.Sel.Name)
	}
	return false
}

func anyNonLit(args []ast.Expr) bool {
	for _, a := range args {
		if !isStringLit(a) {
			return true
		}
	}
	return false
}

func lastElem(p string) string {
	return p[strings.LastIndexByte(p, '/')+1:]
}
