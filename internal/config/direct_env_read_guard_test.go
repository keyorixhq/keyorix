package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// directEnvReads returns one finding per os.Getenv / os.LookupEnv / syscall.Getenv
// call in src whose argument is a string literal naming a secret that has a *_FILE
// form (isFileCapable). Such a read sees only the plain variable: a token supplied
// through <NAME>_FILE is invisible to it, and the file the boot checks judged is
// bypassed (#3830: the bootstrap token and the Vault tokens did this).
//
// Recognised forms: the "os" and "syscall" imports with or without an alias and a
// selector on them, called with a string literal. NOT recognised: a name held in a
// variable or built by concatenation (os.Getenv(n), os.Getenv(p+"_TOKEN")), a
// dot-import of os, and a hand-written <NAME>_FILE read -- the secretenv.Lookup
// guard (TestNoLiveSecretenvLookupOfConfigSecrets) and review cover those shapes.
func directEnvReads(t *testing.T, filename string, src any, isFileCapable func(string) bool) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	// local import name -> reader functions of that package.
	readers := map[string]map[string]bool{}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		var fns map[string]bool
		switch p {
		case "os":
			fns = map[string]bool{"Getenv": true, "LookupEnv": true}
		case "syscall":
			fns = map[string]bool{"Getenv": true}
		default:
			continue
		}
		local := p
		if imp.Name != nil {
			local = imp.Name.Name
		}
		readers[local] = fns
	}
	if len(readers) == 0 {
		return nil
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || !readers[id.Name][sel.Sel.Name] {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if name, uerr := strconv.Unquote(lit.Value); uerr == nil && isFileCapable(name) {
			out = append(out, fset.Position(call.Pos()).String()+": "+id.Name+"."+sel.Sel.Name+"("+lit.Value+") ignores "+name+"_FILE")
		}
		return true
	})
	return out
}

// TestNoDirectEnvReadOfFileCapableVars (#3830 class guard): outside
// internal/config and internal/secretenv no non-test file may read a secret that
// has a *_FILE form (secretEnvNames: bootstrap token, Vault token, DB password,
// SCIM token, ...) with os.Getenv / os.LookupEnv. Read it with
// config.LookupSecretEnv, which answers from the snapshot the boot checks judged.
// Client-side variables outside secretEnvNames (KEYORIX_TOKEN of the CLI, MCP and
// k8s-sync binaries) are not this guard's population.
func TestNoDirectEnvReadOfFileCapableVars(t *testing.T) {
	fileCapable := configSecretName(t)
	root := filepath.Join("..", "..")
	skipDir := map[string]bool{".git": true, ".scratch": true, ".claude": true, "node_modules": true, "vendor": true, "web": true, "testdata": true}
	exempt := map[string]bool{
		filepath.Join(root, "internal", "config"):    true,
		filepath.Join(root, "internal", "secretenv"): true,
	}
	var findings []string
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] || exempt[path] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		scanned++
		findings = append(findings, directEnvReads(t, path, nil, fileCapable)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files from %s: the walk is not seeing the repository", scanned, root)
	}
	sort.Strings(findings)
	for _, f := range findings {
		t.Errorf("%s: use config.LookupSecretEnv, which honours _FILE and answers from the boot snapshot", f)
	}
}

// TestDirectEnvReadScanner_Calibration plants the reads the guard exists for (red)
// and the ones it must leave alone (green), so a guard that matches nothing cannot
// pass for one that works.
func TestDirectEnvReadScanner_Calibration(t *testing.T) {
	fileCapable := configSecretName(t)
	red := map[string]string{
		"bootstrap token":  "package p\nimport \"os\"\nfunc f() string { return os.Getenv(\"KEYORIX_BOOTSTRAP_TOKEN\") }\n",
		"default vault":    "package p\nimport \"os\"\nfunc f() { _, _ = os.LookupEnv(\"VAULT_TOKEN\") }\n",
		"aliased os":       "package p\nimport o \"os\"\nfunc f() { _ = o.Getenv(\"KEYORIX_SCIM_TOKEN\") }\n",
		"syscall":          "package p\nimport \"syscall\"\nfunc f() { _, _ = syscall.Getenv(\"KEYORIX_DB_PASSWORD\") }\n",
		"sso client token": "package p\nimport \"os\"\nfunc f() { _ = os.Getenv(\"KEYORIX_SSO_OKTA_CLIENT_SECRET\") }\n",
	}
	for name, src := range red {
		if got := directEnvReads(t, "planted.go", src, fileCapable); len(got) != 1 {
			t.Errorf("planted %q: want 1 finding, got %v", name, got)
		}
	}
	green := map[string]string{
		"unrelated variable":  "package p\nimport \"os\"\nfunc f() { _ = os.Getenv(\"HOME\") }\n",
		"snapshot accessor":   "package p\nimport \"github.com/keyorixhq/keyorix/internal/config\"\nfunc f() { _, _, _ = config.LookupSecretEnv(\"KEYORIX_BOOTSTRAP_TOKEN\") }\n",
		"a different package": "package p\nimport os \"example.com/other\"\nfunc f() { _ = os.Getenv(\"KEYORIX_BOOTSTRAP_TOKEN\") }\n",
		"no os import":        "package p\nfunc f() { _ = Getenv(\"KEYORIX_BOOTSTRAP_TOKEN\") }\n",
		"the _FILE variable":  "package p\nimport \"os\"\nfunc f() { _ = os.Getenv(\"KEYORIX_BOOTSTRAP_TOKEN_FILE\") }\n",
	}
	for name, src := range green {
		if got := directEnvReads(t, "ok.go", src, fileCapable); len(got) != 0 {
			t.Errorf("%q must not be flagged: %v", name, got)
		}
	}
}
