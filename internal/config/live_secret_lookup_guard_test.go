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

const secretenvImportPath = "github.com/keyorixhq/keyorix/internal/secretenv"

// liveSecretLookups returns one finding per use of secretenv.Lookup in src that
// bypasses secretSnapshot: a call whose name argument is a secretEnvNames
// secret, a call whose name is not a string literal (it cannot be shown not to
// be one), and any reference to Lookup that is not a call (a method value
// hides its argument). secretenv.LookupChecked is not covered: it is the key
// material rule, read and judged by its own consumer.
//
// Recognised forms: the import (with or without an alias) of the secretenv
// package and a selector on it; a dot import is not recognised (none exists, a
// new one would need this guard taught about it).
func liveSecretLookups(t *testing.T, filename string, src any, configSecret func(string) bool) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	local := ""
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p != secretenvImportPath {
			continue
		}
		local = "secretenv"
		if imp.Name != nil {
			local = imp.Name.Name
		}
	}
	if local == "" {
		return nil
	}
	isLookup := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Lookup" {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == local
	}
	var out []string
	called := map[ast.Expr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isLookup(call.Fun) {
			return true
		}
		called[call.Fun] = true
		pos := fset.Position(call.Pos())
		lit, isLit := ast.Expr(nil), false
		if len(call.Args) == 1 {
			lit = call.Args[0]
			_, isLit = lit.(*ast.BasicLit)
		}
		if !isLit {
			out = append(out, pos.String()+": secretenv.Lookup of a name that is not a string literal")
			return true
		}
		name, uerr := strconv.Unquote(lit.(*ast.BasicLit).Value)
		if uerr != nil || configSecret(name) {
			out = append(out, pos.String()+": secretenv.Lookup("+lit.(*ast.BasicLit).Value+") re-opens a secret config.Load snapshotted")
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok && isLookup(e) && !called[e] {
			out = append(out, fset.Position(e.Pos()).String()+": secretenv.Lookup referenced without a call")
		}
		return true
	})
	return out
}

// configSecretName reports whether name is one secretEnvNames can return: the
// fixed SecretEnvVars, the default Vault connector token, and the per-provider
// SSO client secret. (Operator-chosen names, such as a connector token_env, are
// not literals in code; a non-literal Lookup argument is itself a finding.)
func configSecretName(t *testing.T) func(string) bool {
	t.Helper()
	c := &Config{}
	c.Connect.Connectors = []ConnectorConfig{{Name: "v", Type: "vault"}}
	set := map[string]bool{}
	for _, n := range c.secretEnvNames() {
		set[n] = true
	}
	return func(name string) bool {
		return set[name] || (strings.HasPrefix(name, "KEYORIX_SSO_") && strings.HasSuffix(name, "_CLIENT_SECRET"))
	}
}

// TestNoLiveSecretenvLookupOfConfigSecrets (#3830): config.Load reads every
// non-key-material *_FILE secret once into secretSnapshot and the boot checks
// judge that descriptor. A server caller that re-opens the file with
// secretenv.Lookup can read a file the permission check never saw (the path
// retargeted between Load and use), so every such caller must use
// config.LookupSecretEnv. Outside internal/config and internal/secretenv, a
// non-test file must not call secretenv.Lookup on a secretEnvNames secret.
func TestNoLiveSecretenvLookupOfConfigSecrets(t *testing.T) {
	configSecret := configSecretName(t)
	root := filepath.Join("..", "..")
	skipDir := map[string]bool{".git": true, ".scratch": true, ".claude": true, "node_modules": true, "vendor": true, "web": true}
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
		findings = append(findings, liveSecretLookups(t, path, nil, configSecret)...)
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
		t.Errorf("%s: use config.LookupSecretEnv, which answers from the snapshot the boot checks judged", f)
	}
}

// TestLiveSecretLookupScanner_Calibration plants the shapes the guard exists
// for (red) and the shapes it must leave alone (green), so a guard that matches
// nothing cannot pass for one that works.
func TestLiveSecretLookupScanner_Calibration(t *testing.T) {
	configSecret := configSecretName(t)
	const head = "package p\nimport \"github.com/keyorixhq/keyorix/internal/secretenv\"\n"
	red := map[string]string{
		"literal config secret": head + "func f() { secretenv.Lookup(\"KEYORIX_BOOTSTRAP_TOKEN\") }\n",
		"default vault token":   head + "func f() { secretenv.Lookup(\"VAULT_TOKEN\") }\n",
		"sso client secret":     head + "func f() { secretenv.Lookup(\"KEYORIX_SSO_OKTA_CLIENT_SECRET\") }\n",
		"variable name":         head + "func f(n string) { secretenv.Lookup(n) }\n",
		"method value":          head + "func f() { g := secretenv.Lookup; _ = g }\n",
		"aliased import":        "package p\nimport se \"github.com/keyorixhq/keyorix/internal/secretenv\"\nfunc f() { se.Lookup(\"KEYORIX_SCIM_TOKEN\") }\n",
		"multiple results used": head + "func f() (string, error) { v, _, err := secretenv.Lookup(\"KEYORIX_DB_PASSWORD\"); return v, err }\n",
	}
	for name, src := range red {
		if got := liveSecretLookups(t, "planted.go", src, configSecret); len(got) == 0 {
			t.Errorf("planted %q was not flagged", name)
		}
	}
	green := map[string]string{
		"not a config secret":  head + "func f() { secretenv.Lookup(\"SOME_UNRELATED_ENV\") }\n",
		"key material checked": head + "func f() { secretenv.LookupChecked(\"KEYORIX_MASTER_PASSWORD\") }\n",
		"no secretenv import":  "package p\nfunc f() { Lookup(\"KEYORIX_BOOTSTRAP_TOKEN\") }\n",
		"unrelated package":    "package p\nimport secretenv \"example.com/other\"\nfunc f() { secretenv.Lookup(\"KEYORIX_BOOTSTRAP_TOKEN\") }\n",
	}
	for name, src := range green {
		if got := liveSecretLookups(t, "ok.go", src, configSecret); len(got) != 0 {
			t.Errorf("%q must not be flagged: %v", name, got)
		}
	}
}
