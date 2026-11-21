package smtpauth

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

const (
	goMailPath   = "github.com/wneessen/go-mail"
	smtpauthPath = "github.com/keyorixhq/keyorix/internal/smtpauth"
)

// TestEveryGoMailClientAuthGoesThroughSmtpauth is the family guard for #4383: every
// production go-mail client that authenticates must get its mechanism from
// smtpauth.New, not from go-mail's own selection. It walks every non-test .go file
// of the repository (nested modules included) that imports go-mail and fails on:
//
//   - any reference to a go-mail SMTPAuth* value (SMTPAuthAutoDiscover, SMTPAuthPlain,
//     SMTPAuthSCRAMSHA256, ...) or to mail.WithSMTPAuth / Client.SetSMTPAuth: these let
//     go-mail pick or run a mechanism smtpauth does not bound;
//   - a mail.WithSMTPAuthCustom / Client.SetSMTPAuthCustom whose argument is not
//     written as a direct smtpauth.New(...) call.
//
// What it does NOT see: a go-mail fork or vendored copy under another import path,
// options built by reflection, and a custom smtp.Auth stored in a variable first
// (that last one is reported, not missed: write the smtpauth.New call inline).
// _test.go files are skipped: fuzz harnesses and the upstream-finding pin drive
// go-mail's own discovery on purpose.
func TestEveryGoMailClientAuthGoesThroughSmtpauth(t *testing.T) {
	g := guardrules.Rollout(t)
	root := srcpath.RepoRoot()
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata", ".scratch":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- walking the repository's own source tree
		if err != nil {
			return err
		}
		if !bytes.Contains(src, []byte(goMailPath)) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		findings, ok := checkGoMailAuth(rel, src)
		if !ok {
			return nil
		}
		scanned++
		for _, f := range findings {
			g.Errorf("%s", f)
		}
		return nil
	})
	if err != nil {
		g.Fatalf("walk %s: %v", root, err)
	}
	// internal/delivery/smtp.go and internal/notifychan/email.go build the two
	// production clients; a scan that finds neither is looking in the wrong place.
	if scanned < 2 {
		g.Errorf("scanned %d non-test files importing %s, want at least 2 (delivery and notifychan): the walk is broken", scanned, goMailPath)
	}
}

// checkGoMailAuth returns the findings for one source file. ok is false when the file
// does not import go-mail (the byte pre-check also matches comments).
func checkGoMailAuth(name string, src []byte) (findings []string, ok bool) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{name + ": parse: " + err.Error()}, true
	}
	mailName, authName := "", ""
	for _, imp := range file.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		local := ""
		if imp.Name != nil {
			local = imp.Name.Name
		}
		switch p {
		case goMailPath:
			mailName = or(local, "mail")
		case smtpauthPath:
			authName = or(local, "smtpauth")
		}
	}
	if mailName == "" {
		return nil, false
	}
	report := func(n ast.Node, msg string) {
		findings = append(findings, fset.Position(n.Pos()).String()+": "+msg)
	}
	isSmtpauthNew := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok || authName == "" {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == authName && sel.Sel.Name == "New"
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			id, isPkg := n.X.(*ast.Ident)
			fromMail := isPkg && id.Name == mailName
			switch {
			case fromMail && strings.HasPrefix(n.Sel.Name, "SMTPAuth"):
				report(n, mailName+"."+n.Sel.Name+": go-mail's own mechanism selection; use mail.WithSMTPAuthCustom(smtpauth.New(...)) (#4383)")
			case fromMail && n.Sel.Name == "WithSMTPAuth", n.Sel.Name == "SetSMTPAuth":
				report(n, n.Sel.Name+": go-mail's own mechanism selection; use mail.WithSMTPAuthCustom(smtpauth.New(...)) (#4383)")
			}
		case *ast.CallExpr:
			sel, ok := n.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, isPkg := sel.X.(*ast.Ident)
			custom := (isPkg && id.Name == mailName && sel.Sel.Name == "WithSMTPAuthCustom") || sel.Sel.Name == "SetSMTPAuthCustom"
			if custom && (len(n.Args) != 1 || !isSmtpauthNew(n.Args[0])) {
				report(n, sel.Sel.Name+" must be given smtpauth.New(...) directly, the only smtp.Auth that bounds SCRAM and keeps PLAIN/LOGIN/SCRAM off connections without TLS (#4383)")
			}
		}
		return true
	})
	return findings, true
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// The guard is only worth something if it fires on the shapes #4383 had and stays
// quiet on the fixed shape.
func TestCheckGoMailAuth_RedAndGreen(t *testing.T) {
	const head = "package p\nimport (\n\tmail \"github.com/wneessen/go-mail\"\n\t\"github.com/keyorixhq/keyorix/internal/smtpauth\"\n\t\"github.com/wneessen/go-mail/smtp\"\n)\nvar _ = smtp.Auth(nil)\nvar _ = smtpauth.New\n"
	cases := []struct {
		name, body string
		wantFinds  int
	}{
		{"fixed shape", "func f(c *mail.Client) { _ = mail.WithSMTPAuthCustom(smtpauth.New(\"u\", \"p\", \"h\")); c.SetSMTPAuthCustom(smtpauth.New(\"u\", \"p\", \"h\")) }", 0},
		{"auto discover (the #4383 shape)", "var o = []mail.Option{mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover)}", 2},
		{"fixed mechanism", "var o = mail.WithSMTPAuth(mail.SMTPAuthSCRAMSHA256)", 2},
		{"set on the client", "func f(c *mail.Client) { c.SetSMTPAuth(mail.SMTPAuthPlain) }", 2},
		{"custom auth not from smtpauth", "var o = mail.WithSMTPAuthCustom(smtp.PlainAuth(\"\", \"u\", \"p\", \"h\", false))", 1},
		{"custom auth via a variable", "var a = smtpauth.New(\"u\", \"p\", \"h\")\nvar o = mail.WithSMTPAuthCustom(a)", 1},
		{"custom auth set on the client", "func f(c *mail.Client, a smtp.Auth) { c.SetSMTPAuthCustom(a) }", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := checkGoMailAuth("p.go", []byte(head+tc.body+"\n"))
			if !ok {
				t.Fatal("file imports go-mail but was not checked")
			}
			if len(got) != tc.wantFinds {
				t.Fatalf("want %d findings, got %d: %q", tc.wantFinds, len(got), got)
			}
		})
	}
	t.Run("aliased import", func(t *testing.T) {
		src := "package p\nimport gm \"github.com/wneessen/go-mail\"\nvar o = gm.WithSMTPAuth(gm.SMTPAuthAutoDiscover)\n"
		if got, _ := checkGoMailAuth("p.go", []byte(src)); len(got) != 2 {
			t.Fatalf("aliased go-mail import: want 2 findings, got %q", got)
		}
	})
	t.Run("comment only is not an import", func(t *testing.T) {
		src := "package p\n// see github.com/wneessen/go-mail\nvar x = 1\n"
		if _, ok := checkGoMailAuth("p.go", []byte(src)); ok {
			t.Fatal("a file that only mentions go-mail in a comment was treated as importing it")
		}
	})
}
