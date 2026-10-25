package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parseIfaces collects every interface TypeSpec of the given sources the way
// generate does, so the expansion tests exercise the same input shape.
func parseIfaces(t *testing.T, srcs ...string) map[string]*ast.InterfaceType {
	t.Helper()
	out := map[string]*ast.InterfaceType{}
	fset := token.NewFileSet()
	for i, src := range srcs {
		f, err := parser.ParseFile(fset, "f"+string(rune('a'+i))+".go", src, 0)
		if err != nil {
			t.Fatalf("parse fixture %d: %v", i, err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, s := range gd.Specs {
				if ts, ok := s.(*ast.TypeSpec); ok {
					if it, ok := ts.Type.(*ast.InterfaceType); ok {
						out[ts.Name.Name] = it
					}
				}
			}
		}
	}
	return out
}

func methodNames(fields []*ast.Field) []string {
	var out []string
	for _, f := range fields {
		out = append(out, f.Names[0].Name)
	}
	return out
}

// TestExpandInterface_FollowsEmbedsAcrossFiles: Storage embeds interfaces that
// live in other files and embed further interfaces; the methods come out in
// declaration order with every embed replaced in place.
func TestExpandInterface_FollowsEmbedsAcrossFiles(t *testing.T) {
	ifaces := parseIfaces(t,
		"package p\ntype Storage interface {\n\tA()\n\tUserStore\n\tZ()\n\tSecretStore\n}\n",
		"package p\ntype UserStore interface {\n\tGetUser()\n\tGroupStore\n}\n",
		"package p\ntype GroupStore interface {\n\tGetGroup()\n}\n",
		"package p\ntype SecretStore interface {\n\tGetSecret()\n}\n",
	)
	fields, err := expandInterface(ifaces, "Storage")
	if err != nil {
		t.Fatalf("expandInterface: %v", err)
	}
	got := strings.Join(methodNames(fields), ",")
	if want := "A,GetUser,GetGroup,Z,GetSecret"; got != want {
		t.Fatalf("methods = %s, want %s", got, want)
	}
}

func TestExpandInterface_RejectsUnknownCyclicAndUnsupportedEmbeds(t *testing.T) {
	cases := []struct {
		name    string
		srcs    []string
		wantErr string
	}{
		{"unknown", []string{"package p\ntype Storage interface {\n\tMissingStore\n}\n"}, "unknown interface MissingStore"},
		{"cycle", []string{"package p\ntype Storage interface {\n\tAStore\n}\ntype AStore interface {\n\tBStore\n}\ntype BStore interface {\n\tAStore\n}\n"}, "embedding cycle"},
		{"self cycle", []string{"package p\ntype Storage interface {\n\tStorage\n}\n"}, "embedding cycle"},
		{"qualified", []string{"package p\ntype Storage interface {\n\tfmt.Stringer\n}\n"}, "unsupported embedded type"},
		{"missing root", []string{"package p\ntype Other interface {\n\tA()\n}\n"}, "interface Storage not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := expandInterface(parseIfaces(t, tc.srcs...), "Storage")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestGenerate_EmbeddedFixture runs the whole generator over a throwaway
// storage package whose Storage is only a composition of embedded interfaces
// declared in other files, and checks the wrappers come out sorted by method
// name regardless of which embed declared them.
func TestGenerate_EmbeddedFixture(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, storagePkgDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"interface.go": "package storage\n\ntype Storage interface {\n\tUserStore\n\tSecretStore\n}\n",
		"iface_user.go": "package storage\n\nimport \"context\"\n\ntype UserStore interface {\n" +
			"\tGetUser(ctx context.Context, id uint) (string, error)\n}\n",
		"iface_secret.go": "package storage\n\nimport (\n\t\"context\"\n\t\"time\"\n)\n\ntype SecretStore interface {\n" +
			"\tCreateSecret(ctx context.Context, at time.Time) error\n\tAnotherThing(ctx context.Context, f Filter) error\n}\n\n" +
			"type Filter struct{}\n",
		"ignored_test.go": "package storage\n\ntype Storage2 interface {\n\tNotCollected()\n}\n",
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, _, n, total, err := generate(root)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if n != 3 || total != 3 {
		t.Fatalf("generated %d of %d methods, want 3 of 3", n, total)
	}
	src := string(out)
	posA := strings.Index(src, ") AnotherThing(")
	posC := strings.Index(src, ") CreateSecret(")
	posG := strings.Index(src, ") GetUser(")
	if posA < 0 || posC < 0 || posG < 0 || posA >= posC || posC >= posG {
		t.Fatalf("expected AnotherThing, CreateSecret, GetUser wrappers in that order, got positions %d %d %d", posA, posC, posG)
	}
	if strings.Contains(src, "NotCollected") {
		t.Fatal("methods of a _test.go interface leaked into the output")
	}
	if !strings.Contains(src, "storage.Filter") {
		t.Fatal("a type declared in a non-interface file was not qualified with storage.")
	}
}

// TestGenerate_RejectsDuplicateMethodAcrossEmbeds: the same method name from two
// embedded interfaces would emit two wrappers and fail to compile later; refuse
// it here with a message that names the method.
func TestGenerate_RejectsDuplicateMethodAcrossEmbeds(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, storagePkgDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	src := "package storage\n\nimport \"context\"\n\ntype Storage interface {\n\tAStore\n\tBStore\n}\n" +
		"type AStore interface {\n\tDo(ctx context.Context) error\n}\n" +
		"type BStore interface {\n\tDo(ctx context.Context) error\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "interface.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, err := generate(root)
	if err == nil || !strings.Contains(err.Error(), "method Do is declared by more than one") {
		t.Fatalf("err = %v, want a duplicate-method error naming Do", err)
	}
}

// TestGenerate_IsDeterministic runs the generator twice in-process over the
// real storage package and requires identical output. The freshness test in
// the parent package (generated_fresh_test.go) is only sound if this holds: a
// generator whose output depended on map iteration or directory order would
// make that test flake instead of reporting real drift. It does not cover
// cross-toolchain go/format differences. Validated red by taking method order
// from map iteration instead of sort.Slice; dropping the import-name sort does
// NOT turn it red, because go/format re-sorts a single import block anyway.
func TestGenerate_IsDeterministic(t *testing.T) {
	root, err := findModuleRoot(".")
	if err != nil {
		t.Fatalf("findModuleRoot from the gen package dir: %v", err)
	}
	first, _, n, _, err := generate(root)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if n == 0 {
		t.Fatal("generate emitted zero methods; the fixture is not exercising the generator")
	}
	for i := range 5 {
		again, _, _, _, err := generate(root)
		if err != nil {
			t.Fatalf("generate (run %d): %v", i+2, err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("generator output differs between run 1 and run %d: output is non-deterministic", i+2)
		}
	}
}
