package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain lets a test run main() in a child process (main calls os.Exit).
func TestMain(m *testing.M) {
	if os.Getenv("MUTATE_RUN_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runMutate(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "MUTATE_RUN_MAIN=1")
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), 0
}

const pkgLevelSrc = `package p

func f(a, b int) bool { return a < b }

var cur, lim = 1, 2
var over = cur > lim
`

// A mutation in a package-level var initialiser lies outside every FuncDecl.
// -clone must refuse it (no-node, exit 3): writing the previous function as
// f__mut would be an UNMUTATED clone and give a false likely-equivalent.
func TestClone_RefusesPackageLevelMutation(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "p.go")
	if err := os.WriteFile(src, []byte(pkgLevelSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	clone := filepath.Join(dir, "zz_clone_test.go")
	out, code := runMutate(t, "-file", src, "-line", "6", "-col", "16", "-type", "CONDITIONALS_BOUNDARY", "-clone", clone)
	if code != 3 || !strings.Contains(out, "no-node") {
		t.Fatalf("want no-node exit 3, got exit %d: %s", code, out)
	}
	if _, err := os.Stat(clone); !os.IsNotExist(err) {
		b, _ := os.ReadFile(clone)
		t.Fatalf("clone written for a package-level mutation:\n%s", b)
	}
}

// Before any FuncDecl there is no enclosing function at all; -clone must
// refuse instead of panicking on a nil FuncDecl.
func TestClone_RefusesMutationBeforeAnyFunc(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "p.go")
	if err := os.WriteFile(src, []byte("package p\n\nvar over = 1 > 2\n\nfunc f(a, b int) bool { return a < b }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runMutate(t, "-file", src, "-line", "3", "-col", "14", "-type", "CONDITIONALS_BOUNDARY", "-clone", filepath.Join(dir, "c_test.go"))
	if code != 3 || !strings.Contains(out, "no-node") {
		t.Fatalf("want no-node exit 3, got exit %d: %s", code, out)
	}
}

// The in-function case still clones, mutated.
func TestClone_MutatesEnclosingFunc(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "p.go")
	if err := os.WriteFile(src, []byte(pkgLevelSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	clone := filepath.Join(dir, "zz_clone_test.go")
	out, code := runMutate(t, "-file", src, "-line", "3", "-col", "34", "-type", "CONDITIONALS_BOUNDARY", "-clone", clone)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	b, err := os.ReadFile(clone)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "func f__mut(") || !strings.Contains(string(b), "a <= b") {
		t.Fatalf("clone is not the mutated f:\n%s", b)
	}
}
