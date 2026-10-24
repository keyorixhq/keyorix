package main

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The three cases of CORE-SPLIT-DESIGN-1 section 7.3 on testdata trees:
// testdata/base is the "before" tree (package core with an in-package test),
// testdata/moved splits a file, exports defaultName and moves the test to
// package coretests with core. qualifiers, and testdata/changed is moved plus
// one changed token in helperT's body.

const moveFlags = "-dirs=internal/core,internal/core/coretests -strip=core -pkgmap=coretests=core -rename=defaultName=DefaultName"

func runProvemove(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String()
}

func tree(name string) string { return filepath.Join("testdata", name) }

func TestSelfCheckIsPureMove(t *testing.T) {
	code, out := runProvemove(t, "-base", tree("base"), "-head", tree("base"), "-dirs", "internal/core")
	if code != 0 || out != "PURE MOVE: 7 declarations identical\n" {
		t.Fatalf("self-check: exit %d, output %q", code, out)
	}
}

func TestSyntheticMoveIsPureMove(t *testing.T) {
	args := append([]string{"-base", tree("base"), "-head", tree("moved")}, strings.Fields(moveFlags)...)
	code, out := runProvemove(t, args...)
	if code != 0 || out != "PURE MOVE: 7 declarations identical\n" {
		t.Fatalf("file split + test moved to coretests with core. qualifiers: exit %d, output %q", code, out)
	}
}

func TestPlantedChangeIsRed(t *testing.T) {
	args := append([]string{"-base", tree("base"), "-head", tree("changed")}, strings.Fields(moveFlags)...)
	code, out := runProvemove(t, args...)
	want := "CHANGED body: core|func:helperT\nNOT A PURE MOVE: 1 difference(s), 6 declarations identical\n"
	if code != 1 || out != want {
		t.Fatalf("one-token body change: exit %d, output %q, want %q", code, out, want)
	}
}

func TestUndeclaredRenameIsRed(t *testing.T) {
	code, out := runProvemove(t, "-base", tree("base"), "-head", tree("moved"),
		"-dirs", "internal/core,internal/core/coretests", "-strip", "core", "-pkgmap", "coretests=core")
	for _, want := range []string{"ADDED in head: core|var:DefaultName", "MISSING in head: core|var:defaultName", "CHANGED body: core|func:helperT"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	if code != 1 {
		t.Fatalf("a rename the PR does not declare must be red, exit %d", code)
	}
}

func TestUsageErrors(t *testing.T) {
	if code, _ := runProvemove(t, "-base", tree("base")); code != 2 {
		t.Errorf("missing -head/-dirs: exit %d, want 2", code)
	}
	if code, _ := runProvemove(t, "-base", tree("base"), "-head", tree("base"), "-dirs", "internal/core", "-rename", "nope"); code != 2 {
		t.Errorf("malformed -rename: exit %d, want 2", code)
	}
}

func TestNormaliseStripsOnlyQualifiers(t *testing.T) {
	strip := map[string]bool{"core": true}
	if normalise(`f(core.X, "core.X", s.core.Y)`, strip) != normalise(`f(X, "core.X", s.core.Y)`, nil) {
		t.Error("core.X must become X; a string literal and a field named core must stay")
	}
	if normalise("a :=  1 // c\nb   := 2", nil) != normalise("a := 1\nb := 2", nil) {
		t.Error("whitespace and comments must not count")
	}
	if normalise("a := 1", nil) == normalise("a := 2", nil) {
		t.Error("a changed literal must count")
	}
}

// TestRepoSelfCheck is the design's "self-check on main's core + core/storage":
// the real tree compared with itself is a pure move.
func TestRepoSelfCheck(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	code, out := runProvemove(t, "-base", root, "-head", root, "-dirs", "internal/core,internal/core/storage")
	m := regexp.MustCompile(`^PURE MOVE: (\d+) declarations identical\n$`).FindStringSubmatch(out)
	if code != 0 || m == nil {
		t.Fatalf("self-check of internal/core: exit %d, output %q", code, out)
	}
	if n, _ := strconv.Atoi(m[1]); n < 5000 {
		t.Fatalf("only %d declarations read from internal/core and internal/core/storage: wrong root", n)
	}
}
