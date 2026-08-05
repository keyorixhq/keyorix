package contracttest

import (
	"os"
	"strings"
	"testing"
)

func TestGoBinary(t *testing.T) {
	t.Run("resolves a real, executable go binary", func(t *testing.T) {
		path, err := goBinary()
		if err != nil {
			t.Fatalf("expected goBinary to succeed, got: %v", err)
		}
		if info, statErr := os.Stat(path); statErr != nil || info.IsDir() {
			t.Errorf("goBinary returned %q, which does not stat as an executable file", path)
		}
	})

	t.Run("goroot pointing nowhere fails", func(t *testing.T) {
		if _, err := goBinaryFrom(t.TempDir()); err == nil {
			t.Error("expected an error when goroot points at a directory with no bin/go")
		}
	})
}

// TestResolveGoBinary_FallsBackToPATH covers the branch goBinary() itself
// can't reach in a normal test run: a goroot whose bin/go doesn't exist (the
// -trimpath / stale-GOROOT scenario) must still resolve "go" via PATH rather
// than fail outright, since a working toolchain is what's actually running
// this test.
func TestResolveGoBinary_FallsBackToPATH(t *testing.T) {
	path, err := resolveGoBinary(t.TempDir())
	if err != nil {
		t.Fatalf("expected a PATH fallback to succeed for a goroot with no bin/go, got: %v", err)
	}
	if info, statErr := os.Stat(path); statErr != nil || info.IsDir() {
		t.Errorf("resolveGoBinary returned %q, which does not stat as an executable file", path)
	}
}

// TestResolveGoBinary_NeitherGorootNorPATH covers the case neither
// candidate works at all, which real goBinary() can't observe (PATH always
// has a working go while running under `go test`).
func TestResolveGoBinary_NeitherGorootNorPATH(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := resolveGoBinary(t.TempDir()); err == nil {
		t.Error("expected an error when neither the goroot candidate nor PATH has a go binary")
	}
}

func TestRealTestNames_DirWithNoGoFiles(t *testing.T) {
	original := handlersPkgDir
	handlersPkgDir = t.TempDir()
	t.Cleanup(func() { handlersPkgDir = original })

	if _, err := realTestNames(); err == nil {
		t.Error("expected an error running `go test -list` against a directory with no Go files")
	}
}

func TestCheckExercisingTestsExist_PropagatesRealTestNamesError(t *testing.T) {
	original := handlersPkgDir
	handlersPkgDir = t.TempDir()
	t.Cleanup(func() { handlersPkgDir = original })

	err := CheckExercisingTestsExist()
	if err == nil {
		t.Fatal("expected an error when realTestNames itself fails")
	}
}

// TestCheckExercisingTestsExist_DetectsMissingName covers the actual
// comparison loop's "found something missing" branch -- every other test in
// this file only reaches CheckExercisingTestsExist's realTestNames() error
// branch or the happy path (the real registry is already consistent), never
// the case the check exists to catch: a renamed or deleted exercising test
// still named in the registry. A regression in the comparison itself (e.g.
// an inverted condition) would go undetected without this.
func TestCheckExercisingTestsExist_DetectsMissingName(t *testing.T) {
	const opID = "healthCheck" // a real, always-present operationId
	const bogusName = "TestThisFunctionDoesNotExistAnywhereInHandlers"

	original := exercisingTests[opID]
	exercisingTests[opID] = append(append([]string{}, original...), bogusName)
	t.Cleanup(func() { exercisingTests[opID] = original })

	err := CheckExercisingTestsExist()
	if err == nil {
		t.Fatal("expected an error when exercisingTests names a test function that does not exist")
	}
	if got := err.Error(); !strings.Contains(got, bogusName) {
		t.Errorf("error does not name the missing test %q: %s", bogusName, got)
	}
}
