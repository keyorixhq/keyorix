package contracttest

import (
	"os"
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
