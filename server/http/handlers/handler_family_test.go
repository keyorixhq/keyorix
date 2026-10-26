package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// handlerFamilySubdirs are the handler subpackages (server/http/handlers/<name>)
// whose non-test sources the source-scanning guards of this package read together
// with this package's own: they hold handlers (reports) and the shared response
// helpers (httpx) that used to live here, so a file moved out of this directory
// must not drop out of a guard. server/http's handler_family_test.go proves this
// list names every subdirectory that carries non-test Go code.
var handlerFamilySubdirs = []string{"httpx", "reports"}

// handlerFamilyGoFiles returns every non-test .go file directly in this directory
// and in each handlerFamilySubdirs directory, as paths relative to this directory.
func handlerFamilyGoFiles(t testing.TB) []string {
	t.Helper()
	var files []string
	for _, dir := range append([]string{"."}, handlerFamilySubdirs...) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			files = append(files, filepath.ToSlash(filepath.Join(dir, name)))
		}
	}
	return files
}

// TestHandlerFamilySubdirsCoverEverySubpackage is the walker-coverage guard for
// the guards of this package: every subdirectory with non-test Go code is in
// handlerFamilySubdirs, or is one of the two that hold no handlers and write no
// responses (contracttest, webauthnparse). server/http's copy of this list
// (handler_family_test.go there) is checked against the same directory.
func TestHandlerFamilySubdirsCoverEverySubpackage(t *testing.T) {
	notScanned := map[string]bool{"contracttest": true, "webauthnparse": true}
	inFamily := map[string]bool{}
	for _, s := range handlerFamilySubdirs {
		inFamily[s] = true
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub, err := os.ReadDir(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		hasGo := false
		for _, f := range sub {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".go") && !strings.HasSuffix(f.Name(), "_test.go") {
				hasGo = true
			}
		}
		if hasGo && !inFamily[e.Name()] && !notScanned[e.Name()] {
			t.Errorf("%s holds non-test Go code but is not in handlerFamilySubdirs: the source-scanning guards of this package would skip it", e.Name())
		}
		delete(inFamily, e.Name())
	}
	for name := range inFamily {
		t.Errorf("handlerFamilySubdirs names %s, which is not a subdirectory here", name)
	}
}
