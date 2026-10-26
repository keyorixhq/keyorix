package http

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// handlerFamilySubdirs are the handler subpackages (server/http/handlers/<name>)
// whose non-test sources the source-scanning guards of this package read together
// with server/http/handlers itself: they hold handlers (reports) and the shared
// response helpers (httpx) that used to live in handlers, so a file moved out of
// that directory must not drop out of a guard. The guards in package handlers use
// their own copy (handlers/handler_family_test.go); TestHandlerFamilyListsEverySubpackage
// keeps both lists, and the real directory, in step.
var handlerFamilySubdirs = []string{"httpx", "reports"}

// handlerFamilyGoPaths returns every non-test .go file directly in dir (the
// handlers directory, spelled the way the caller spells it) and in each
// handlerFamilySubdirs directory below it, as dir-prefixed paths.
func handlerFamilyGoPaths(dir string) ([]string, error) {
	var paths []string
	for _, d := range append([]string{dir}, familySubdirPaths(dir)...) {
		entries, err := os.ReadDir(d)
		if errors.Is(err, fs.ErrNotExist) && d != dir {
			// A fixture directory (the wire-actor guard's red-proof) has no subpackages;
			// for the real directory TestHandlerFamilyListsEverySubpackage fails on a
			// listed subdirectory that does not exist.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", d, err)
		}
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			paths = append(paths, filepath.Join(d, n))
		}
	}
	return paths, nil
}

func familySubdirPaths(dir string) []string {
	out := make([]string, 0, len(handlerFamilySubdirs))
	for _, s := range handlerFamilySubdirs {
		out = append(out, filepath.Join(dir, s))
	}
	return out
}

// handlerSubpackagesNotScanned are the subdirectories of server/http/handlers that
// carry non-test Go code but are deliberately not part of the handler family:
// contracttest and webauthnparse hold no handlers and write no responses.
var handlerSubpackagesNotScanned = map[string]string{
	"contracttest":  "test harness for the OpenAPI contract; no handlers, no response writes",
	"webauthnparse": "stdlib-only parser leaf (leaf_test.go); no handlers, no response writes",
}

// TestHandlerFamilyListsEverySubpackage is the walker-coverage guard for the
// handler family: every subdirectory of server/http/handlers that holds non-test
// Go code is either in handlerFamilySubdirs (the source-scanning guards read it)
// or listed in handlerSubpackagesNotScanned with a reason. A new handler subpackage
// therefore fails here until a person decides which of the two it is, instead of
// silently dropping out of every guard that walks the handlers directory.
func TestHandlerFamilyListsEverySubpackage(t *testing.T) {
	root := filepath.Join("handlers")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	inFamily := map[string]bool{}
	for _, s := range handlerFamilySubdirs {
		inFamily[s] = true
	}
	var problems []string
	seenSub := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub, err := os.ReadDir(filepath.Join(root, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		hasGo := false
		for _, f := range sub {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".go") && !strings.HasSuffix(f.Name(), "_test.go") {
				hasGo = true
			}
		}
		if !hasGo {
			continue
		}
		seenSub++
		_, skipped := handlerSubpackagesNotScanned[e.Name()]
		switch {
		case inFamily[e.Name()] && skipped:
			problems = append(problems, e.Name()+" is both in handlerFamilySubdirs and handlerSubpackagesNotScanned")
		case !inFamily[e.Name()] && !skipped:
			problems = append(problems, e.Name()+" holds non-test Go code but is in neither handlerFamilySubdirs nor handlerSubpackagesNotScanned: the source-scanning guards would silently skip it")
		}
		delete(inFamily, e.Name())
	}
	for name := range inFamily {
		problems = append(problems, "handlerFamilySubdirs names "+name+", which is not a handlers subdirectory with non-test Go code")
	}
	for name := range handlerSubpackagesNotScanned {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			problems = append(problems, "handlerSubpackagesNotScanned names "+name+", which does not exist: remove it")
		}
	}
	if seenSub == 0 {
		problems = append(problems, "no handler subpackage found at all: the guard is looking in the wrong place")
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}
