package ci_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// toolModulePrefixes are the module path prefixes of CI tools that must never be
// a Go dependency of this repository. vacuum (the OpenAPI linter) and the pb33f
// libraries it is built from run only as the pinned, SHA-256-checked release
// binary (devtools/vacuum/VACUUM.pin + install.sh). On #4649 a Dependabot bump of
// vacuum's own dependency tree, carried in a go.mod of this repo, broke product
// dependencies; the class is closed by keeping the tool out of every go.mod.
//
// Scope: no legitimate product dependency on either prefix exists (checked
// 2026-11-23: no go.mod, go.sum or product .go file mentions them), so the guard
// covers every go.mod and go.work in the tree, not only the root one. Add a prefix here
// when another CI tool is moved to a pinned binary.
var toolModulePrefixes = []string{
	"github.com/daveshanley/",
	"github.com/pb33f/",
}

const toolModuleAdvice = "CI tools are not Go dependencies: they run as pinned release binaries whose SHA-256 is checked in " +
	"(devtools/vacuum/VACUUM.pin, installed by devtools/vacuum/install.sh), so a bump of a tool's own dependency " +
	"tree can never break a product build (#4649). Remove the requirement; to move vacuum, follow devtools/vacuum/README.md."

// findToolModuleRequires walks root for go.mod and go.work files and returns one
// "file:line: text" entry per line that names a module under toolModulePrefixes:
// a require (direct or indirect), replace, exclude, tool or use directive all
// show up the same way. Comments are ignored, so a note explaining why a tool is
// absent is allowed. testdata, node_modules, .git and .scratch are skipped.
func findToolModuleRequires(root string) ([]string, error) {
	var hits []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".scratch", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" && d.Name() != "go.work" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			if c := strings.Index(line, "//"); c >= 0 {
				line = line[:c]
			}
			for field := range strings.FieldsSeq(line) {
				field = strings.Trim(field, "\"`")
				for _, prefix := range toolModulePrefixes {
					if strings.HasPrefix(field, prefix) {
						hits = append(hits, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(rel), i+1, strings.TrimSpace(line)))
					}
				}
			}
		}
		return nil
	})
	sort.Strings(hits)
	return hits, err
}

// TestNoToolModuleInGoModGuard fails when any go.mod or go.work of the
// repository requires, replaces or lists as a tool a module under
// toolModulePrefixes (github.com/daveshanley/vacuum, github.com/pb33f/*). It
// reads the files themselves, not the module graph, so it also sees a tool added
// only to a nested module such as a revived devtools/vacuum/go.mod.
func TestNoToolModuleInGoModGuard(t *testing.T) {
	g := guardrules.Rollout(t)
	hits, err := findToolModuleRequires(filepath.Join("..", ".."))
	if err != nil {
		g.Fatalf("scanning go.mod files: %v", err)
	}
	if len(hits) > 0 {
		g.Fatalf("a CI tool module is required by a go.mod:\n  %s\n%s", strings.Join(hits, "\n  "), toolModuleAdvice)
	}
}

// TestToolModuleFinderCalibration proves findToolModuleRequires both ways on
// synthetic trees: it flags a require (single line and block), an indirect
// require, a replace, a tool directive and a go.work replace, in a root and a
// nested module; and it stays quiet on a clean module, on a comment that names a
// tool, on a look-alike path, and on files under testdata.
func TestToolModuleFinderCalibration(t *testing.T) {
	write := func(root, rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	clean := t.TempDir()
	write(clean, "go.mod", "module example.test/m\n\ngo 1.27\n\n// vacuum lives in devtools/vacuum/VACUUM.pin, never here: github.com/daveshanley/vacuum\n"+
		"require (\n\tgithub.com/daveshanleyfan/other v1.0.0\n\tgithub.com/pb33fish/x v1.0.0\n\texample.test/ok v1.0.0 // indirect, formerly github.com/pb33f/libopenapi\n)\n")
	write(clean, "testdata/go.mod", "module example.test/fixture\n\nrequire github.com/pb33f/libopenapi v0.1.0\n")
	write(clean, "web/node_modules/p/go.mod", "module example.test/p\n\nrequire github.com/daveshanley/vacuum v0.1.0\n")
	hits, err := findToolModuleRequires(clean)
	if err != nil || len(hits) != 0 {
		t.Fatalf("clean tree: hits=%v err=%v, want none", hits, err)
	}

	bad := t.TempDir()
	write(bad, "go.mod", "module example.test/m\n\nrequire github.com/daveshanley/vacuum v0.42.3\n")
	write(bad, "cli/go.mod", "module example.test/m/cli\n\nrequire (\n\texample.test/ok v1.0.0\n\tgithub.com/pb33f/libopenapi v0.1.0 // indirect\n)\n")
	write(bad, "devtools/vacuum/go.mod", "module example.test/vacuum\n\ntool github.com/daveshanley/vacuum\n")
	write(bad, "migrate/go.mod", "module example.test/migrate\n\nreplace example.test/ok => github.com/pb33f/doctor v0.1.0\n")
	write(bad, "go.work", "go 1.27\n\nuse .\n\nreplace github.com/pb33f/libopenapi => ../libopenapi\n")
	hits, err = findToolModuleRequires(bad)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"cli/go.mod:5: github.com/pb33f/libopenapi v0.1.0",
		"devtools/vacuum/go.mod:3: tool github.com/daveshanley/vacuum",
		"go.mod:3: require github.com/daveshanley/vacuum v0.42.3",
		"go.work:5: replace github.com/pb33f/libopenapi => ../libopenapi",
		"migrate/go.mod:3: replace example.test/ok => github.com/pb33f/doctor v0.1.0",
	}
	if strings.Join(hits, "\n") != strings.Join(want, "\n") {
		t.Fatalf("hits:\n%s\nwant:\n%s", strings.Join(hits, "\n"), strings.Join(want, "\n"))
	}
}
