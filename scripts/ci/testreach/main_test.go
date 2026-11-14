package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writePkg lays out one package directory "p" under a fresh working
// directory and returns a request for it.
func writePkg(t *testing.T, files map[string]string) request {
	t.Helper()
	root := t.TempDir()
	t.Chdir(root)
	for name, src := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return request{Dir: "p", ImportPath: "example.com/p"}
}

func outside(files ...string) []target {
	var ts []target
	for _, f := range files {
		ts = append(ts, target{File: f, Outside: true})
	}
	return ts
}

func wantTests(t *testing.T, r result, want ...string) {
	t.Helper()
	if r.All {
		t.Fatalf("got ALL tests (%s), want exactly %v", r.Reason, want)
	}
	if !slices.Equal(r.Tests, want) {
		t.Fatalf("tests=%v (%s), want %v", r.Tests, r.Reason, want)
	}
}

func wantAll(t *testing.T, r result, reasonPart string) {
	t.Helper()
	if !r.All {
		t.Fatalf("tests=%v (%s), want ALL", r.Tests, r.Reason)
	}
	if !strings.Contains(r.Reason, reasonPart) {
		t.Fatalf("reason %q, want it to mention %q", r.Reason, reasonPart)
	}
}

const pkgSrc = "package p\n\nfunc Prod() int { return 1 }\n"

// A literal naming the changed file selects the tests that reach it, through
// helpers, methods called by name and types whose methods hold it; a test
// that reaches none of them is left out.
func TestReach_LiteralSelectsOnlyTheTestsThatReachIt(t *testing.T) {
	r := writePkg(t, map[string]string{
		"p/p.go": pkgSrc,
		"p/a_test.go": `package p
import ("os"; "testing")
type doc struct{}
func (doc) load() string { b, _ := os.ReadFile("../docs/guide.md"); return string(b) }
func helper() string { var d doc; return d.load() }
func TestReadsGuide(t *testing.T) { _ = helper() }
func TestUnrelated(t *testing.T) { _ = Prod() }
func TestCallsMethodByName(t *testing.T) { var x interface{ load() string } = doc{}; _ = x.load() }
`,
	})
	r.Targets = outside("docs/guide.md")
	wantTests(t, analyse(r), "TestCallsMethodByName", "TestReadsGuide")
}

// A method another package calls (fmt calling String) is reached through
// the type alone: the test package never names the method.
func TestReach_TypeReachesItsMethods(t *testing.T) {
	r := writePkg(t, map[string]string{
		"p/p.go": pkgSrc,
		"p/a_test.go": `package p
import ("fmt"; "os"; "testing")
type doc struct{}
func (doc) String() string { b, _ := os.ReadFile("../docs/guide.md"); return string(b) }
func TestPrintsDoc(t *testing.T) { _ = fmt.Sprint(doc{}) }
func TestUnrelated(t *testing.T) { _ = fmt.Sprint(1) }
`,
	})
	r.Targets = outside("docs/guide.md")
	wantTests(t, analyse(r), "TestPrintsDoc")
}

// The same literal, but the target sits elsewhere: nothing is selected, and a
// changed test file selects its own tests and their users.
func TestReach_ChangedTestFileSelectsItsDeclarations(t *testing.T) {
	r := writePkg(t, map[string]string{
		"p/p.go": pkgSrc,
		"p/a_test.go": `package p
import "testing"
func TestA(t *testing.T) {}
`,
		"p/b_test.go": `package p
import "testing"
func sharedFixture() int { return 2 }
func TestB(t *testing.T) { _ = sharedFixture() }
`,
		"p/c_test.go": `package p
import "testing"
func TestC(t *testing.T) { _ = sharedFixture() }
`,
	})
	r.Targets = outside("docs/other.md")
	none := analyse(r)
	wantTests(t, none)
	// An empty selection is [] in the JSON, never null: mq_slim iterates it
	// (a null crashed the lever on 9 of 60 replayed rounds).
	if b, _ := json.Marshal(none); !strings.Contains(string(b), `"tests":[]`) {
		t.Fatalf("empty selection encodes as %s, want \"tests\":[]", b)
	}
	r.TestFiles = []string{"b_test.go"}
	wantTests(t, analyse(r), "TestB", "TestC")
}

// init, TestMain and package-level initialisers that call something run in
// every test: reaching a seed from one selects everything. A plain data var
// is reached only through its users.
func TestReach_GlobalsSelectEverything(t *testing.T) {
	for name, src := range map[string]string{
		"init":            `func init() { _ = load() }`,
		"TestMain":        `func TestMain(m *testing.M) { _ = load(); m.Run() }`,
		"var with a call": `var loaded = load()`,
	} {
		t.Run(name, func(t *testing.T) {
			r := writePkg(t, map[string]string{
				"p/p.go": pkgSrc,
				"p/a_test.go": "package p\nimport \"testing\"\nfunc load() string { return \"docs/guide.md\" }\n" + src +
					"\nfunc TestA(t *testing.T) {}\nfunc TestB(t *testing.T) {}\n",
			})
			r.Targets = outside("docs/guide.md")
			wantAll(t, analyse(r), "runs in every test")
		})
	}
	r := writePkg(t, map[string]string{
		"p/p.go": pkgSrc,
		"p/a_test.go": `package p
import "testing"
var skipDirs = []string{"web", "docs/guide.md"}
func TestUsesData(t *testing.T) { _ = skipDirs }
func TestOther(t *testing.T) {}
`,
	})
	r.Targets = outside("docs/guide.md")
	wantTests(t, analyse(r), "TestUsesData")
}

// A non-Go file in the package's own directory is reached by a relative
// literal, by ".", by a glob, and by any file-reading call or a reader
// import, none of which name it.
func TestReach_InputInPackageDirectory(t *testing.T) {
	cases := map[string]string{
		"relative literal": `func TestX(t *testing.T) { _, _ = os.ReadFile("testdata/golden.json") }`,
		"dot literal":      `func TestX(t *testing.T) { _ = os.Getenv("."); _ = "." }`,
		"glob literal":     `func TestX(t *testing.T) { _ = "*.json" }`,
		"readdir call":     `func TestX(t *testing.T) { _, _ = os.ReadDir(dir()) }; func dir() string { return t0 }; var t0 string`,
		"walk call":        `func TestX(t *testing.T) { _ = filepath.WalkDir(t0, nil) }; var t0 string`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := writePkg(t, map[string]string{
				"p/p.go":                 pkgSrc,
				"p/testdata/golden.json": "{}",
				"p/a_test.go":            "package p\nimport (\"os\"; \"path/filepath\"; \"testing\")\nvar _ = filepath.Join\nvar _ = os.Getenv\n" + body + "\nfunc TestNoFiles(t *testing.T) { _ = Prod() }\n",
			})
			r.Targets = []target{{File: "p/testdata/golden.json"}}
			wantTests(t, analyse(r), "TestX")
		})
	}
	r := writePkg(t, map[string]string{
		"p/p.go": pkgSrc,
		"p/a_test.go": `package p
import ("testing"; "example.com/srcpath")
func TestUsesReader(t *testing.T) { _ = srcpath.Root() }
func TestNoFiles(t *testing.T) {}
`,
	})
	r.Targets = []target{{File: "p/INVARIANTS.md"}}
	r.ReaderImports = []string{"example.com/srcpath"}
	wantTests(t, analyse(r), "TestUsesReader")
}

// A one-word directory literal names a target only when the target is
// outside every package (select-affected.py's rule 3), and a .go target is
// named by path, never by its basename.
func TestReach_RuleThreeSemantics(t *testing.T) {
	src := map[string]string{
		"p/p.go": pkgSrc,
		"p/a_test.go": `package p
import "testing"
func TestWeb(t *testing.T) { _ = "web" }
func TestMainGo(t *testing.T) { _ = "main.go" }
func TestPath(t *testing.T) { _ = "internal/q/main.go" }
`,
	}
	r := writePkg(t, src)
	r.Targets = []target{{File: "web/e2e/x.spec.ts", Outside: true}}
	wantTests(t, analyse(r), "TestWeb")
	r.Targets = []target{{File: "web/e2e/x.spec.ts", Outside: false}}
	wantTests(t, analyse(r))
	r.Targets = []target{{File: "internal/q/main.go"}}
	wantTests(t, analyse(r), "TestPath")
}

// seed_imports, a chain package's init and the fuzz corpus.
func TestReach_ImportsChainAndCorpus(t *testing.T) {
	r := writePkg(t, map[string]string{
		"p/p.go": pkgSrc,
		"p/a_test.go": `package p
import ("testing"; "example.com/statemap")
func TestUsesStatemap(t *testing.T) { _ = statemap.Load() }
func FuzzParse(f *testing.F) {}
func TestOther(t *testing.T) {}
`,
		"q/q.go": "package q\nfunc init() { register(\"docs/guide.md\") }\nfunc register(string) {}\n",
		"r/r.go": "package r\nfunc Helper() string { return \"docs/guide.md\" }\n",
	})
	r.Targets = outside("docs/guide.md")
	r.SeedImports = []string{"example.com/statemap"}
	wantTests(t, analyse(r), "TestUsesStatemap")

	r.SeedImports = nil
	r.Targets = []target{{File: "p/testdata/fuzz/FuzzParse/seed1"}}
	wantTests(t, analyse(r), "FuzzParse")

	r.Targets = outside("docs/guide.md")
	r.Chain = []chainPkg{{Dir: "r", IsSeed: true}}
	wantTests(t, analyse(r))
	r.Chain = []chainPkg{{Dir: "q", IsSeed: true}}
	wantAll(t, analyse(r), "runs in every test binary that links it")
}

// What cannot be analysed by name falls back to every test.
func TestReach_FallsBackToAll(t *testing.T) {
	for name, src := range map[string]string{
		"dot import":  "package p\nimport (\"testing\"; . \"strings\")\nvar _ = ToUpper\nfunc TestA(t *testing.T) {}\n",
		"linkname":    "package p\nimport (\"testing\"; _ \"unsafe\")\n//go:linkname x runtime.x\nvar x int\nfunc TestA(t *testing.T) {}\n",
		"test embed":  "package p\nimport (\"testing\"; _ \"embed\")\n//go:embed testdata\nvar fs string\nfunc TestA(t *testing.T) {}\n",
		"parse error": "package p\nfunc TestA(t *testing.T) {\n",
	} {
		t.Run(name, func(t *testing.T) {
			r := writePkg(t, map[string]string{"p/p.go": pkgSrc, "p/a_test.go": src})
			r.Targets = outside("docs/guide.md")
			if got := analyse(r); !got.All {
				t.Fatalf("tests=%v (%s), want ALL", got.Tests, got.Reason)
			}
		})
	}
}

func TestIsTestName(t *testing.T) {
	for n, want := range map[string]bool{"Test": true, "TestX": true, "Test_x": true, "Testify": false, "FuzzY": true, "Example": true, "ExampleFoo": true, "Examples": false, "helper": false} {
		if got := isTestName(n); got != want {
			t.Errorf("isTestName(%q)=%v, want %v", n, got, want)
		}
	}
}
