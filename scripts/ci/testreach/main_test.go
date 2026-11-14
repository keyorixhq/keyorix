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
	const bSrc = `package p
import "testing"
func sharedFixture() int { return 2 }
func TestB(t *testing.T) { _ = sharedFixture() }
`
	r := writePkg(t, map[string]string{
		"p/p.go": pkgSrc,
		"p/a_test.go": `package p
import "testing"
func TestA(t *testing.T) {}
`,
		"p/b_test.go": bSrc,
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
	withBase(t, &r, map[string]string{"b_test.go": bSrc})
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

// A test that walks the tree and checks that cited paths exist observes a file
// elsewhere that no literal names (internal/docsdrift's TestDocLinksResolve
// failed when internal/core/INVARIANTS.md was deleted, and the first version of
// testreach did not select it). Any file-reading call is a seed, for every target.
func TestReach_ComputedPathReaderSeesEveryTarget(t *testing.T) {
	r := writePkg(t, map[string]string{
		"p/p.go": pkgSrc,
		"p/a_test.go": `package p
import ("io/fs"; "os"; "path/filepath"; "testing")
func repoRoot() string { return ".." }
func TestCitedPathsExist(t *testing.T) {
	_ = filepath.WalkDir(filepath.Join(repoRoot(), "docs"), func(p string, d fs.DirEntry, err error) error {
		_, serr := os.Stat(p)
		return serr
	})
}
func TestPure(t *testing.T) {}
`,
	})
	r.Targets = []target{{File: "internal/core/INVARIANTS.md"}}
	wantTests(t, analyse(r), "TestCitedPathsExist")
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

// withBase sets the request's base versions of its changed test files through
// the JSON the request is decoded from (mq_slim fills it from git show).
func withBase(t *testing.T, r *request, base map[string]string) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"base_test_sources": base})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, r); err != nil {
		t.Fatal(err)
	}
}

// The registry-row pattern (CLAUDE.md: one test file per row, registered from
// init()): reg_test.go checks the table, a_reg_test.go fills a row. Deleting
// a_reg_test.go breaks the package although no declaration left in the head
// tree is in a changed file, so nothing seeds and testreach used to answer
// "0 of 2 tests" (REVIEW-4196-DEEP-1 M1; server/faultops without
// best_effort_tables_entry_logauditevent_test.go gave "0 of 152").
const regSrc = `package p
import "testing"
var Registry = map[string]bool{}
func TestRegistryHasA(t *testing.T) { if !Registry["a"] { t.Fatal("no a") } }
func TestOther(t *testing.T) {}
`

func TestReach_DeletedTestFileSelectsEveryTest(t *testing.T) {
	r := writePkg(t, map[string]string{"p/p.go": pkgSrc, "p/reg_test.go": regSrc})
	r.Targets = outside("docs/guide.md")
	r.TestFiles = []string{"a_reg_test.go"}
	withBase(t, &r, map[string]string{"a_reg_test.go": "package p\nfunc init() { Registry[\"a\"] = true }\n"})
	wantAll(t, analyse(r), "a_reg_test.go")
}

// The same row removed from a test file that stays: the base version declared
// an init (or TestMain, or a var whose initialiser calls something), which ran
// in every test, so every test can observe its removal. A removed plain
// declaration seeds the head declarations that use its name, and a removed
// method seeds the users of its type.
func TestReach_RemovedInitSelectsEveryTest(t *testing.T) {
	for name, removed := range map[string]string{
		"init":            "func init() { Registry[\"a\"] = true }\n",
		"TestMain":        "func TestMain(m *testing.M) { Registry[\"a\"] = true; m.Run() }\n",
		"var with a call": "var _ = register(\"a\")\nfunc register(k string) bool { Registry[k] = true; return true }\n",
	} {
		t.Run(name, func(t *testing.T) {
			head := "package p\nimport \"testing\"\nfunc TestFromRow(t *testing.T) {}\n"
			r := writePkg(t, map[string]string{"p/p.go": pkgSrc, "p/reg_test.go": regSrc, "p/a_reg_test.go": head})
			r.Targets = outside("docs/guide.md")
			r.TestFiles = []string{"a_reg_test.go"}
			withBase(t, &r, map[string]string{"a_reg_test.go": head + removed})
			wantAll(t, analyse(r), "base version of a_reg_test.go")
		})
	}

	r := writePkg(t, map[string]string{
		"p/p.go": "package p\ntype Doc struct{}\nfunc Prod() int { return 1 }\n",
		"p/a_test.go": `package p
import ("fmt"; "testing")
func TestPrintsDoc(t *testing.T) { _ = fmt.Sprint(Doc{}) }
func TestUsesLimit(t *testing.T) { _ = limit }
func TestUnrelated(t *testing.T) { _ = Prod() }
`,
		"p/b_test.go": "package p\nvar limit = 3\n",
	})
	r.Targets = outside("docs/guide.md")
	r.TestFiles = []string{"b_test.go"}
	withBase(t, &r, map[string]string{"b_test.go": "package p\nvar limit = 3\nfunc (Doc) String() string { return \"doc\" }\n"})
	wantTests(t, analyse(r), "TestPrintsDoc", "TestUsesLimit")
}

// Without the base version of a changed test file nothing tells what it
// removed: every test (fail closed). An empty base is a file added by the
// change. An unparsable base also selects every test.
func TestReach_ChangedTestFileWithoutBaseSelectsEveryTest(t *testing.T) {
	src := map[string]string{"p/p.go": pkgSrc, "p/a_test.go": "package p\nimport \"testing\"\nfunc TestA(t *testing.T) {}\nfunc TestB(t *testing.T) {}\n"}
	r := writePkg(t, src)
	r.Targets = outside("docs/guide.md")
	r.TestFiles = []string{"a_test.go"}
	wantAll(t, analyse(r), "no base version")

	withBase(t, &r, map[string]string{"a_test.go": "package p\nfunc TestA(\n"})
	wantAll(t, analyse(r), "base version of a_test.go")

	withBase(t, &r, map[string]string{"a_test.go": ""})
	wantTests(t, analyse(r), "TestA", "TestB")
}
