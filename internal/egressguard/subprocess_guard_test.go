package egressguard

// The subprocess half of the egress guard. egress_inventory_guard_test.go sees the
// Go network call sites; a child process the server, the CLI or an operator's
// configuration starts is outside that view, because the child may open any
// connection it likes. This file makes the other half of the claim checkable:
// every place shipped code starts a process is listed in the "Subprocess call
// sites" table of docs/security/egress-inventory.md with a class, what it runs,
// who sets the command line and whether it can reach the network.
//
// How the set of sites is established (and why it is complete for the forms it
// knows). Every non-test .go file under the repository root is parsed, in every
// module, skipping what the network guard skips plus the files of its DEV rows
// (scripts/, examples/, ...: development tooling the DEV import check proves is
// not imported by shipped code). A file is a site when it references, through its
// own import names (aliases are followed), one of subprocessForms, or builds an
// exec.Cmd value directly. A bare reference counts, not only a call, so
// `run := exec.Command` is found. A site is keyed by file and enclosing function;
// a package-level initialiser is function "<package>". The row key carries no line
// number, so an unrelated edit above a site does not stale the table.
//
// What it does NOT cover:
//   - A process started by a library we import (a cloud SDK shelling out to a
//     credential helper, a database driver). Only our own call sites are seen.
//   - Anything the child does: the "Reaches the network" column is reviewed prose,
//     not derived.
//   - Shell strings: a site that runs `sh -c <string>` is still one site; the row
//     must say who builds the string.
//   - Processes started by shell scripts, Dockerfiles, Helm hooks or workflows.
//   - Reflection and code generated at run time.
//
// Rollout: report-only on its first day (docs/guard-rollout-contract.md,
// docs/guard-rollout.d/TestEgressSubprocessSitesAreInventoried.tsv).

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

const subprocessSection = "Subprocess call sites"

// subprocessClasses are the classes a row may use. The legend table of the
// inventory document must define exactly these.
var subprocessClasses = []string{"EXEC-OPERATOR-CONFIGURED", "EXEC-LOCAL-ONLY", "EXEC-USER-COMMAND"}

// subprocessForms: a reference to any of these symbols of the package starts a
// process. The package name must equal the last path element.
var subprocessForms = map[string][]string{
	"os/exec":                  {"Command", "CommandContext"},
	"golang.org/x/sys/execabs": {"Command", "CommandContext"}, // drop-in for os/exec
	"syscall":                  {"Exec", "ForkExec"},
	"os":                       {"StartProcess"},
	"golang.org/x/sys/unix":    {"Exec"},
}

// subprocessTypeForms: constructing a value of the type (a literal, new(T), var T)
// builds a command without Command(); a parameter or field of the type does not.
var subprocessTypeForms = map[string][]string{
	"os/exec": {"Cmd"},
}

// subprocessSite is one place a file starts a process.
type subprocessSite struct {
	File string // slash-separated, relative to the repository root
	Func string // enclosing function ("Recv.Name" for a method), "<package>" outside one
	Line int
	Form string // e.g. "os/exec.Command"
}

func (s subprocessSite) key() string { return s.File + "\x00" + s.Func }

// funcName names a declaration the way the table does.
func funcName(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	t := d.Recv.List[0].Type
	if st, ok := t.(*ast.StarExpr); ok {
		t = st.X
	}
	if ix, ok := t.(*ast.IndexExpr); ok { // generic receiver T[P]
		t = ix.X
	}
	if ix, ok := t.(*ast.IndexListExpr); ok {
		t = ix.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + d.Name.Name
	}
	return d.Name.Name
}

// scanSubprocessSource returns the subprocess sites of one parsed file.
func scanSubprocessSource(fset *token.FileSet, f *ast.File, rel string) []subprocessSite {
	names := localNames(f)
	var out []subprocessSite
	inspect := func(fn string, root ast.Node) {
		add := func(pos token.Pos, form string) {
			out = append(out, subprocessSite{File: rel, Func: fn, Line: fset.Position(pos).Line, Form: form})
		}
		typeHit := func(e ast.Expr) (string, bool) {
			p, sym, ok := selector(names, e)
			if ok && slices.Contains(subprocessTypeForms[p], sym) {
				return p + "." + sym, true
			}
			return "", false
		}
		ast.Inspect(root, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if p, sym, ok := selector(names, x); ok && slices.Contains(subprocessForms[p], sym) {
					add(x.Pos(), p+"."+sym)
				}
			case *ast.CompositeLit:
				if form, ok := typeHit(x.Type); ok {
					add(x.Pos(), form+"{}")
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
					if form, ok := typeHit(x.Args[0]); ok {
						add(x.Pos(), "new("+form+")")
					}
				}
			case *ast.ValueSpec:
				if x.Type != nil {
					if form, ok := typeHit(x.Type); ok {
						add(x.Pos(), "var "+form)
					}
				}
			}
			return true
		})
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			inspect(funcName(fd), fd)
			continue
		}
		inspect("<package>", d)
	}
	return out
}

// scanSubprocessTree parses every non-test Go file under root that no DEV row covers.
func scanSubprocessTree(root string, dev []allowRow) ([]subprocessSite, error) {
	var all []subprocessSite
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDir(root, p) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		relOS, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(relOS)
		if slices.ContainsFunc(dev, func(r allowRow) bool { return r.covers(rel) }) {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		all = append(all, scanSubprocessSource(fset, f, rel)...)
		return nil
	})
	return all, err
}

// subprocessRow is one row of the "Subprocess call sites" table.
type subprocessRow struct {
	File, Func, Class string
	Runs, SetBy, Net  string
}

func (r subprocessRow) key() string { return r.File + "\x00" + r.Func }

var (
	subprocessRowRe    = regexp.MustCompile("^\\|\\s*`([^`|]+)`\\s*\\|\\s*`([^`|]+)`\\s*\\|\\s*(\\S+)\\s*\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|\\s*$")
	subprocessLegendRe = regexp.MustCompile(`(?m)^\|\s*(EXEC-[A-Z-]+)\s*\|`)
)

// sectionOf returns the text under the "## <title>" heading up to the next "## ".
func sectionOf(doc, title string) (string, bool) {
	lines := strings.Split(doc, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "## "+title {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return "", false
	}
	end := len(lines)
	for i := start; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "## ") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n"), true
}

// parseSubprocessTable reads the legend (class ids) and the site rows of the
// subprocess section of the inventory document.
func parseSubprocessTable(doc string) (rows []subprocessRow, legend map[string]bool, err error) {
	sec, ok := sectionOf(doc, subprocessSection)
	if !ok {
		return nil, nil, fmt.Errorf("%s has no \"## %s\" section", inventoryRel, subprocessSection)
	}
	legend = map[string]bool{}
	for _, m := range subprocessLegendRe.FindAllStringSubmatch(sec, -1) {
		legend[m[1]] = true
	}
	seen := map[string]bool{}
	for line := range strings.SplitSeq(sec, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		m := subprocessRowRe.FindStringSubmatch(line)
		if m == nil {
			return nil, nil, fmt.Errorf("%s: malformed subprocess row %q: want | `file` | `function` | class | runs | command line set by | reaches the network |", inventoryRel, line)
		}
		r := subprocessRow{File: m[1], Func: m[2], Class: m[3], Runs: strings.TrimSpace(m[4]), SetBy: strings.TrimSpace(m[5]), Net: strings.TrimSpace(m[6])}
		if r.Runs == "" || r.SetBy == "" || r.Net == "" {
			return nil, nil, fmt.Errorf("%s: subprocess row for %s %s has an empty column: say what it runs, who sets the command line and whether it can reach the network", inventoryRel, r.File, r.Func)
		}
		if seen[r.key()] {
			return nil, nil, fmt.Errorf("%s: duplicate subprocess row for %s %s", inventoryRel, r.File, r.Func)
		}
		seen[r.key()] = true
		rows = append(rows, r)
	}
	return rows, legend, nil
}

// checkSubprocesses returns one message per violation: a site no row covers, a row
// that covers no site, a row with a class the legend does not define, a legend
// class no row uses, and a legend that differs from subprocessClasses.
func checkSubprocesses(sites []subprocessSite, rows []subprocessRow, legend map[string]bool) []string {
	var msgs []string
	siteKeys := map[string]bool{}
	for _, s := range sites {
		siteKeys[s.key()] = true
	}
	rowKeys := map[string]bool{}
	for _, r := range rows {
		rowKeys[r.key()] = true
	}
	// One message per uncovered (file, function), naming its first site and every form.
	type agg struct {
		line  int
		forms []string
	}
	missing := map[string]*agg{}
	var order []subprocessSite
	for _, s := range sites {
		if rowKeys[s.key()] {
			continue
		}
		a, ok := missing[s.key()]
		if !ok {
			a = &agg{line: s.Line}
			missing[s.key()] = a
			order = append(order, s)
		}
		a.line = min(a.line, s.Line)
		if !slices.Contains(a.forms, s.Form) {
			a.forms = append(a.forms, s.Form)
		}
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].File != order[j].File {
			return order[i].File < order[j].File
		}
		return order[i].Func < order[j].Func
	})
	for _, s := range order {
		a := missing[s.key()]
		sort.Strings(a.forms)
		msgs = append(msgs, fmt.Sprintf("%s:%d starts a subprocess (%s) in %s and has no row in the %q table of %s: add | `%s` | `%s` | <%s> | what it runs | who sets the command line | can it reach the network |",
			s.File, a.line, strings.Join(a.forms, ", "), s.Func, subprocessSection, inventoryRel, s.File, s.Func, strings.Join(subprocessClasses, " | ")))
	}
	used := map[string]bool{}
	for _, r := range rows {
		if !siteKeys[r.key()] {
			msgs = append(msgs, fmt.Sprintf("%s: subprocess row `%s` `%s` covers no call site any more: delete it", inventoryRel, r.File, r.Func))
		}
		used[r.Class] = true
		if !legend[r.Class] {
			msgs = append(msgs, fmt.Sprintf("%s: subprocess row `%s` `%s` names class %s, which the legend of that section does not define", inventoryRel, r.File, r.Func, r.Class))
		}
	}
	var ids []string
	for id := range legend {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !slices.Contains(subprocessClasses, id) {
			msgs = append(msgs, fmt.Sprintf("%s: legend class %s is not one of %s", inventoryRel, id, strings.Join(subprocessClasses, ", ")))
		} else if !used[id] {
			msgs = append(msgs, fmt.Sprintf("%s: legend class %s has no subprocess row: the class is a claim with no code behind it", inventoryRel, id))
		}
	}
	for _, c := range subprocessClasses {
		if !legend[c] {
			msgs = append(msgs, fmt.Sprintf("%s: the legend of the %q section does not define class %s", inventoryRel, subprocessSection, c))
		}
	}
	return msgs
}

// TestEgressSubprocessSitesAreInventoried: every place shipped code starts a
// process has a row (class, what it runs, who sets the command line, whether it can
// reach the network) in the subprocess table of the egress inventory.
func TestEgressSubprocessSitesAreInventoried(t *testing.T) {
	g := guardrules.Rollout(t)
	root, rows, _ := loadRepoFiles(g)
	doc, err := os.ReadFile(filepath.Join(root, inventoryRel)) // #nosec G304 -- fixed path under the repository root
	require.NoError(g, err)
	table, legend, err := parseSubprocessTable(string(doc))
	require.NoError(g, err)
	var dev []allowRow
	for _, r := range rows {
		if r.Class == devClass {
			dev = append(dev, r)
		}
	}
	sites, err := scanSubprocessTree(root, dev)
	require.NoError(g, err)
	require.NotEmpty(g, sites, "the scan found no subprocess site at all: the scanner is broken, not the tree clean (internal/crypto/exec_provider.go is one)")
	for _, m := range checkSubprocesses(sites, table, legend) {
		g.Errorf("%s", m)
	}
}

// ---- self-tests: the scanner and the check against planted fixtures ----------

func scanSubprocessText(t *testing.T, rel, src string) []subprocessSite {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	require.NoError(t, err)
	return scanSubprocessSource(fset, f, rel)
}

func subprocessFormsOf(sites []subprocessSite) []string {
	var out []string
	for _, s := range sites {
		out = append(out, s.Func+" "+s.Form)
	}
	sort.Strings(out)
	return out
}

const fixtureExec = `package x

import (
	"context"
	osexec "os/exec"
)

func run(ctx context.Context) {
	_ = osexec.Command("a")
	_ = osexec.CommandContext(ctx, "b")
}
`

func TestEgressSubprocessScanner_FindsEachForm(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"aliased Command and CommandContext", fixtureExec, []string{"run os/exec.Command", "run os/exec.CommandContext"}},
		{"method receiver is named", `package x
import "os/exec"
type S struct{}
func (s *S) Go() { _ = exec.Command("a") }
`, []string{"S.Go os/exec.Command"}},
		{"function value, not a call", `package x
import "os/exec"
func f() { run := exec.Command; _ = run }
`, []string{"f os/exec.Command"}},
		{"package-level initialiser", `package x
import "os/exec"
var c = exec.Command("a")
`, []string{"<package> os/exec.Command"}},
		{"closure belongs to its function", `package x
import "os/exec"
func f() { go func() { _ = exec.Command("a") }() }
`, []string{"f os/exec.Command"}},
		{"cmd literal", `package x
import "os/exec"
func f() { _ = &exec.Cmd{Path: "/bin/a"} }
`, []string{"f os/exec.Cmd{}"}},
		{"new(Cmd) and var Cmd", `package x
import "os/exec"
func f() { _ = new(exec.Cmd); var c exec.Cmd; _ = c }
`, []string{"f new(os/exec.Cmd)", "f var os/exec.Cmd"}},
		{"syscall exec", `package x
import "syscall"
func f() { _ = syscall.Exec("/bin/a", nil, nil) }
`, []string{"f syscall.Exec"}},
		{"fork exec and start process", `package x
import ("os"; "syscall")
func f() { _, _ = syscall.ForkExec("a", nil, nil); _, _ = os.StartProcess("a", nil, nil) }
`, []string{"f os.StartProcess", "f syscall.ForkExec"}},
		{"x/sys execabs", `package x
import "golang.org/x/sys/execabs"
func f() { _ = execabs.Command("a") }
`, []string{"f golang.org/x/sys/execabs.Command"}},
		{"x/sys unix exec", `package x
import "golang.org/x/sys/unix"
func f() { _ = unix.Exec("a", nil, nil) }
`, []string{"f golang.org/x/sys/unix.Exec"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, subprocessFormsOf(scanSubprocessText(t, "x.go", c.src)))
		})
	}
}

func TestEgressSubprocessScanner_SparesWhatStartsNothing(t *testing.T) {
	for name, src := range map[string]string{
		"cmd only in a parameter":    "package x\nimport \"os/exec\"\nfunc f(c *exec.Cmd) error { return c.Run() }\n",
		"cmd only in a field":        "package x\nimport \"os/exec\"\ntype T struct{ C *exec.Cmd }\n",
		"exit error type":            "package x\nimport \"os/exec\"\nfunc f(e error) bool { _, ok := e.(*exec.ExitError); return ok }\n",
		"lookpath only searches":     "package x\nimport \"os/exec\"\nfunc f() { _, _ = exec.LookPath(\"git\") }\n",
		"a local named exec":         "package x\ntype e struct{ Command int }\nfunc f() { exec := e{}; _ = exec.Command }\n",
		"syscall without exec":       "package x\nimport \"syscall\"\nfunc f() { _ = syscall.Getpid() }\n",
		"os file functions":          "package x\nimport \"os\"\nfunc f() { _, _ = os.Open(\"a\") }\n",
		"unrelated package named os": "package x\nimport os \"example.test/os\"\nfunc f() { _ = os.StartProcess }\n",
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, scanSubprocessText(t, "x.go", src))
		})
	}
}

const fixtureSubprocessDoc = "# x\n\n## Other\n\n| `a.go` | `F` | EXEC-LOCAL-ONLY | not mine | | |\n\n## Subprocess call sites\n\n" +
	"| Class | Meaning |\n|---|---|\n| EXEC-OPERATOR-CONFIGURED | a |\n| EXEC-LOCAL-ONLY | b |\n| EXEC-USER-COMMAND | c |\n\n" +
	"| File | Function | Class | Runs | Command line set by | Reaches the network |\n|---|---|---|---|---|---|\n" +
	"| `srv/exec.go` | `S.Go` | EXEC-OPERATOR-CONFIGURED | the helper | config | whatever the helper does |\n" +
	"| `srv/git.go` | `scan` | EXEC-LOCAL-ONLY | git diff | fixed | no |\n" +
	"| `cli/run.go` | `execChild` | EXEC-USER-COMMAND | the user's command | the user | whatever it does |\n\n## Next\n"

func TestEgressSubprocessTable_ParsesSectionOnly(t *testing.T) {
	rows, legend, err := parseSubprocessTable(fixtureSubprocessDoc)
	require.NoError(t, err)
	require.Len(t, rows, 3, "the row under ## Other is not part of the section")
	assert.Equal(t, subprocessRow{File: "srv/exec.go", Func: "S.Go", Class: "EXEC-OPERATOR-CONFIGURED", Runs: "the helper", SetBy: "config", Net: "whatever the helper does"}, rows[0])
	assert.Equal(t, map[string]bool{"EXEC-OPERATOR-CONFIGURED": true, "EXEC-LOCAL-ONLY": true, "EXEC-USER-COMMAND": true}, legend)

	for name, doc := range map[string]string{
		"no section":    "# x\n",
		"empty column":  "## Subprocess call sites\n| `a.go` | `F` | EXEC-LOCAL-ONLY | git | | no |\n",
		"five columns":  "## Subprocess call sites\n| `a.go` | `F` | EXEC-LOCAL-ONLY | git | fixed |\n",
		"duplicate row": "## Subprocess call sites\n| `a.go` | `F` | EXEC-LOCAL-ONLY | git | fixed | no |\n| `a.go` | `F` | EXEC-LOCAL-ONLY | git | fixed | no |\n",
	} {
		_, _, err := parseSubprocessTable(doc)
		assert.Error(t, err, name)
	}
}

func TestEgressSubprocessCheck_RedOnPlantedSiteGreenWhenListed(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	write("go.mod", "module example.test/m\n")
	write("srv/ok.go", "package srv\n")
	write("srv/ok_test.go", fixtureExec)    // test files are not sites
	write("testdata/x.go", fixtureExec)     // neither is testdata
	write("scripts/tool/t.go", fixtureExec) // a DEV row's tree is not scanned
	dev := []allowRow{{Path: "scripts/", Class: devClass, Reason: "dev tooling"}}

	rows, legend, err := parseSubprocessTable(fixtureSubprocessDoc)
	require.NoError(t, err)

	// Red 1: nothing planted, but every row points at a function with no site.
	sites, err := scanSubprocessTree(root, dev)
	require.NoError(t, err)
	assert.Empty(t, sites)
	msgs := checkSubprocesses(sites, rows, legend)
	assert.Contains(t, strings.Join(msgs, "\n"), "`srv/exec.go` `S.Go` covers no call site any more")

	// Green: the three listed call sites exist, one per row.
	write("srv/exec.go", "package srv\nimport \"os/exec\"\ntype S struct{}\nfunc (s *S) Go() { _ = exec.Command(\"h\") }\n")
	write("srv/git.go", "package srv\nimport \"os/exec\"\nfunc scan() { _ = exec.Command(\"git\", \"diff\") }\n")
	write("cli/run.go", "package cli\nimport \"os/exec\"\nfunc execChild() { _ = exec.Command(\"c\") }\n")
	sites, err = scanSubprocessTree(root, dev)
	require.NoError(t, err)
	assert.Empty(t, checkSubprocesses(sites, rows, legend))

	// Red 2: plant an unlisted call site.
	write("srv/planted.go", fixtureExec)
	sites, err = scanSubprocessTree(root, dev)
	require.NoError(t, err)
	msgs = checkSubprocesses(sites, rows, legend)
	require.Len(t, msgs, 1, "%v", msgs)
	assert.Contains(t, msgs[0], "srv/planted.go:9 starts a subprocess (os/exec.Command, os/exec.CommandContext) in run")
	assert.Contains(t, msgs[0], "add | `srv/planted.go` | `run` |")

	// Green: the same tree with a row for the planted function.
	rows = append(rows, subprocessRow{File: "srv/planted.go", Func: "run", Class: "EXEC-LOCAL-ONLY", Runs: "x", SetBy: "x", Net: "x"})
	assert.Empty(t, checkSubprocesses(sites, rows, legend))
}

func TestEgressSubprocessCheck_ClassAndLegendMustAgree(t *testing.T) {
	site := []subprocessSite{{File: "a.go", Func: "F", Line: 3, Form: "os/exec.Command"}}
	all := map[string]bool{"EXEC-OPERATOR-CONFIGURED": true, "EXEC-LOCAL-ONLY": true, "EXEC-USER-COMMAND": true}
	mk := func(class string) []subprocessRow {
		return []subprocessRow{
			{File: "a.go", Func: "F", Class: class, Runs: "x", SetBy: "x", Net: "x"},
			{File: "b.go", Func: "G", Class: "EXEC-OPERATOR-CONFIGURED", Runs: "x", SetBy: "x", Net: "x"},
			{File: "c.go", Func: "H", Class: "EXEC-USER-COMMAND", Runs: "x", SetBy: "x", Net: "x"},
		}
	}
	sites := append(slices.Clone(site),
		subprocessSite{File: "b.go", Func: "G", Line: 1, Form: "os/exec.Command"},
		subprocessSite{File: "c.go", Func: "H", Line: 1, Form: "os/exec.Command"})

	// Green: every class defined and used, every site listed.
	assert.Empty(t, checkSubprocesses(sites, mk("EXEC-LOCAL-ONLY"), all))
	// Red: a class outside the legend.
	assert.Contains(t, strings.Join(checkSubprocesses(sites, mk("EXEC-WHATEVER"), all), "\n"), "names class EXEC-WHATEVER")
	// Red: a legend that drops a class, and one that invents a class.
	msgs := strings.Join(checkSubprocesses(sites, mk("EXEC-LOCAL-ONLY"), map[string]bool{"EXEC-LOCAL-ONLY": true, "EXEC-OPERATOR-CONFIGURED": true}), "\n")
	assert.Contains(t, msgs, "does not define class EXEC-USER-COMMAND")
	extra := map[string]bool{"EXEC-OPERATOR-CONFIGURED": true, "EXEC-LOCAL-ONLY": true, "EXEC-USER-COMMAND": true, "EXEC-NEW": true}
	assert.Contains(t, strings.Join(checkSubprocesses(sites, mk("EXEC-LOCAL-ONLY"), extra), "\n"), "legend class EXEC-NEW is not one of")
}

func TestEgressSubprocessFuncName(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", `package x
type T struct{}
type G[P any] struct{}
func (T) A() {}
func (*T) B() {}
func (g *G[P]) C() {}
func D() {}
`, 0)
	require.NoError(t, err)
	var got []string
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			got = append(got, funcName(fd))
		}
	}
	assert.Equal(t, []string{"T.A", "T.B", "G.C", "D"}, got)
}
