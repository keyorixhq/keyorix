// Command guardinputs selects the guard tests whose inputs a change touched
// (CI-GUARD-TRIGGERS-1). ci.yml's docs-guards job runs it through
// scripts/ci/run-input-guards.sh on every pull_request and merge_group run.
//
// Why: every Go job in ci.yml (preflight, test-quick-*, test-suite,
// repo-guards) is skipped when a change is docs_only, web_only, go_unaffected
// or operator_only. A guard test that reads one of those files (a Markdown
// file, web/nginx.conf, a script, operator/ Go code) then never runs for the
// change that can break it. #3616 (QUICK_START.md only) merged that way and
// turned main red: TestDocsShowNoLiteralSecretOnCommandLine reads every *.md.
//
// scripts/ci/guard-inputs.tsv maps each such guard test file to the globs it
// reads. This command reads changed paths (one per line) on stdin and prints,
// for every mapped file with a matching glob, one line
//
//	<module dir> TAB <package dir relative to the module, ./x/y> TAB <-run regex>
//
// An empty change list (the caller could not read it) selects every mapped
// file: when in doubt, run. guardinputs_test.go checks the map against the
// test sources and against ci.yml's own path classification.
//
// Usage (from the repository root):
//
//	go run ./scripts/ci/guardinputs select [-map scripts/ci/guard-inputs.tsv] < changed.txt
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// DefaultMap is the guard -> input globs map, relative to the repository root.
const DefaultMap = "scripts/ci/guard-inputs.tsv"

// Row is one line of the map: a test file, the globs it reads, and the
// reviewed non-inputs (globs written with a leading '!': paths the heuristic in
// guardinputs_test.go points at that the file does not actually read).
type Row struct {
	File    string
	Inputs  []string
	NotRead []string
	Note    string
	Line    int
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "select" {
		fmt.Fprintln(os.Stderr, "usage: guardinputs select [-map FILE] < changed-paths")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("select", flag.ExitOnError)
	mapPath := fs.String("map", DefaultMap, "guard -> input globs map")
	_ = fs.Parse(os.Args[2:])
	rows, err := LoadMap(*mapPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "guardinputs:", err)
		os.Exit(1)
	}
	changed, err := readLines(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "guardinputs: reading the change list:", err)
		os.Exit(1)
	}
	if len(changed) == 0 {
		fmt.Fprintln(os.Stderr, "guardinputs: empty change list, selecting every mapped guard (fail-safe)")
	}
	plan, err := Plan(".", rows, changed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "guardinputs:", err)
		os.Exit(1)
	}
	for _, p := range plan {
		fmt.Printf("%s\t%s\t%s\n", p.Module, p.Package, p.Regex)
	}
}

// LoadMap parses the TSV map: file TAB globs TAB note, '#' comments and blank
// lines ignored. globs is a comma-separated list; '!glob' marks a reviewed
// non-input.
func LoadMap(p string) ([]Row, error) {
	f, err := os.Open(p) // #nosec G304 -- fixed repo path or an explicit -map flag
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var rows []Row
	seen := map[string]int{}
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 3 {
			return nil, fmt.Errorf("%s:%d: want 3 tab-separated columns (file, globs, note), got %d", p, n, len(cols))
		}
		r := Row{File: cols[0], Note: strings.TrimSpace(cols[2]), Line: n}
		if prev, dup := seen[r.File]; dup {
			return nil, fmt.Errorf("%s:%d: %s already mapped on line %d", p, n, r.File, prev)
		}
		seen[r.File] = n
		for g := range strings.SplitSeq(cols[1], ",") {
			g = strings.TrimSpace(g)
			switch {
			case g == "":
				return nil, fmt.Errorf("%s:%d: empty glob", p, n)
			case strings.HasPrefix(g, "!"):
				r.NotRead = append(r.NotRead, g[1:])
			default:
				r.Inputs = append(r.Inputs, g)
			}
		}
		if r.Note == "" {
			return nil, fmt.Errorf("%s:%d: the note column is empty: say what the file reads (or why a path is not read)", p, n)
		}
		rows = append(rows, r)
	}
	return rows, sc.Err()
}

// MatchGlob reports whether name (a slash-separated repo path) matches
// pattern. '**' as a whole segment matches zero or more segments; other
// segments use path.Match ('*', '?', '[...]' within one segment).
func MatchGlob(pattern, name string) bool {
	return matchSegs(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegs(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			for i := 0; i <= len(name); i++ {
				if matchSegs(pat[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		if ok, err := path.Match(pat[0], name[0]); err != nil || !ok {
			return false
		}
		pat, name = pat[1:], name[1:]
	}
	return len(name) == 0
}

// Matches reports whether any of r's input globs matches name.
func (r Row) Matches(name string) bool {
	for _, g := range r.Inputs {
		if MatchGlob(g, name) {
			return true
		}
	}
	return false
}

// Step is one go test invocation of the plan.
type Step struct {
	Module  string // directory of the owning go.mod, relative to the repo root
	Package string // ./dir relative to Module
	Regex   string // -run regex naming the mapped files' Test funcs
}

var testFuncRE = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)`)

// TestFuncs returns the top-level Test funcs declared in a _test.go file.
func TestFuncs(src []byte) []string {
	var out []string
	for _, m := range testFuncRE.FindAllSubmatch(src, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

// ModuleOf returns the directory (relative to root) of the go.mod owning dir.
func ModuleOf(root, dir string) string {
	d := dir
	for {
		if _, err := os.Stat(filepath.Join(root, d, "go.mod")); err == nil {
			return d
		}
		if d == "." || d == "" {
			return "."
		}
		d = path.Dir(d)
	}
}

// Plan returns the go test steps for the rows whose inputs a changed path
// matches (every row with inputs when changed is empty), one per package.
func Plan(root string, rows []Row, changed []string) ([]Step, error) {
	byPkg := map[[2]string][]string{}
	for _, r := range rows {
		if len(r.Inputs) == 0 {
			continue
		}
		if len(changed) > 0 && !slices.ContainsFunc(changed, r.Matches) {
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, r.File)) // #nosec G304 -- path from the repo map
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", r.Line, err)
		}
		names := TestFuncs(src)
		if len(names) == 0 {
			return nil, fmt.Errorf("line %d: %s declares no Test func", r.Line, r.File)
		}
		dir := path.Dir(r.File)
		mod := ModuleOf(root, dir)
		rel := dir
		if mod != "." {
			rel = strings.TrimPrefix(strings.TrimPrefix(dir, mod), "/")
		}
		pkg := "./" + rel
		if rel == "" || rel == "." {
			pkg = "."
		}
		key := [2]string{mod, pkg}
		byPkg[key] = append(byPkg[key], names...)
	}
	var out []Step
	for k, names := range byPkg {
		sort.Strings(names)
		out = append(out, Step{Module: k[0], Package: k[1], Regex: "^(" + strings.Join(uniq(names), "|") + ")$"})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].Package < out[j].Package
	})
	return out, nil
}

func uniq(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func readLines(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return out, nil
}
