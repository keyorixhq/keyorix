// Command fuzzplan is the planning half of .github/workflows/fuzz-changed.yml.
// It never changes which fuzz targets a PR runs; it changes how fast the plan
// is computed and how the planned targets are laid out across runners.
//
//	fuzzplan list ./internal/core ./server/http      prints pkg|FuzzName, one per line
//	fuzzplan pack [-shards 6] [-max-shard-seconds N] reads pkg|FuzzName on stdin, prints shard JSON
//
// list replaces `go test -list '^Fuzz' pkg`, which links a test binary per
// changed package and cost the plan job about three minutes on a typical PR. It
// asks `go list -find` for the package's test files, so build constraints and
// module membership are decided exactly as go test decides them, then applies
// the same syntactic rule cmd/go applies to test functions (isFuzzTest below).
// What it does NOT do: a package whose test files do not type-check is listed
// here, where `go test -list` planned nothing for it. Its shard then goes red,
// which build-and-test will have done for the same PR anyway.
//
// pack keeps a package's targets together when that does not cost balance,
// because each package a shard touches costs one instrumented compile of it
// (three minutes for ./server). The costs are measured medians; a wrong or
// missing cost skews shard balance and can never drop a target.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// targetSeconds is one target at the workflow's 90s FUZZTIME plus the
	// engine's start and stop.
	targetSeconds = 91
	// skippedSeconds is a target that t.Skips on the PR runner (no Postgres).
	skippedSeconds = 2
	// defaultCompileSeconds is used for a package not in compileSeconds.
	defaultCompileSeconds = 30
)

// compileSeconds is the median time, per package, from a shard's first target
// of that package to the fuzz engine starting. Measured on 17 fuzz-changed
// runs, 2026-10-24 to 2026-11-09 (550 target runs).
var compileSeconds = map[string]int{
	"./server":                 179,
	"./internal/core":          132,
	"./internal/backupfmt":     68,
	"./internal/auditverify":   66,
	"./internal/config":        44,
	"./server/http/handlers":   35,
	"./internal/connect":       31,
	"./server/authzdiff":       21,
	"./server/faultops":        21,
	"./server/http":            19,
	"./server/admin":           14,
	"./internal/storage/store": 13,
}

// skippedOnRunner names targets that need KEYORIX_TEST_PG_DSN, which the
// fuzz-changed job does not set: they start and skip, so they weigh almost
// nothing. They stay planned, the list only corrects the weight.
var skippedOnRunner = map[string]bool{
	"FuzzCrossReplicaOps":              true,
	"FuzzCrossReplicaInvariants":       true,
	"FuzzUpgradeMigrationPostgres":     true,
	"FuzzStorageBackendDifferential":   true,
	"FuzzStorageBackendDifferentialV2": true,
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "list":
		err = list(os.Stdout, os.Stderr, os.Args[2:])
	case "pack":
		err = runPack(os.Stdin, os.Stdout, os.Stderr, os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fuzzplan:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fuzzplan list PKGDIR...\n       fuzzplan pack [-shards N] [-max-shard-seconds N] < plan")
	os.Exit(2)
}

// list prints every fuzz target of each package directory. A directory go
// cannot resolve to a root-module package with test files (a //go:build ignore
// tool, the separate ./cli module) or whose test file does not parse
// contributes nothing, as it did under `go test -list ... || return 0`; each
// such skip is logged.
func list(stdout, stderr io.Writer, pkgs []string) error {
	for _, pkg := range pkgs {
		names, err := packageTargets(pkg)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "fuzzplan: no targets from %s: %v\n", pkg, err)
			continue
		}
		for _, n := range names {
			if _, err := fmt.Fprintf(stdout, "%s|%s\n", pkg, n); err != nil {
				return fmt.Errorf("writing plan: %w", err)
			}
		}
	}
	return nil
}

// packageTargets returns the sorted fuzz targets of pkg.
func packageTargets(pkg string) ([]string, error) {
	files, err := testFiles(pkg)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, f := range files {
		found, err := fuzzTargets(f)
		if err != nil {
			return nil, err
		}
		names = append(names, found...)
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// testFiles returns the absolute paths of the test files go test would compile
// for pkg, internal and external.
func testFiles(pkg string) ([]string, error) {
	cmd := exec.Command("go", "list", "-find", "-json=Dir,TestGoFiles,XTestGoFiles", pkg) // #nosec G204 G702 -- CI-only tool: pkg is a changed-package path from the plan job, passed as a single argv entry (no shell)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
	}
	var p struct {
		Dir                       string
		TestGoFiles, XTestGoFiles []string
	}
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		return nil, fmt.Errorf("parsing go list output: %w", err)
	}
	var files []string
	for _, f := range slices.Concat(p.TestGoFiles, p.XTestGoFiles) {
		files = append(files, filepath.Join(p.Dir, f))
	}
	return files, nil
}

func fuzzTargets(path string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && isFuzzTest(fn) {
			names = append(names, fn.Name.Name)
		}
	}
	return names, nil
}

// isFuzzTest is the rule cmd/go/internal/load applies: a top-level func named
// Fuzz or FuzzX (X not a lowercase letter) taking one *F or *pkg.F and
// returning nothing.
func isFuzzTest(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") {
		return false
	}
	if rest := strings.TrimPrefix(fn.Name.Name, "Fuzz"); rest != "" {
		if r, _ := utf8.DecodeRuneInString(rest); unicode.IsLower(r) {
			return false
		}
	}
	params := fn.Type.Params.List
	if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 || len(params) != 1 || len(params[0].Names) > 1 {
		return false
	}
	star, ok := params[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	switch x := star.X.(type) {
	case *ast.Ident:
		return x.Name == "F"
	case *ast.SelectorExpr:
		return x.Sel.Name == "F"
	}
	return false
}

type target struct{ pkg, fn string }

func (t target) String() string { return t.pkg + "|" + t.fn }

func (t target) seconds() int {
	if skippedOnRunner[t.fn] {
		return skippedSeconds
	}
	return targetSeconds
}

func compileCost(pkg string) int {
	if s, ok := compileSeconds[pkg]; ok {
		return s
	}
	return defaultCompileSeconds
}

// shard is one element of the matrix the workflow fans out over.
type shard struct {
	ID      int    `json:"id"`
	Targets string `json:"targets"`
}

func runPack(stdin io.Reader, stdout, stderr io.Writer, args []string) error {
	fs := flag.NewFlagSet("pack", flag.ContinueOnError)
	maxShards := fs.Int("shards", 6, "maximum number of shards")
	maxSeconds := fs.Int("max-shard-seconds", 480, "open another shard (up to -shards) once the estimated work per shard exceeds this")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *maxShards < 1 || *maxSeconds < 1 {
		return fmt.Errorf("-shards and -max-shard-seconds must be positive")
	}
	var targets []target
	sc := bufio.NewScanner(stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		pkg, fn, ok := strings.Cut(line, "|")
		if !ok || pkg == "" || fn == "" {
			return fmt.Errorf("malformed plan line %q, want pkg|FuzzName", line)
		}
		targets = append(targets, target{pkg, fn})
	}
	if err := sc.Err(); err != nil {
		return err
	}
	packed := pack(targets, *maxShards, *maxSeconds)
	out := make([]shard, len(packed))
	for i, s := range packed {
		names := make([]string, len(s))
		for j, t := range s {
			names[j] = t.String()
		}
		out[i] = shard{ID: i, Targets: strings.Join(names, " ")}
		_, _ = fmt.Fprintf(stderr, "fuzzplan: shard %d: %d targets, estimated %ds\n", i, len(s), shardSeconds(s))
	}
	return json.NewEncoder(stdout).Encode(out)
}

// pack lays targets out over as many shards as the estimated work needs, at
// most maxShards. Targets are placed one at a time, biggest package first, on
// the shard that ends up least loaded: a shard already compiling the package is
// cheaper than a cold one by the compile, so a package only spreads over
// another shard when balance is worth more than the extra compile.
func pack(targets []target, maxShards, maxSeconds int) [][]target {
	if len(targets) == 0 {
		return nil
	}
	work := map[string]int{}
	for _, t := range targets {
		if work[t.pkg] == 0 {
			work[t.pkg] = compileCost(t.pkg)
		}
		work[t.pkg] += t.seconds()
	}
	total := 0
	for _, w := range work {
		total += w
	}
	n := min(maxShards, len(targets), (total+maxSeconds-1)/maxSeconds)
	n = max(n, 1)

	// Biggest package first, so the expensive ones claim empty shards.
	order := slices.Clone(targets)
	slices.SortFunc(order, func(a, b target) int {
		if c := work[b.pkg] - work[a.pkg]; c != 0 {
			return c
		}
		if c := strings.Compare(a.pkg, b.pkg); c != 0 {
			return c
		}
		return strings.Compare(a.fn, b.fn)
	})

	shards := make([][]target, n)
	load := make([]int, n)
	has := make([]map[string]bool, n)
	for i := range has {
		has[i] = map[string]bool{}
	}
	for _, t := range order {
		best, bestLoad := 0, -1
		for i := range shards {
			l := load[i] + t.seconds()
			if !has[i][t.pkg] {
				l += compileCost(t.pkg)
			}
			if bestLoad < 0 || l < bestLoad {
				best, bestLoad = i, l
			}
		}
		shards[best] = append(shards[best], t)
		has[best][t.pkg] = true
		load[best] = bestLoad
	}
	return shards
}

func shardSeconds(s []target) int {
	total, seen := 0, map[string]bool{}
	for _, t := range s {
		if !seen[t.pkg] {
			total += compileCost(t.pkg)
			seen[t.pkg] = true
		}
		total += t.seconds()
	}
	return total
}
