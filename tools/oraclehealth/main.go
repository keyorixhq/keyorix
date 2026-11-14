// Command oraclehealth measures whether a Go fuzz target's oracle can actually
// catch defects. It plants small AST mutants in the code under test, runs a
// named fuzz target for a fixed time budget against each mutant, and records
// whether the mutant was KILLED (oracle caught it) or SURVIVED (an oracle
// hole). It is stdlib-only and imports no project-internal packages, so it runs
// on any Go module checkout, not just Keyorix.
//
// Each mutant is applied in a working COPY of the module: one file is
// rewritten, the fuzz target is run, then the file is restored before the next
// mutant. The tool only mutates a directory carrying the marker file that its
// own copy step writes, and refuses a -module that contains .git or an -src /
// -work pair that overlap, so a real checkout cannot be edited by mistake.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type options struct {
	module   string
	src      string
	work     string
	pkg      string
	funcs    string
	targets  string
	fuzztime time.Duration
	max      int
	seed     int64
	parallel int
	nice     int
	gomaxp   int
	equiv    bool
	out      string
	verbose  bool
}

// Run is one target's health summary.
type Run struct {
	Target       string   `json:"target"`
	Package      string   `json:"package"`
	Mutants      int      `json:"mutants"`
	Killed       int      `json:"killed"`
	Survived     int      `json:"survived"`
	Equivalent   int      `json:"equivalent_suspected"`
	Timeout      int      `json:"timeout"`
	BuildFail    int      `json:"build_fail"`
	Error        int      `json:"error"`
	KillRate     float64  `json:"kill_rate"`
	SurvivorList []Result `json:"survivors"`
}

// Report is the full JSON artefact for a tool invocation.
type Report struct {
	Package   string `json:"package"`
	FuzzTime  string `json:"fuzztime"`
	Seed      int64  `json:"seed"`
	Generated string `json:"generated"`
	Runs      []Run  `json:"runs"`
}

func main() {
	var o options
	flag.StringVar(&o.module, "module", "", "path to a working COPY made by this tool (-src/-work) to mutate in place; refused without its marker file or if it contains .git")
	flag.StringVar(&o.src, "src", "", "module root to copy into -work before running (alternative to -module)")
	flag.StringVar(&o.work, "work", "", "destination for the copy when -src is set; must be outside -src and empty or a previous copy (default: a temp dir, removed on exit)")
	flag.StringVar(&o.pkg, "pkg", "", "package under test, module-relative (e.g. internal/backupfmt)")
	flag.StringVar(&o.funcs, "funcs", "", "comma-separated function allow-list to mutate (default: all)")
	flag.StringVar(&o.targets, "targets", "", "comma-separated fuzz target names (e.g. FuzzExtractArchivePathSafety)")
	flag.DurationVar(&o.fuzztime, "fuzztime", 20*time.Second, "fuzz budget per mutant")
	flag.IntVar(&o.max, "max", 40, "cap on mutants per run (0 = no cap)")
	flag.Int64Var(&o.seed, "seed", 1, "deterministic seed for mutant sampling")
	flag.IntVar(&o.parallel, "parallel", 2, "fuzz workers (-parallel)")
	flag.IntVar(&o.nice, "nice", 10, "nice level for subprocesses")
	flag.IntVar(&o.gomaxp, "gomaxprocs", 2, "GOMAXPROCS for subprocesses")
	flag.BoolVar(&o.equiv, "equiv", false, "classify survivors on unit-test-dead lines as EQUIVALENT-SUSPECTED")
	flag.StringVar(&o.out, "out", "", "write a JSON report to this path")
	flag.BoolVar(&o.verbose, "v", false, "verbose per-mutant logging")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := runCtx(ctx, o)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "oraclehealth:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	return runCtx(context.Background(), o)
}

func runCtx(ctx context.Context, o options) error {
	if o.pkg == "" || o.targets == "" {
		return fmt.Errorf("both -pkg and -targets are required")
	}
	moduleRoot := o.module
	if moduleRoot == "" {
		if o.src == "" {
			return fmt.Errorf("one of -module or -src is required")
		}
		dst := o.work
		if dst == "" {
			d, err := os.MkdirTemp("", "ko-oraclehealth-copy-*")
			if err != nil {
				return err
			}
			dst = d
			// A default temp copy is disposable; an explicit -work is kept for reuse.
			defer func() { _ = os.RemoveAll(d) }()
		}
		fmt.Fprintf(os.Stderr, "copying %s -> %s ...\n", o.src, dst)
		if err := copyModule(o.src, dst); err != nil {
			return fmt.Errorf("copy module: %w", err)
		}
		moduleRoot = dst
	}
	moduleRoot, err := resolvePath(moduleRoot)
	if err != nil {
		return err
	}
	if err := checkModuleDir(moduleRoot); err != nil {
		return err
	}

	pkgDir := filepath.Join(moduleRoot, filepath.FromSlash(o.pkg))
	if fi, err := os.Stat(pkgDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("package dir %s not found in copy", pkgDir)
	}

	funcAllow := map[string]bool{}
	for _, f := range splitComma(o.funcs) {
		funcAllow[f] = true
	}
	targets := splitComma(o.targets)

	all, err := collectMutations(moduleRoot, pkgDir, funcAllow)
	if err != nil {
		return fmt.Errorf("collect mutations: %w", err)
	}
	muts := selectMutations(all, o.max, o.seed)
	fmt.Fprintf(os.Stderr, "mutations: %d candidate(s), %d selected (cap=%d seed=%d)\n", len(all), len(muts), o.max, o.seed)

	env := Env{
		ModuleRoot: moduleRoot,
		PkgRel:     o.pkg,
		FuzzTime:   o.fuzztime,
		Parallel:   o.parallel,
		Nice:       o.nice,
		GOMAXPROCS: o.gomaxp,
		Verbose:    o.verbose,
	}

	interrupted := func() error {
		if ctx.Err() != nil {
			return fmt.Errorf("interrupted (%v): no report written, results so far are incomplete", ctx.Err())
		}
		return nil
	}

	// Optional coverage signal for equivalence classification (computed once on
	// the unmutated copy).
	var cov map[string]map[int]bool
	var unitOK bool
	if o.equiv {
		fmt.Fprintln(os.Stderr, "computing unit-test coverage for equivalence classification ...")
		cov, unitOK = env.coveredLines(ctx)
		fmt.Fprintf(os.Stderr, "coverage: unit suite ok=%v, files=%d\n", unitOK, len(cov))
	}

	report := Report{
		Package:   o.pkg,
		FuzzTime:  o.fuzztime.String(),
		Seed:      o.seed,
		Generated: time.Now().UTC().Format(time.RFC3339),
	}

	nonOracle := 0
	for _, target := range targets {
		fmt.Fprintf(os.Stderr, "\n=== target %s ===\n", target)
		ok, detail := env.baselineGreen(ctx, target)
		if err := interrupted(); err != nil {
			return err
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "BASELINE NOT GREEN for %s; skipping. detail:\n%s\n", target, detail)
			report.Runs = append(report.Runs, Run{Target: target, Package: o.pkg})
			continue
		}
		run := Run{Target: target, Package: o.pkg, Mutants: len(muts)}
		for i, m := range muts {
			res := applyAndRun(ctx, env, target, m)
			if err := interrupted(); err != nil {
				return err
			}
			if res.Verdict == Survived && o.equiv && unitOK && !lineCovered(cov, m.File, m.Line) {
				res.Verdict = Equivalent
				res.Detail = "unit suite passes and mutated line uncovered by unit tests"
			}
			switch res.Verdict {
			case Killed:
				run.Killed++
			case Survived:
				run.Survived++
				run.SurvivorList = append(run.SurvivorList, res)
			case Equivalent:
				run.Equivalent++
				run.SurvivorList = append(run.SurvivorList, res)
			case Timeout:
				run.Timeout++
			case BuildFail:
				run.BuildFail++
			case Error:
				run.Error++
				nonOracle++
				fmt.Fprintf(os.Stderr, "ERROR detail for %s:\n%s\n", m.String(), res.Detail)
			}
			if o.verbose || res.Verdict != Killed {
				fmt.Fprintf(os.Stderr, "[%2d/%2d] %-20s %s (%.0fs)\n", i+1, len(muts), res.Verdict, m.String(), res.Seconds)
			}
		}
		compiled := run.Killed + run.Survived + run.Equivalent + run.Timeout
		if compiled > 0 {
			run.KillRate = float64(run.Killed) / float64(compiled)
		}
		report.Runs = append(report.Runs, run)
		printRunSummary(run)
	}

	if o.out != "" {
		if err := writeJSON(o.out, report); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", o.out)
	}
	printTable(report)
	if nonOracle > 0 {
		return fmt.Errorf("%d mutant run(s) failed for reasons unrelated to the oracle (verdict ERROR, excluded from the kill rate): the report is incomplete, fix the environment and re-run", nonOracle)
	}
	return nil
}

// applyAndRun applies one mutation to the copy, gates on compilation, runs the
// target, and always restores the file.
func applyAndRun(ctx context.Context, env Env, target string, m Mutation) Result {
	start := time.Now()
	res := Result{Mutation: m, Target: target}

	orig, err := os.ReadFile(m.Abs)
	if err != nil {
		res.Verdict = BuildFail
		res.Detail = "read: " + err.Error()
		return res
	}
	mutated := string(orig[:m.Start]) + m.New + string(orig[m.End:])
	if err := os.WriteFile(m.Abs, []byte(mutated), 0o600); err != nil { // #nosec G703 -- m.Abs is a file of the tool's own scratch copy of the target package, found by its own walk
		res.Verdict = BuildFail
		res.Detail = "write: " + err.Error()
		return res
	}
	// Guarantee restore no matter what.
	defer func() { _ = os.WriteFile(m.Abs, orig, 0o600) }() // #nosec G703 -- restores the same scratch-copy file written above

	if ok, detail := env.buildOK(ctx); !ok {
		res.Verdict = BuildFail
		res.Detail = detail
		res.Seconds = time.Since(start).Seconds()
		return res
	}
	before := env.snapshotCorpus(target)
	verdict, detail := env.runFuzz(ctx, target)
	env.restoreCorpus(target, before)
	res.Verdict = verdict
	res.Detail = detail
	res.Seconds = time.Since(start).Seconds()
	return res
}

func printRunSummary(r Run) {
	fmt.Fprintf(os.Stderr, "--- %s: mutants=%d killed=%d survived=%d equiv=%d timeout=%d buildfail=%d error=%d killrate=%.0f%%\n",
		r.Target, r.Mutants, r.Killed, r.Survived, r.Equivalent, r.Timeout, r.BuildFail, r.Error, r.KillRate*100)
}

func printTable(rep Report) {
	fmt.Println()
	fmt.Println("| target | mutants | killed | survived | equiv | timeout | buildfail | error | kill-rate |")
	fmt.Println("|--------|---------|--------|----------|-------|---------|-----------|-------|-----------|")
	for _, r := range rep.Runs {
		fmt.Printf("| %s | %d | %d | %d | %d | %d | %d | %d | %.0f%% |\n",
			r.Target, r.Mutants, r.Killed, r.Survived, r.Equivalent, r.Timeout, r.BuildFail, r.Error, r.KillRate*100)
	}
	for _, r := range rep.Runs {
		if len(r.SurvivorList) == 0 {
			continue
		}
		fmt.Printf("\nsurvivors for %s:\n", r.Target)
		sort.Slice(r.SurvivorList, func(i, j int) bool {
			return r.SurvivorList[i].Mutation.String() < r.SurvivorList[j].Mutation.String()
		})
		for _, s := range r.SurvivorList {
			fmt.Printf("  [%s] %s\n", s.Verdict, s.Mutation.String())
		}
	}
}

func writeJSON(path string, rep Report) error {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func splitComma(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
