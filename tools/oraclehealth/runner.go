package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Classification of one mutant against one fuzz target.
type Verdict string

const (
	Killed      Verdict = "KILLED"
	Survived    Verdict = "SURVIVED"
	Equivalent  Verdict = "EQUIVALENT-SUSPECTED"
	Timeout     Verdict = "TIMEOUT"
	BuildFail   Verdict = "BUILD-FAIL"
	BaselineBad Verdict = "BASELINE-FAIL"
	// Error is a run that failed for a reason that says nothing about the
	// oracle (interrupted, toolchain or link error, out of disk, a test binary
	// that exits without running the target). It is excluded from the kill rate
	// and makes the tool exit non-zero.
	Error Verdict = "ERROR"
)

// Result is one (mutant, target) outcome.
type Result struct {
	Mutation Mutation `json:"mutation"`
	Target   string   `json:"target"`
	Verdict  Verdict  `json:"verdict"`
	Seconds  float64  `json:"seconds"`
	Detail   string   `json:"detail,omitempty"`
}

// Env carries the toolchain configuration shared by every subprocess.
type Env struct {
	ModuleRoot string        // working copy module root (absolute)
	PkgRel     string        // package path relative to module root, e.g. internal/backupfmt
	FuzzTime   time.Duration // per-mutant fuzz budget
	Parallel   int
	Nice       int
	GOMAXPROCS int
	Verbose    bool
}

func (e Env) pkgArg() string {
	p := "./" + filepath.ToSlash(e.PkgRel)
	return strings.TrimSuffix(p, "/")
}

// goCmd builds an exec.Cmd rooted in the working copy, with nice and the
// pinned cache/temp environment.
func (e Env) goCmd(ctx context.Context, args ...string) *exec.Cmd {
	full := append([]string{"-n", fmt.Sprintf("%d", e.Nice), "go"}, args...)
	cmd := exec.CommandContext(ctx, "nice", full...) // #nosec G204 -- fixed nice/go binaries; args are this tool's own go subcommands and flags
	cmd.Dir = e.ModuleRoot
	cmd.Env = append(os.Environ(), fmt.Sprintf("GOMAXPROCS=%d", e.GOMAXPROCS))
	// Run the whole nice/go/test-binary tree in one process group and kill the
	// group on cancel, so an orphaned test binary cannot keep the output pipe
	// open; WaitDelay bounds the wait if one still does.
	killGroupOnCancel(cmd)
	cmd.WaitDelay = 10 * time.Second
	return cmd
}

// baselineGreen compiles the package and runs the target's seed corpus on the
// unmutated copy; a non-green baseline makes every mutant meaningless. The
// target must actually run and pass: `go test -run ^Typo$` exits 0 with "no
// tests to run", which is not a green baseline.
func (e Env) baselineGreen(ctx context.Context, target string) (bool, string) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// Run just the seed corpus (no -fuzz) as a fast, deterministic sanity run.
	cmd := e.goCmd(cctx, "test", "-v", "-run", "^"+target+"$", "-count=1", e.pkgArg())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, tail(string(out), 40)
	}
	if !strings.Contains(string(out), "--- PASS: "+target+" ") {
		return false, "target " + target + " did not run (no matching fuzz target or test?):\n" + tail(string(out), 20)
	}
	return true, ""
}

// buildOK checks the mutated package still compiles. A non-compiling mutant is
// discarded (BUILD-FAIL), never counted as killed.
func (e Env) buildOK(ctx context.Context) (bool, string) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := e.goCmd(cctx, "build", e.pkgArg())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, tail(string(out), 12)
	}
	return true, ""
}

// runFuzz runs one fuzz target for FuzzTime and classifies the outcome.
func (e Env) runFuzz(ctx context.Context, target string) (Verdict, string) {
	// Wall timeout = fuzztime + generous compile/exit headroom.
	budget := e.FuzzTime + 150*time.Second
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	ft := fmt.Sprintf("%ds", int(e.FuzzTime.Seconds()))
	cmd := e.goCmd(cctx,
		"test",
		"-run", "^$",
		"-fuzz", "^"+target+"$",
		"-fuzztime", ft,
		fmt.Sprintf("-parallel=%d", e.Parallel),
		e.pkgArg(),
	)
	out, err := cmd.CombinedOutput()
	s := string(out)
	// An interrupted run says nothing about the oracle, whatever the subprocess
	// printed before it was killed.
	if ctx.Err() != nil {
		return Error, "interrupted: " + ctx.Err().Error()
	}
	if cctx.Err() == context.DeadlineExceeded {
		return Timeout, tail(s, 20)
	}
	if err == nil {
		return Survived, ""
	}
	if strings.Contains(s, "[build failed]") || strings.Contains(s, "build constraints exclude") {
		return BuildFail, tail(s, 12)
	}
	// A failing fuzz run counts as a kill only when the target itself failed:
	// either the seed corpus already fails or the fuzzer found a crasher, both
	// of which print "--- FAIL: <target>". Any other non-zero exit (toolchain or
	// link error, ENOSPC, a test binary that exits early) is not the oracle
	// catching anything.
	if strings.Contains(s, "--- FAIL: "+target+" ") || strings.Contains(s, "--- FAIL: "+target+"/") {
		return Killed, tail(s, 20)
	}
	return Error, "non-oracle failure (no --- FAIL: " + target + " in output): " + tail(s, 20)
}

// corpusSnapshot lists the committed/seed fuzz corpus files for a target so a
// crasher the fuzzer writes during one mutant run can be removed before the
// next, keeping each mutant's measurement independent.
func (e Env) corpusDir(target string) string {
	return filepath.Join(e.ModuleRoot, e.PkgRel, "testdata", "fuzz", target)
}

func (e Env) snapshotCorpus(target string) map[string]bool {
	set := map[string]bool{}
	dir := e.corpusDir(target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return set
	}
	for _, en := range entries {
		set[en.Name()] = true
	}
	return set
}

func (e Env) restoreCorpus(target string, before map[string]bool) {
	dir := e.corpusDir(target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, en := range entries {
		if !before[en.Name()] {
			_ = os.Remove(filepath.Join(dir, en.Name()))
		}
	}
}

func tail(s string, nLines int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > nLines {
		lines = lines[len(lines)-nLines:]
	}
	return strings.Join(lines, "\n")
}
