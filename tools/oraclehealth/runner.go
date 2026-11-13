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
	Allowlisted Verdict = "ALLOWLISTED"
	Timeout     Verdict = "TIMEOUT"
	BuildFail   Verdict = "BUILD-FAIL"
	BaselineBad Verdict = "BASELINE-FAIL"
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
	cmd := exec.CommandContext(ctx, "nice", full...)
	cmd.Dir = e.ModuleRoot
	cmd.Env = append(os.Environ(), fmt.Sprintf("GOMAXPROCS=%d", e.GOMAXPROCS))
	return cmd
}

// baselineGreen compiles the package and runs the target's seed corpus on the
// unmutated copy; a non-green baseline makes every mutant meaningless.
func (e Env) baselineGreen(ctx context.Context, target string) (bool, string) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// Run just the seed corpus (no -fuzz) as a fast, deterministic sanity run.
	cmd := e.goCmd(cctx, "test", "-run", "^"+target+"$", "-count=1", e.pkgArg())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, tail(string(out), 40)
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
	if cctx.Err() == context.DeadlineExceeded {
		return Timeout, tail(s, 20)
	}
	if err == nil {
		return Survived, ""
	}
	if strings.Contains(s, "[build failed]") || strings.Contains(s, "build constraints exclude") {
		return BuildFail, tail(s, 12)
	}
	// A failing fuzz run: either the seed corpus already fails or the fuzzer
	// found a crasher. Either way the oracle caught the mutant.
	return Killed, tail(s, 20)
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
