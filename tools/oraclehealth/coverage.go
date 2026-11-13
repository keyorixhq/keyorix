package main

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"time"
)

// coveredLines runs the package's own unit tests under -covermode=set on the
// unmutated copy and returns, per source file (module-relative path), the set
// of line numbers executed at least once. It is used only to classify
// survivors: a survivor on a line the unit suite never executes is
// EQUIVALENT-SUSPECTED (dead per the available coverage signal), matching the
// task's definition. unitOK reports whether the unit suite itself passed; if it
// did not, the signal is untrustworthy and no equivalence upgrade is made.
func (e Env) coveredLines(ctx context.Context) (lines map[string]map[int]bool, unitOK bool) {
	lines = map[string]map[int]bool{}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	prof, err := os.CreateTemp("", "ko-oraclehealth-cov-*.out")
	if err != nil {
		return lines, false
	}
	profPath := prof.Name()
	_ = prof.Close()
	defer func() { _ = os.Remove(profPath) }()

	// Exclude the fuzz targets themselves (-run matches nothing fuzz-shaped is
	// fine; we want ordinary unit coverage). Run the whole package's tests.
	cmd := e.goCmd(cctx, "test", "-covermode=set", "-coverprofile="+profPath, "-count=1", e.pkgArg())
	out, runErr := cmd.CombinedOutput()
	unitOK = runErr == nil
	_ = out

	data, err := os.Open(profPath) // #nosec G304 -- profPath is the coverage profile this tool just had go test write in its own work dir
	if err != nil {
		return lines, unitOK
	}
	defer func() { _ = data.Close() }()
	sc := bufio.NewScanner(data)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}
		// form: <file>:<startLine>.<col>,<endLine>.<col> <numStmt> <count>
		file, after, ok := strings.CutLast(line, ":")
		if !ok {
			continue
		}
		rest := strings.Fields(after)
		if len(rest) != 3 {
			continue
		}
		count, _ := strconv.Atoi(rest[2])
		rng := rest[0] // startLine.col,endLine.col
		startRng, endRng, ok := strings.Cut(rng, ",")
		if !ok {
			continue
		}
		start := parseLine(startRng)
		end := parseLine(endRng)
		if start == 0 {
			continue
		}
		// Normalise file to the trailing package-relative form; cover profiles
		// emit an import-path-qualified name, so match by suffix on the base.
		key := normalizeCoverFile(file)
		if lines[key] == nil {
			lines[key] = map[int]bool{}
		}
		if count > 0 {
			for l := start; l <= end; l++ {
				lines[key][l] = true
			}
		}
	}
	return lines, unitOK
}

func parseLine(s string) int {
	dot := strings.Index(s, ".")
	if dot >= 0 {
		s = s[:dot]
	}
	n, _ := strconv.Atoi(s)
	return n
}

// normalizeCoverFile reduces a cover-profile file key (import-path/foo.go) to
// just its base name, which is what we match mutations against.
func normalizeCoverFile(f string) string {
	if _, after, ok := strings.CutLast(f, "/"); ok {
		return after
	}
	return f
}

// lineCovered reports whether the given module-relative file+line was executed
// by the unit suite, using base-name matching.
func lineCovered(cov map[string]map[int]bool, relFile string, line int) bool {
	base := relFile
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	m := cov[base]
	if m == nil {
		return false
	}
	return m[line]
}
