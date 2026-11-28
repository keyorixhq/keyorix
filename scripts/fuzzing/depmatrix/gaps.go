// gaps.go — the gap guard: every REACH=UNTRUSTED, FUZZ=NONE dependency must be
// either fuzzed or carry a written, dated exemption.
//
// WHY THIS EXISTS INSTEAD OF A COMMITTED MATRIX. The matrix itself (every
// column: reach, fuzz, version, import_count, top_pkgs, evidence) is derived
// from go.mod files, imports and targets.d, so it is generated on demand and
// never committed: a committed copy of derived data goes stale on every
// dependency bump or new import, and a test that byte-compares it turns every
// such pull request red. The only things a person decides are (1) why a
// reachable-from-untrusted-input dependency has no fuzz target yet and until
// when, and (2) hand-written notes. Those are the committed inputs, one file per
// module under docs/fuzz/dep-fuzz.d/, so two pull requests never edit one file.
//
// FRAGMENT FORMAT. docs/fuzz/dep-fuzz.d/<module with "/" replaced by "__">.tsv
// holds exactly one row (lines starting with # are comments):
//
//	module <TAB> expires (YYYY-MM-DD) <TAB> reason
//
// WHAT THE CHECKS DO NOT VERIFY:
//   - That an exempted dependency is actually safe; the reason is prose.
//   - That a fuzz target covering a dependency is any good (see the README).
//   - That a WRAPPED dependency is reached by its fuzz target: WRAPPED is
//     counted as covered on import evidence alone (a fuzz file imports an own
//     package whose non-test files import the dependency), with no proof the
//     fuzzed path calls into it.
//   - Anything about versions or import counts: the checks deliberately ignore
//     them so a dependency bump or an extra import of a known module cannot
//     fail them.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// gapDir is the directory of exemption fragments, relative to the repo root.
const gapDir = "docs/fuzz/dep-fuzz.d"

// gapExemption is one parsed fragment.
type gapExemption struct {
	Module  string
	Expires string // YYYY-MM-DD, validated by guardrules.CheckExpiry in the test
	Reason  string
	Source  string // fragment path relative to the repo root
}

// gapFileName is the fragment file name for a module path.
func gapFileName(module string) string {
	return strings.ReplaceAll(module, "/", "__") + ".tsv"
}

// parseGapExemption parses one fragment. name is the file's base name; it must
// equal gapFileName(module) so a rename or a copy-paste cannot silently exempt
// a different module than the file claims.
func parseGapExemption(name string, data []byte) (gapExemption, error) {
	var rows []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rows = append(rows, line)
	}
	if len(rows) != 1 {
		return gapExemption{}, fmt.Errorf("%s: want exactly one row, got %d", name, len(rows))
	}
	f := strings.Split(rows[0], "\t")
	if len(f) != 3 {
		return gapExemption{}, fmt.Errorf("%s: want 3 tab-separated fields (module, expires, reason), got %d", name, len(f))
	}
	e := gapExemption{
		Module:  strings.TrimSpace(f[0]),
		Expires: strings.TrimSpace(f[1]),
		Reason:  strings.TrimSpace(f[2]),
		Source:  gapDir + "/" + name,
	}
	if e.Module == "" || e.Reason == "" {
		return gapExemption{}, fmt.Errorf("%s: module and reason must be non-empty", name)
	}
	if want := gapFileName(e.Module); name != want {
		return gapExemption{}, fmt.Errorf("%s: file name must be %s for module %s", name, want, e.Module)
	}
	return e, nil
}

// loadGapExemptions reads every *.tsv fragment under root/gapDir. A missing
// directory means no exemptions. A malformed fragment is an error: a guard that
// skips a file it cannot read would silently drop an exemption.
func loadGapExemptions(root string) ([]gapExemption, error) {
	dir := filepath.Join(root, filepath.FromSlash(gapDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []gapExemption
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".tsv") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, ent.Name())) // #nosec G304 -- developer tool: dir is docs/fuzz/dep-fuzz.d under the repo root, names come from os.ReadDir of that same directory
		if err != nil {
			return nil, err
		}
		e, err := parseGapExemption(ent.Name(), data)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// isOpenGap reports whether a row is a dependency that is reachable from
// untrusted input and has no fuzz coverage at all.
func isOpenGap(r DepRow) bool {
	return r.Reach == string(reachUntrusted) && r.Fuzz == string(fuzzNone)
}

// gapFindings is the result of comparing the live matrix with the exemptions.
type gapFindings struct {
	Unexempted []string // open gaps with no exemption
	Stale      []string // exemptions for a module that is not an open gap any more
	Duplicate  []string // modules exempted by more than one fragment
}

// checkGaps compares the live rows with the exemptions. It reads only the
// module, reach and fuzz columns of a row.
func checkGaps(rows []DepRow, exemptions []gapExemption) gapFindings {
	var f gapFindings
	open := map[string]bool{}
	for _, r := range rows {
		if isOpenGap(r) {
			open[r.Module] = true
		}
	}
	seen := map[string]int{}
	for _, e := range exemptions {
		seen[e.Module]++
	}
	for m := range open {
		if seen[m] == 0 {
			f.Unexempted = append(f.Unexempted, m)
		}
	}
	for m, n := range seen {
		if !open[m] {
			f.Stale = append(f.Stale, m)
		}
		if n > 1 {
			f.Duplicate = append(f.Duplicate, m)
		}
	}
	sort.Strings(f.Unexempted)
	sort.Strings(f.Stale)
	sort.Strings(f.Duplicate)
	return f
}
