package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// allowEntry is one row of the equivalent/dead-mutant allowlist: a survivor that
// is behaviour-equivalent or unreachable (so its survival is not an oracle hole)
// and should not be re-reported on every run. class is "equivalent" or "dead";
// reason must name the code that makes the mutation unobservable.
type allowEntry struct {
	target, file, fn, op, orig, newText, class, reason string
}

// normWS collapses every run of whitespace (spaces, tabs, newlines) to a single
// space and trims, so a multi-line guard body matches its single-line allowlist
// form and the match survives re-indentation. Line numbers are deliberately NOT
// part of the key: a mutation keyed on (target,file,func,op,orig,new) keeps
// matching when surrounding code shifts it to a new line, and stops matching
// (fails safe, re-reporting) only when the mutated construct itself changes.
func normWS(s string) string { return strings.Join(strings.Fields(s), " ") }

func allowKey(target, file, fn, op, orig, newText string) string {
	return strings.Join([]string{target, file, fn, op, normWS(orig), normWS(newText)}, "\x00")
}

// loadAllowlist reads a TSV of equivalent/dead mutants to suppress. Columns
// (tab-separated): target, file, func, op, orig, new, class, reason. Blank lines
// and lines beginning with '#' are ignored; a header row whose first column is
// the literal "target" is skipped. An empty path yields an empty (not nil-erroring)
// allowlist.
func loadAllowlist(path string) (map[string]allowEntry, error) {
	out := map[string]allowEntry{}
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		raw := sc.Text()
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		cols := strings.Split(raw, "\t")
		if len(cols) < 8 {
			return nil, fmt.Errorf("%s:%d: want 8 tab-separated columns, got %d", path, ln, len(cols))
		}
		if cols[0] == "target" { // header row
			continue
		}
		e := allowEntry{
			target: cols[0], file: cols[1], fn: cols[2], op: cols[3],
			orig: cols[4], newText: cols[5], class: cols[6], reason: cols[7],
		}
		if e.class != "equivalent" && e.class != "dead" {
			return nil, fmt.Errorf("%s:%d: class must be \"equivalent\" or \"dead\", got %q", path, ln, e.class)
		}
		if strings.TrimSpace(e.reason) == "" {
			return nil, fmt.Errorf("%s:%d: empty reason (an allowlist entry must name the code that makes the mutant unobservable)", path, ln)
		}
		out[allowKey(e.target, e.file, e.fn, e.op, e.orig, e.newText)] = e
	}
	return out, sc.Err()
}

// matchAllow returns the allowlist entry for a survivor, if any.
func matchAllow(allow map[string]allowEntry, target string, m Mutation) (allowEntry, bool) {
	e, ok := allow[allowKey(target, m.File, m.Func, m.Op, m.Orig, m.New)]
	return e, ok
}
