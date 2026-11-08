// invariant-map maps every named invariant (INV-*) defined in the package
// INVARIANTS.md / INVARIANTS.d docs to the checks that reference it, and
// classifies it:
//
//	COVERED-BY-FUZZ  a fuzz target, fuzz oracle or fuzzutil code names it
//	COVERED-BY-TEST  only a unit/integration/e2e/CI check names it
//	DOC-ONLY         no check references it
//
// It also reports invariants whose documented check no longer exists, IDs
// referenced but not defined, and IDs used inconsistently. It is fully
// deterministic and offline: no network, no models, no timestamps.
//
// Usage (from the repository root):
//
//	go run ./scripts/fuzzing/invariant-map -json out.json -md out.md
//	go run ./scripts/fuzzing/invariant-map -check
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("invariant-map", flag.ContinueOnError)
	fs.SetOutput(errw)
	root := fs.String("root", "", "repository root (default: nearest parent containing go.mod)")
	jsonOut := fs.String("json", "", "write the JSON report to this file")
	mdOut := fs.String("md", "", "write the Markdown report to this file")
	check := fs.Bool("check", false, "fail on undefined referenced IDs and on invariants with no check")
	allow := fs.String("allowlist", "", "allowlist file (default: <tool dir>/allowlist.txt if present)")
	noStale := fs.Bool("no-stale", false, "with -check: do not fail on documented checks that no longer exist")
	strictDocs := fs.Bool("strict-docs", false, "with -check: also fail on undefined IDs mentioned only in docs")
	noSkipSelf := fs.Bool("include-self", false, "scan this tool's own directory too (used by tests)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	r := *root
	if r == "" {
		var err error
		if r, err = findRoot(); err != nil {
			_, _ = fmt.Fprintln(errw, "invariant-map:", err)
			return 2
		}
	}
	rep, err := Analyze(r, !*noSkipSelf)
	if err != nil {
		_, _ = fmt.Fprintln(errw, "invariant-map:", err)
		return 2
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := writeFile(*jsonOut, append(b, '\n')); err != nil {
			_, _ = fmt.Fprintln(errw, "invariant-map:", err)
			return 2
		}
	}
	if *mdOut != "" {
		if err := writeFile(*mdOut, []byte(Markdown(rep))); err != nil {
			_, _ = fmt.Fprintln(errw, "invariant-map:", err)
			return 2
		}
	}
	s := rep.Summary
	_, _ = fmt.Fprintf(out, "invariants=%d fuzz=%d test=%d doc-only=%d stale=%d duplicates=%d unknown-refs=%d\n",
		s.Invariants, s.ByClass[ClassFuzz], s.ByClass[ClassTest], s.ByClass[ClassDocOnly], s.WithStale, s.Duplicates, s.Unknown)
	if !*check {
		return 0
	}
	al := *allow
	if al == "" {
		def := filepath.Join(r, selfDir, "allowlist.txt")
		if _, err := os.Stat(def); err == nil {
			al = def
		}
	}
	rules, err := loadAllowlist(al)
	if err != nil {
		_, _ = fmt.Fprintln(errw, "invariant-map:", err)
		return 2
	}
	problems := Check(rep, rules, !*noStale, *strictDocs)
	for _, p := range problems {
		_, _ = fmt.Fprintln(out, "FAIL", p)
	}
	if len(problems) > 0 {
		_, _ = fmt.Fprintf(out, "invariant-map: %d problem(s)\n", len(problems))
		return 1
	}
	_, _ = fmt.Fprintln(out, "invariant-map: check ok")
	return 0
}

func writeFile(p string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

func findRoot() (string, error) {
	d, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		n := filepath.Dir(d)
		if n == d {
			return "", fmt.Errorf("no go.mod found above the working directory; pass -root")
		}
		d = n
	}
}

// ---- allowlist --------------------------------------------------------

// Rule is one allowlist entry: "<kind> <glob>  # reason".
type Rule struct{ Kind, Glob string }

// Allowlist kinds.
const (
	AllowUnknownRef = "unknown-ref" // an ID that code may mention without a definition
	AllowNoCheck    = "no-check"    // an invariant allowed to have no check or Guard text
	AllowStale      = "stale-check" // an invariant allowed to name a missing check
)

func loadAllowlist(p string) ([]Rule, error) {
	if p == "" {
		return nil, nil
	}
	f, err := os.Open(p) // #nosec G304 -- operator-supplied allowlist path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var rules []Rule
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		l := sc.Text()
		if k := strings.Index(l, "#"); k >= 0 {
			l = l[:k]
		}
		fl := strings.Fields(l)
		if len(fl) == 0 {
			continue
		}
		if len(fl) != 2 || (fl[0] != AllowUnknownRef && fl[0] != AllowNoCheck && fl[0] != AllowStale) {
			return nil, fmt.Errorf("%s:%d: want '<unknown-ref|no-check|stale-check> <ID or glob>'", p, n)
		}
		if _, err := path.Match(fl[1], "x"); err != nil {
			return nil, fmt.Errorf("%s:%d: bad glob: %v", p, n, err)
		}
		rules = append(rules, Rule{fl[0], fl[1]})
	}
	return rules, sc.Err()
}

func allowed(rules []Rule, kind, id string) bool {
	for _, r := range rules {
		if r.Kind == kind {
			if ok, _ := path.Match(r.Glob, id); ok {
				return true
			}
		}
	}
	return false
}

// Check returns the problems that make -check fail.
//
//   - an ID mentioned in code (or, with strictDocs, docs) that no doc defines;
//   - an invariant with no check reference, no Guard text and no UNGUARDED
//     marker (a new invariant added without any statement about its check);
//   - an invariant whose documented Guard names a test/file that no longer
//     exists (unless noStale).
func Check(rep *Report, rules []Rule, stale, strictDocs bool) []string {
	var out []string
	for _, u := range rep.UnknownRefs {
		if allowed(rules, AllowUnknownRef, u.ID) {
			continue
		}
		if u.InCode || strictDocs {
			where := ""
			if len(u.Refs) > 0 {
				where = fmt.Sprintf(" (%s:%d)", u.Refs[0].File, u.Refs[0].Line)
			}
			msg := "undefined invariant ID " + u.ID + where
			if u.Suggestion != "" {
				msg += "; did you mean " + u.Suggestion + "?"
			}
			out = append(out, msg)
		}
	}
	for _, inv := range rep.Invariants {
		if inv.EvidenceTotal == 0 && !inv.Unguarded && !inv.HasGuardText && len(inv.StaleChecks) == 0 && !allowed(rules, AllowNoCheck, inv.ID) {
			out = append(out, fmt.Sprintf("invariant %s (%s:%d) has no check reference, no Guard: text and no UNGUARDED marker", inv.ID, inv.Defs[0].File, inv.Defs[0].Line))
		}
		if stale && len(inv.StaleChecks) > 0 && !allowed(rules, AllowStale, inv.ID) {
			out = append(out, fmt.Sprintf("invariant %s names a check that no longer exists: %s", inv.ID, strings.Join(inv.StaleChecks, ", ")))
		}
	}
	return out
}
