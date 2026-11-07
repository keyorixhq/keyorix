package main

import (
	"fmt"
	"sort"
	"strings"
)

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// Markdown renders the report. Output is deterministic.
func Markdown(r *Report) string {
	var b strings.Builder
	s := r.Summary
	b.WriteString("# Invariant coverage map\n\n")
	fmt.Fprintf(&b, "Invariants: %d (distinct IDs). Registered fuzz targets: %d.\n\n", s.Invariants, s.FuzzTargets)
	b.WriteString("| Class | Count |\n|---|---|\n")
	for _, c := range []string{ClassFuzz, ClassTest, ClassDocOnly} {
		fmt.Fprintf(&b, "| %s | %d |\n", c, s.ByClass[c])
	}
	fmt.Fprintf(&b, "\nOf the fuzz class, %d are file-level only (the ID sits in a file with a fuzz target but not in the target itself).\n", s.FuzzFileOnly)
	fmt.Fprintf(&b, "Invariants naming a check that no longer exists: %d. Duplicate IDs: %d. Declared UNGUARDED: %d. Undefined IDs referenced: %d.\n", s.WithStale, s.Duplicates, s.Unguarded, s.Unknown)
	fmt.Fprintf(&b, "Ledger rows: %d (stale: %d).\n\n", s.LedgerRows, s.LedgerStale)

	b.WriteString("## By area\n\n| Area | Total | Fuzz | Test | Doc-only |\n|---|---|---|---|---|\n")
	for _, a := range r.ByArea {
		fmt.Fprintf(&b, "| `%s` | %d | %d | %d | %d |\n", a.Area, a.Total, a.Fuzz, a.Test, a.DocOnly)
	}

	var docOnly, stale, fileOnly, unreg []Invariant
	for _, inv := range r.Invariants {
		if inv.Class == ClassDocOnly {
			docOnly = append(docOnly, inv)
		}
		if len(inv.StaleChecks) > 0 {
			stale = append(stale, inv)
		}
		if inv.Class == ClassFuzz && inv.FuzzStrength == "file" {
			fileOnly = append(fileOnly, inv)
		}
		for _, f := range inv.Flags {
			if f == "fuzz-unregistered" {
				unreg = append(unreg, inv)
			}
		}
	}
	sort.SliceStable(docOnly, func(i, j int) bool {
		if docOnly[i].SecurityScore != docOnly[j].SecurityScore {
			return docOnly[i].SecurityScore > docOnly[j].SecurityScore
		}
		return docOnly[i].ID < docOnly[j].ID
	})

	table := func(title string, list []Invariant, withStale bool) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n## %s (%d)\n\n", title, len(list))
		if withStale {
			b.WriteString("| ID | Area | Missing check(s) |\n|---|---|---|\n")
		} else {
			b.WriteString("| ID | Area | Severity | Score | Unguarded | Statement |\n|---|---|---|---|---|---|\n")
		}
		for _, inv := range list {
			if withStale {
				fmt.Fprintf(&b, "| %s | `%s` | %s |\n", inv.ID, inv.Area, cell(strings.Join(inv.StaleChecks, ", ")))
			} else {
				ug := ""
				if inv.Unguarded {
					ug = "yes"
				}
				fmt.Fprintf(&b, "| %s | `%s` | %s | %d | %s | %s |\n", inv.ID, inv.Area, inv.Severity, inv.SecurityScore, ug, cell(clip(inv.Statement, 140)))
			}
		}
	}
	table("DOC-ONLY invariants, ranked by security relevance", docOnly, false)
	table("Invariants whose documented check no longer exists", stale, true)
	table("Fuzz coverage at file level only", fileOnly, false)
	table("Fuzz evidence only on targets not registered in targets.d", unreg, false)

	if len(r.UnknownRefs) > 0 {
		b.WriteString("\n## Undefined IDs referenced\n\n| ID | In code | First reference | Closest defined ID |\n|---|---|---|---|\n")
		for _, u := range r.UnknownRefs {
			first := ""
			if len(u.Refs) > 0 {
				first = fmt.Sprintf("%s:%d", u.Refs[0].File, u.Refs[0].Line)
			}
			code := "no"
			if u.InCode {
				code = "yes"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", u.ID, code, first, u.Suggestion)
		}
	}
	if len(r.Inconsistency) > 0 {
		b.WriteString("\n## Inconsistent ID usage\n\n| Kind | IDs | Detail |\n|---|---|---|\n")
		for _, c := range r.Inconsistency {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", c.Kind, cell(strings.Join(c.IDs, ", ")), cell(clip(c.Detail, 240)))
		}
	}
	if len(r.IndexMismatch) > 0 {
		b.WriteString("\n## docs/INVARIANTS.md index counts that differ from the parsed docs\n\n")
		for _, m := range r.IndexMismatch {
			fmt.Fprintf(&b, "- %s\n", m)
		}
	}
	var lstale []LedgerRow
	for _, l := range r.Ledger {
		if l.Class == "STALE" {
			lstale = append(lstale, l)
		}
	}
	if len(lstale) > 0 {
		fmt.Fprintf(&b, "\n## Ledger rows naming a missing test (%d)\n\n| Claim | Ledger | Missing |\n|---|---|---|\n", len(lstale))
		for _, l := range lstale {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", l.Claim, l.File, cell(strings.Join(l.Missing, ", ")))
		}
	}
	return b.String()
}
