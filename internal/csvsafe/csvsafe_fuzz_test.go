package csvsafe

// FuzzCSVSafeFormulaNeutralization fuzzes Neutralize, the single shared CWE-1236 spreadsheet
// formula-injection neutraliser every CSV export layer (core, cli, http handlers) delegates to.
// Two sound invariants (assert only the safe direction, so neither can false-positive):
//
//   - NO DATA LOSS: Neutralize only ever prepends a single leading quote — it never drops,
//     reorders, or otherwise rewrites the value. (Output is exactly s or "'"+s.)
//   - NO FORMULA CELL (end-to-end): the neutralised value, written through a real encoding/csv
//     Writer and read back through a real Reader — the exact path an export takes — must never
//     produce a cell that begins with a spreadsheet formula trigger (=, +, -, @, TAB, CR). This
//     is what an attacker would break to smuggle `=cmd|'/C calc'!A0`-style payloads into an
//     auditor's spreadsheet; round-tripping through encoding/csv also guards against the CSV
//     encoding itself ever re-introducing a leading trigger.
//
// Pure function + encoding/csv, no server/DB — CI-runnable.

import (
	"encoding/csv"
	"strings"
	"testing"
)

// csvFormulaTriggers is the set of leading bytes a spreadsheet may execute as a formula/command,
// mirroring Neutralize's own switch. A neutralised, round-tripped cell must begin with none of them.
var csvFormulaTriggers = map[byte]bool{'=': true, '+': true, '-': true, '@': true, '\t': true, '\r': true}

func FuzzCSVSafeFormulaNeutralization(f *testing.F) {
	for _, s := range []string{
		"", "safe value", "a=b (not leading)",
		"=cmd", "+1", "-2+3", "@SUM(A1)", "\tTAB", "\rCR",
		"=1+2\";=cmd|'/C calc'!A0", " =leading space then eq", "\n=leading lf then eq",
		"quote\"inside", "comma,inside", "line\nbreak", "'already quoted",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		out := Neutralize(s)

		// Invariant 1: no data loss — Neutralize only ever prepends a single quote.
		if out != s && out != "'"+s {
			t.Fatalf("Neutralize altered data beyond a single leading quote: in=%q out=%q", s, out)
		}

		// An empty cell carries no formula-injection risk, and a single empty CSV field encodes
		// as a blank line that encoding/csv legitimately skips on read — nothing to round-trip.
		if out == "" {
			return
		}

		// Invariant 2: end-to-end — write the neutralised cell through encoding/csv and read it
		// back; the resulting cell must not begin with a formula trigger.
		var buf strings.Builder
		w := csv.NewWriter(&buf)
		if err := w.Write([]string{out}); err != nil {
			t.Fatalf("csv write of neutralised cell %q: %v", out, err)
		}
		w.Flush()
		if err := w.Error(); err != nil {
			t.Fatalf("csv writer flush error on %q: %v", out, err)
		}
		rec, err := csv.NewReader(strings.NewReader(buf.String())).Read()
		if err != nil || len(rec) == 0 {
			t.Fatalf("csv read-back of %q failed: err=%v rec=%v", out, err, rec)
		}
		cell := rec[0]
		if len(cell) > 0 && csvFormulaTriggers[cell[0]] {
			t.Fatalf("CSV FORMULA INJECTION: input %q neutralised to %q, but the read-back cell %q begins with a formula trigger %q",
				s, out, cell, string(cell[0]))
		}
	})
}
