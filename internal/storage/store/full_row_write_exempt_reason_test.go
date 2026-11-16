package store

// full_row_write_exempt_reason_test.go — STORE-STALE-NOV-3 item 3.
//
// docs/full-row-write-exempt.tsv's header defines the reason classes a row may claim
// (SAFE-CAS, RESIDUAL, UNSAFE-OPEN #issue, NO-CALLER, FIXED-NO-CALLER, pending: #PR,
// arrives with #PR). Until this test the guard read the reason column only to look
// for "arrives with #N": an empty reason, or prose with no class, exempted a
// full-row write just as well as a reviewed verdict. Both shapes occurred in the
// ledger's history ("The CreateShareRecord Saves live here ...",
// "NO-PRODUCTION-CALLER: ..."). This makes the class, and a justification after it,
// part of the row's syntax.
//
// What this does NOT check: that the class is TRUE. The interleave tests
// (full_row_writer_*interleave_test.go) and the independent reviewer column
// (internal/core/guards/exempt_ledger_review_test.go) are what back a verdict; this
// only refuses a row that does not state one.

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// fullRowExemptReasonRe is the class a reason must start with, then the rest.
var fullRowExemptReasonRe = regexp.MustCompile(`^(SAFE-CAS|RESIDUAL|NO-CALLER|FIXED-NO-CALLER|UNSAFE-OPEN #\d+|pending: #\d+|arrives with #\d+)\b(.*)$`)

// fullRowExemptMinJustification is the shortest justification accepted after the
// class (letters and digits only, so "SAFE-CAS: ..." does not pass on punctuation).
const fullRowExemptMinJustification = 20

// fullRowExemptReasonProblem returns "" for a well-formed reason, else what is wrong.
func fullRowExemptReasonProblem(reason string) string {
	m := fullRowExemptReasonRe.FindStringSubmatch(reason)
	if m == nil {
		return "reason must start with a class from the ledger header (SAFE-CAS, RESIDUAL, NO-CALLER, FIXED-NO-CALLER, UNSAFE-OPEN #issue, pending: #PR, arrives with #PR)"
	}
	n := 0
	for _, r := range m[2] {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			n++
		}
	}
	if n < fullRowExemptMinJustification {
		return fmt.Sprintf("class %s needs a justification after it (why this site cannot revert a concurrent write, or which columns it can), got %q", m[1], strings.TrimSpace(m[2]))
	}
	return ""
}

// TestFullRowWriteGuard_EveryExemptRowNamesAReasonClass: every row of the ledger,
// direct-write and caller rows alike, states a class and a justification.
func TestFullRowWriteGuard_EveryExemptRowNamesAReasonClass(t *testing.T) {
	g := guardrules.Rollout(t)
	rows := loadFullRowExempt(t)
	require.NotEmpty(t, rows, "fixture: the ledger has rows")
	for _, r := range rows {
		if p := fullRowExemptReasonProblem(r.Reason); p != "" {
			g.Errorf("%s:%d %s %s %s: %s", fullRowExemptPath, r.Line, r.File, r.Func, r.Model, p)
		}
	}
}

// TestFullRowWriteGuard_ReasonClassCalibration: the check refuses the shapes that
// reached the ledger before it existed and accepts every class the header defines.
func TestFullRowWriteGuard_ReasonClassCalibration(t *testing.T) {
	accept := []string{
		"SAFE-CAS: conditional on state='pending'; no other writer changes a pending row.",
		"SAFE-CAS [carried #2725]: moves the request off pending through the pending CAS.",
		"RESIDUAL: a stale revert of display_name only, which gates nothing.",
		"NO-CALLER: the primitive has no production caller since the column-scoped rewrite.",
		"FIXED-NO-CALLER: every caller moved to the column-scoped write (TestX).",
		"UNSAFE-OPEN #2677: a stale Save can revert a revoke; fix tracked there.",
		"pending: #4210 makes the lift conditional; remove this row when it merges.",
		"arrives with #2671 (the CreateShareRecord Saves move here; on merge drop this phrase)",
	}
	for _, s := range accept {
		require.Emptyf(t, fullRowExemptReasonProblem(s), "a well-formed reason was refused: %q", s)
	}
	refuse := map[string]string{
		"empty":                     "",
		"whitespace":                "   ",
		"prose, class later":        "The CreateShareRecord Saves live here since #2785. RESIDUAL: re-sharing over an existing row",
		"class not in the header":   "NO-PRODUCTION-CALLER: nothing calls this primitive in production code",
		"UNSAFE-OPEN with no issue": "UNSAFE-OPEN: a stale Save can revert a revoke of the membership row",
		"class prefix of a word":    "SAFE-CASE: conditional on state, nothing else writes the row at all",
		"class with no reason":      "SAFE-CAS",
		"class with punctuation":    "SAFE-CAS: ... (see above) ...",
		"class with a stub":         "RESIDUAL: tbd",
		"lower-case class":          "safe-cas: conditional on state, nothing else writes the row at all",
	}
	for name, s := range refuse {
		require.NotEmptyf(t, fullRowExemptReasonProblem(s), "%s: a reason with no stated class or justification was accepted: %q", name, s)
	}
}
