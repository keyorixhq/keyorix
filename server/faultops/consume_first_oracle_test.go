// consume_first_oracle_test.go teaches oracle (a)'s ERROR branch the one
// state-change-on-error shape this repository has ALREADY reviewed, classified
// and machine-enforced as correct: docs/atomicity-exempt.tsv class B,
// "consume-first by design -- a single-use value is consumed BEFORE later work
// and must stay consumed even if later work fails (replay protection)".
//
// Why this is a separate file and not another knownOpenTolerances row: a
// tolerance says "a filed, not-yet-fixed finding". These are not findings. The
// functions involved carry their own `// atomicity: consume-first by design`
// marker comment, a class-B row in docs/atomicity-exempt.tsv, and a verifying
// *_FailsClosed test; internal/core/atomicity_guard_test.go already fails the
// build if either stops being classified. Oracle (a) was the only mechanism in
// the repo that did not know about that ledger, so it read a deliberately
// RETAINED consumption as a partial commit -- and because the consumption
// happens before ANY faulted call, every storage method on the op reproduces
// it, which is why per-(method, nth) tolerances for this shape grow without
// ever converging (see #2549's four bulk-approve rows for the same treadmill).
//
// WHAT THIS VERIFIES. For an op with an entry below, and only on a reported
// ERROR, that the ONLY difference between this run's OWN before and after
// state is the declared consumption:
//   - consumedColumns: the named columns of the named tables, and
//   - consumedByDeletion: the named tables, and then only under a PURE ROW
//     SUBTRACTION -- rows may disappear, but a row that was ADDED or EDITED
//     makes the exemption refuse.
//
// Every other table and column must be byte-identical to this run's own
// pre-fault state. If anything else moved, the oracle still fails. That is the
// load-bearing property: it is NOT "class B functions may leave state behind",
// which would mask a genuine partial commit inside the same function.
//
// WHAT THIS DOES NOT VERIFY, stated explicitly per CLAUDE.md:
//   - Audit content. outcomeLogTables (AuditEvent/SecretAccessLog/Notification)
//     are excluded from the comparison, on the SAME reasoning the (a) SUCCESS
//     branch's onlyOutcomeLogTables already states: oracle (c) runs first and
//     would have caught a fail-open-authz cause before execution reaches here.
//     A wrong audit *message* on a consume-first error path is invisible here.
//   - Whether the consume-first design is the right design. It takes
//     docs/atomicity-exempt.tsv's class-B classification as given, and
//     TestConsumeFirstExemptions_MatchAtomicityLedger refuses any entry whose
//     function the ledger does not classify B -- so this list cannot drift
//     into blessing a function nobody reviewed, but it also does not re-derive
//     that review.
//   - The SUCCESS branch. A reported success is compared against the
//     fault-free REFERENCE run, a different question; this exemption is
//     deliberately error-branch-only.
package faultops

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

type consumeFirstExemption struct {
	// op is the opCatalog key. Checked against opCatalog by
	// TestConsumeFirstExemptions_OpsExist, so a route rename cannot leave a
	// silently-dead entry behind.
	op string
	// fn is the consuming function, spelled EXACTLY as docs/atomicity-exempt.tsv
	// spells it -- that string equality is what ties this entry to the ledger's
	// class-B classification.
	fn string
	// consumedColumns: table -> columns that carry the consumption marker and
	// may therefore differ on an error return.
	consumedColumns map[string][]string
	// consumedByDeletion: tables whose consumption is a row DELETE. Accepted
	// only under pureRowSubtraction.
	consumedByDeletion []string
	// why is the one-line reason, printed in the ACCEPTABLE-BY-DESIGN log line
	// so a passing run still says what it accepted and on what grounds.
	why string
}

var consumeFirstExemptions = []consumeFirstExemption{
	// #2817. DisableMFA calls requireReauth (atomicity-exempt.tsv class B, own
	// marker comment at internal/core/mfa.go's requireReauth) BEFORE its
	// SetUserMFAEnabled+DeleteMFAForUser transaction. requireReauth's
	// MarkTOTPStepUsed burns the matched TOTP time-step -- MFASecret.LastUsedStep
	// -- on c.storage, outside that transaction, which is the anti-replay
	// guarantee: a code that has been accepted once must not be accepted again
	// inside its +/-1-step window, whether or not the action it authorised went
	// on to succeed.
	//
	// consumedColumns, NOT a whole-table MFASecret exemption: a genuine partial
	// commit on this op would be SetUserMFAEnabled committing while
	// DeleteMFAForUser rolled back (or the reverse), which shows up as the
	// MFASecret ROW vanishing or User.MFAEnabled flipping -- neither of which
	// LastUsedStep's exclusion hides. Exempting the table would have masked it.
	{
		op:              "REST POST /api/v1/auth/mfa/disable",
		fn:              "(*KeyorixCore).requireReauth",
		consumedColumns: map[string][]string{"MFASecret": {"LastUsedStep"}},
		why:             "requireReauth burned the matched TOTP time-step (MFASecret.LastUsedStep) before the disable transaction; it must stay burned so the same code cannot be replayed",
	},
}

// consumeFirstExemptionFor returns the entry for op, or nil.
func consumeFirstExemptionFor(op string) *consumeFirstExemption {
	for i := range consumeFirstExemptions {
		if consumeFirstExemptions[i].op == op {
			return &consumeFirstExemptions[i]
		}
	}
	return nil
}

// pureRowSubtraction reports whether after's rows are a strict multiset subset
// of before's -- the signature of a consume implemented as a row DELETE. A row
// present in after but not in before (an INSERT, or an UPDATE, since the row
// snapshot is canonical per-row JSON and an edit changes the string) makes this
// false, so a partial commit that happens to touch the same table still fails
// the oracle.
func pureRowSubtraction(before, after tableSnapshot) bool {
	if len(after.Rows) >= len(before.Rows) {
		return false
	}
	have := make(map[string]int, len(before.Rows))
	for _, r := range before.Rows {
		have[r]++
	}
	for _, r := range after.Rows {
		if have[r] == 0 {
			return false
		}
		have[r]--
	}
	return true
}

// consumeFirstAccountsForDiff reports whether the entire before->after change
// on this run is the op's declared single-use consumption and nothing else.
func consumeFirstAccountsForDiff(in oracleInput) (*consumeFirstExemption, bool) {
	e := consumeFirstExemptionFor(in.op)
	if e == nil {
		return nil, false
	}
	for _, tbl := range e.consumedByDeletion {
		if !pureRowSubtraction(in.before.Tables[tbl], in.after.Tables[tbl]) {
			return nil, false
		}
	}
	excluded := append(append([]string{}, outcomeLogTables...), e.consumedByDeletion...)
	if hashExcludingColumns(in.before, excluded, e.consumedColumns) !=
		hashExcludingColumns(in.after, excluded, e.consumedColumns) {
		return nil, false
	}
	return e, true
}

// atomicityLedgerClasses parses docs/atomicity-exempt.tsv into function ->
// class. Comment lines start with '#'; "AUDIT:"-prefixed rows are a different
// key namespace (TestAtomicityGuard_AuditBeforeWrite) and are skipped.
func atomicityLedgerClasses(t *testing.T) map[string]string {
	t.Helper()
	const path = "../../docs/atomicity-exempt.tsv"
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v -- the class-B ledger this exemption list is derived from must exist", path, err)
	}
	defer func() { _ = f.Close() }()
	classes := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 2 || strings.HasPrefix(cols[0], "AUDIT:") {
			continue
		}
		classes[cols[0]] = cols[1]
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if len(classes) == 0 {
		t.Fatalf("%s parsed to zero rows -- the parser and the file have diverged, "+
			"which would make TestConsumeFirstExemptions_MatchAtomicityLedger vacuously green", path)
	}
	return classes
}

// TestConsumeFirstExemptions_MatchAtomicityLedger is what stops this list from
// drifting into a general carve-out: every entry must name a function that
// docs/atomicity-exempt.tsv classifies B. Reclassify or delete a row there and
// this goes red, rather than oracle (a) quietly continuing to accept state
// changes on a design nobody signed off on any more.
func TestConsumeFirstExemptions_MatchAtomicityLedger(t *testing.T) {
	classes := atomicityLedgerClasses(t)
	for _, e := range consumeFirstExemptions {
		class, ok := classes[e.fn]
		if !ok {
			t.Errorf("consumeFirstExemption for op %q names fn %q, which has no row in "+
				"docs/atomicity-exempt.tsv -- an oracle exemption may only rest on a function the "+
				"atomicity ledger has actually classified", e.op, e.fn)
			continue
		}
		if class != "B" {
			t.Errorf("consumeFirstExemption for op %q names fn %q, which docs/atomicity-exempt.tsv "+
				"classifies %q, not B (consume-first by design) -- only class B justifies retaining "+
				"state on an error return", e.op, e.fn, class)
		}
	}
}

// TestConsumeFirstExemptions_OpsExist keeps a route rename from leaving a dead
// entry that silently stops applying (and, worse, reads as still covering the
// op it names).
func TestConsumeFirstExemptions_OpsExist(t *testing.T) {
	known := make(map[string]bool, len(opCatalog))
	for _, op := range opCatalog {
		known[op.Key] = true
	}
	for _, e := range consumeFirstExemptions {
		if !known[e.op] {
			t.Errorf("consumeFirstExemption names op %q, which is not in opCatalog -- stale entry", e.op)
		}
	}
}

// TestConsumeFirstExemptions_Documented: each entry must carry a fn and a why,
// so a passing ACCEPTABLE-BY-DESIGN line always states what it accepted.
func TestConsumeFirstExemptions_Documented(t *testing.T) {
	for _, e := range consumeFirstExemptions {
		if e.fn == "" {
			t.Errorf("consumeFirstExemption for op %q has no fn", e.op)
		}
		if e.why == "" {
			t.Errorf("consumeFirstExemption for op %q has no why", e.op)
		}
		if len(e.consumedColumns) == 0 && len(e.consumedByDeletion) == 0 {
			t.Errorf("consumeFirstExemption for op %q declares no consumption at all -- it would "+
				"accept ANY unchanged-elsewhere diff, which is not what this mechanism is for", e.op)
		}
	}
}

// --- calibration: red AND green on synthetic snapshots -------------------
//
// CLAUDE.md: "confirm it is green on a known-good case as well as red on a
// known-bad one -- both directions". These cases are synthetic because the
// point is the PREDICATE's discrimination, not any one op's behaviour; the
// real op's behaviour is proved by the live replay in the PR body.

func calibSnapshot(t *testing.T, mfaRows, otherRows, loginStateRows []string) dbSnapshot {
	t.Helper()
	tbl := func(name string, rows []string) tableSnapshot {
		return tableSnapshot{Table: name, Hash: strings.Join(rows, "|"), Rows: rows}
	}
	return dbSnapshot{Tables: map[string]tableSnapshot{
		"MFASecret":     tbl("MFASecret", mfaRows),
		"User":          tbl("User", otherRows),
		"SSOLoginState": tbl("SSOLoginState", loginStateRows),
		"AuditEvent":    tbl("AuditEvent", []string{"audit-anything"}),
	}}
}

func TestConsumeFirstPredicate_Calibration(t *testing.T) {
	const op = "REST POST /api/v1/auth/mfa/disable"
	// The real predicate hashes per-row JSON with the named column removed, so
	// the calibration rows have to be real JSON for rowsHashExcludingColumns to
	// strip anything.
	stepUnset := `{"ID":1,"UserID":1,"LastUsedStep":null}`
	stepBurned := `{"ID":1,"UserID":1,"LastUsedStep":57221}`
	userBefore := `{"ID":1,"MFAEnabled":true}`
	userAfter := `{"ID":1,"MFAEnabled":false}`

	t.Run("green: only the declared consumption column moved", func(t *testing.T) {
		in := oracleInput{
			op:     op,
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, nil),
			after:  calibSnapshot(t, []string{stepBurned}, []string{userBefore}, nil),
		}
		if _, ok := consumeFirstAccountsForDiff(in); !ok {
			t.Fatal("predicate refused a diff confined to MFASecret.LastUsedStep -- it must accept the " +
				"consume-first shape it exists for, or oracle (a) stays red on a correct design")
		}
	})

	t.Run("red: a second table moved too", func(t *testing.T) {
		in := oracleInput{
			op:     op,
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, nil),
			after:  calibSnapshot(t, []string{stepBurned}, []string{userAfter}, nil),
		}
		if e, ok := consumeFirstAccountsForDiff(in); ok {
			t.Fatalf("predicate ACCEPTED a diff that also flipped User.MFAEnabled (%+v) -- this is exactly "+
				"the genuine partial commit the exemption must not mask", e)
		}
	})

	t.Run("red: the MFASecret row vanished (a real partial commit)", func(t *testing.T) {
		in := oracleInput{
			op:     op,
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, nil),
			after:  calibSnapshot(t, nil, []string{userBefore}, nil),
		}
		if _, ok := consumeFirstAccountsForDiff(in); ok {
			t.Fatal("predicate ACCEPTED a vanished MFASecret row -- DeleteMFAForUser committing while the " +
				"rest of the transaction rolled back must still fail the oracle")
		}
	})

	t.Run("red: unknown op gets no exemption", func(t *testing.T) {
		in := oracleInput{
			op:     "REST POST /api/v1/secrets/",
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, nil),
			after:  calibSnapshot(t, []string{stepBurned}, []string{userBefore}, nil),
		}
		if _, ok := consumeFirstAccountsForDiff(in); ok {
			t.Fatal("predicate applied to an op with no entry -- it must be per-op, not global")
		}
	})
}

// TestPureRowSubtraction_Calibration pins the deletion-shaped half of the
// predicate independently of any exemption entry, so the SAML-side entry
// (stacked PR, #2814) lands on a primitive that is already red/green-proved.
func TestPureRowSubtraction_Calibration(t *testing.T) {
	row := func(rows ...string) tableSnapshot { return tableSnapshot{Rows: rows} }
	cases := []struct {
		name          string
		before, after tableSnapshot
		want          bool
	}{
		{"one row deleted", row("a", "b"), row("a"), true},
		{"all rows deleted", row("a"), row(), true},
		{"nothing deleted", row("a", "b"), row("a", "b"), false},
		{"row added", row("a"), row("a", "b"), false},
		{"row edited, count unchanged", row("a", "b"), row("a", "b-edited"), false},
		{"row edited and one deleted", row("a", "b", "c"), row("a", "b-edited"), false},
		{"duplicate rows, one deleted", row("a", "a", "b"), row("a", "b"), true},
		{"duplicate rows, more than existed", row("a", "b"), row("a", "a"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pureRowSubtraction(tc.before, tc.after); got != tc.want {
				t.Errorf("pureRowSubtraction(%v, %v) = %v, want %v", tc.before.Rows, tc.after.Rows, got, tc.want)
			}
		})
	}
}
