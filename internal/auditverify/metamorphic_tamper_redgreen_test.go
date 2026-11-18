package auditverify_test

// Red/green proofs for the ACH1 metamorphic tamper oracle.
//
// TestMetamorphicOracle_RedGreen proves the oracle decision
// (metamorphicViolation) fires on exactly the (changed, verdict, err) shapes a
// BROKEN verifier would produce and stays silent on the shapes a CORRECT one
// produces — with NO edit to production code (the function is fed the shapes
// directly).
//
// TestMetamorphicOracle_EndToEnd_PerFamily drives every mutation family through
// the REAL verifier on a real checkpointed chain and asserts the end-to-end
// relation holds: content-changing families are detected (non-VALID), control
// families (true no-op, and a write to the unauthenticated machine_identity_id
// column) stay VALID. Each content family is replayed 3× with different offsets.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

func TestMetamorphicOracle_RedGreen(t *testing.T) {
	t.Parallel()
	someErr := errors.New("open sqlite: file is not a database")

	cases := []struct {
		name          string
		changed       bool
		verdict       auditverify.Verdict
		err           error
		wantViolation bool // true => the oracle MUST fire (red shape)
	}{
		// RED shapes — a buggy verifier that misses tamper, or false-alarms.
		{"changed_but_VALID_is_a_MISS", true, auditverify.VerdictValid, nil, true},
		{"unchanged_but_BROKEN_is_a_FALSE_ALARM", false, auditverify.VerdictBroken, nil, true},
		{"unchanged_but_INDETERMINATE_is_a_FALSE_ALARM", false, auditverify.VerdictIndeterminate, nil, true},
		{"unchanged_but_errored_is_a_FALSE_ALARM", false, auditverify.VerdictValid, someErr, true},

		// GREEN shapes — a correct verifier.
		{"changed_and_BROKEN_ok", true, auditverify.VerdictBroken, nil, false},
		{"changed_and_INDETERMINATE_ok", true, auditverify.VerdictIndeterminate, nil, false},
		{"changed_and_SEALED_ok", true, auditverify.VerdictSealed, nil, false},
		{"changed_and_typed_error_ok", true, auditverify.VerdictValid, someErr, false},
		{"unchanged_and_VALID_ok", false, auditverify.VerdictValid, nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := metamorphicViolation(tc.changed, tc.verdict, tc.err)
			if tc.wantViolation && got == "" {
				t.Fatalf("oracle FAILED TO FIRE on a bug shape (changed=%v verdict=%s err=%v): expected a violation",
					tc.changed, tc.verdict, tc.err)
			}
			if !tc.wantViolation && got != "" {
				t.Fatalf("oracle FALSE-FIRED on a correct shape (changed=%v verdict=%s err=%v): %q",
					tc.changed, tc.verdict, tc.err, got)
			}
		})
	}
}

// endToEndChain builds a fresh valid checkpointed chain of n events and returns
// the fixture plus its verdict-key options.
func endToEndChain(t *testing.T, n int) (*diffFixture, auditverify.Options) {
	t.Helper()
	f := newDiffFixture(t)
	f.logEvents(n, time.Hour)
	_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	if err != nil || !written {
		t.Fatalf("checkpoint not written: err=%v written=%v", err, written)
	}
	opts := auditverify.Options{CheckpointKey: fixedCheckpointKey}
	// base must be VALID
	db, err := auditverify.OpenSQLiteReadOnly(f.path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := auditverify.Verify(context.Background(), db, opts)
	_ = db.Close()
	if err != nil || res.Verdict != auditverify.VerdictValid {
		t.Fatalf("base chain not VALID: verdict=%v err=%v", res.Verdict, err)
	}
	return f, opts
}

func verdictAfter(t *testing.T, f *diffFixture, opts auditverify.Options) (auditverify.Verdict, error) {
	t.Helper()
	db, err := auditverify.OpenSQLiteReadOnly(f.path)
	if err != nil {
		return "", err
	}
	defer func() { _ = db.Close() }()
	res, err := auditverify.Verify(context.Background(), db, opts)
	if err != nil {
		return "", err
	}
	return res.Verdict, nil
}

// TestMetamorphicOracle_EndToEnd_PerFamily is the live, per-family detection
// proof: each fuzz-byte program selects one family; we apply it, compute the
// real fingerprint delta and the real verdict, and assert the full oracle holds.
func TestMetamorphicOracle_EndToEnd_PerFamily(t *testing.T) {
	t.Parallel()

	// Each content family, driven 3× with different fuzz programs (offsets).
	// data[0] => chain-size nibble unused here (we size directly); applyMutation
	// consumes r for kind + picks. We craft r to land on a specific kind.
	families := []struct {
		name string
		kind byte // mutation kind selector (see applyMutation switch)
	}{
		{"byteflip", 0},
		{"timestamp", 1},
		{"delete", 2},
		{"truncate-tail", 3},
		{"duplicate-id0", 4},
		{"reorder-content", 5},
		{"splice-foreign", 6},
		{"replace-lastN", 7},
		{"numeric-nudge", 8},
	}

	foreign := staticForeignRows()

	for _, fam := range families {
		for rep := range 3 {
			t.Run(fam.name+"/"+string(rune('a'+rep)), func(t *testing.T) {
				f, opts := endToEndChain(t, 12)
				fpBefore := fingerprintChain(f)
				ids := liveIDs(f)
				// Program: first byte selects kind (mod 11), remaining bytes vary picks.
				prog := []byte{fam.kind, byte(rep * 37), byte(rep*11 + 3), byte(rep*7 + 1), byte(rep * 5)}
				r := &brd{b: prog}
				label := applyMutation(r, f, ids, foreign)
				fpAfter := fingerprintChain(f)

				changed := fpAfter != fpBefore
				if !changed {
					// A content family that, for this particular offset, happened to
					// be a no-op (e.g. flipping an already-equal value or deleting a
					// non-existent id) is legitimate — skip, it proves nothing either
					// way, but it must NOT be reported as broken.
					t.Skipf("[%s] this offset produced no authenticated-content change (no-op); relation trivially holds", label)
				}
				verdict, verr := verdictAfter(t, f, opts)
				if v := metamorphicViolation(changed, verdict, verr); v != "" {
					t.Fatalf("%s [%s]: verdict=%s err=%v", v, label, verdict, verr)
				}
				t.Logf("[%s] detected: verdict=%s err=%v", label, verdict, verr)
			})
		}
	}
}

// TestMetamorphicOracle_Controls_StayValid proves the control mutations (true
// no-op, and a write to the unauthenticated machine_identity_id column) leave
// the fingerprint UNCHANGED and the verdict VALID — i.e. the oracle is not a
// vacuous always-expect-broken guard, and the verifier correctly ignores the
// column it does not authenticate.
func TestMetamorphicOracle_Controls_StayValid(t *testing.T) {
	t.Parallel()
	for _, kind := range []byte{9, 10} { // control-noop, control-unauth-col
		f, opts := endToEndChain(t, 10)
		fpBefore := fingerprintChain(f)
		ids := liveIDs(f)
		r := &brd{b: []byte{kind, 3, 1}}
		label := applyMutation(r, f, ids, staticForeignRows())
		fpAfter := fingerprintChain(f)
		if fpAfter != fpBefore {
			t.Fatalf("[%s] control mutation unexpectedly changed the authenticated fingerprint", label)
		}
		verdict, verr := verdictAfter(t, f, opts)
		if verr != nil || verdict != auditverify.VerdictValid {
			t.Fatalf("[%s] control mutation did not stay VALID: verdict=%s err=%v", label, verdict, verr)
		}
		t.Logf("[%s] stayed VALID as required", label)
	}
}
