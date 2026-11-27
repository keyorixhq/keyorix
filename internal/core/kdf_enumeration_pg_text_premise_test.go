package core

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/identity"
)

// TestKDFEnumerationOracle_AbsentNameGateRefusesPGRefusedBytes guards the premise
// that keeps FuzzKDFEnumerationOracle off the Postgres seeding class
// (fuzz-corpus#194): the fuzzer's absentName only reaches the database after
// identity.NewFoldedName accepted it, and the harness swaps in a fixed sentinel
// when it did not. So the premise is that NewFoldedName refuses every string
// Postgres refuses in a text column (invalid UTF-8, NUL). If it ever accepts one,
// the harness would write it raw into the lockout accounting and fail on SQLSTATE
// 22021 before the oracle ran; route such a string through fuzzworld.PGText then.
//
// This checks the gate only. It does not show the product handles such a name: the
// harness never sends one, so the oracle says nothing about an absent username made
// of those bytes. candidatePW is not stored (only hashed and compared).
func TestKDFEnumerationOracle_AbsentNameGateRefusesPGRefusedBytes(t *testing.T) {
	for _, name := range []string{"\x00", "ghost\x00name", "\xad", "\xff\xfe", "ab\xc3\x28", "\xad\x00"} {
		if fn, err := identity.NewFoldedName(name); err == nil {
			t.Errorf("identity.NewFoldedName(%q) accepted a string Postgres refuses (folded %q): FuzzKDFEnumerationOracle would seed it raw", name, fn.Folded())
		}
	}
}
