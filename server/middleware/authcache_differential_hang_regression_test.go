package middleware

import (
	"testing"
	"time"
)

// TestAuthCacheDifferential_PasswordChangeStormIsCapped is the regression for
// fuzz-corpus issue #119. The saved crasher is one 0xda byte (op%13==10, an
// authenticated-request step) followed by 47 0xb1 bytes (op%13==8, password
// change → bcrypt). Run uncapped, that 48-op program does 47 bcrypt hashes and
// takes ~85s on the reporting host — over Go's per-input fuzz-worker hang limit,
// which the worker reports as "fuzzing process hung or terminated unexpectedly"
// rather than any oracle failure. With acdMaxPasswordChangesPerProgram applied
// by acRunProgram the same program runs only 3 hashes and finishes well under
// the limit.
//
// Red/green: the uncapped program was measured at 85.21s replaying this exact
// input against the pre-fix fuzz body (see the HF1 report); this test asserts
// the capped path is under a generous 10s bound, so a regression that removed
// or raised the cap past the storm length would fail it.
func TestAuthCacheDifferential_PasswordChangeStormIsCapped(t *testing.T) {
	w := acBuildWorld(t)

	program := make([]byte, 48)
	program[0] = 0xda
	for i := 1; i < len(program); i++ {
		program[i] = 0xb1
	}
	// Precondition: the bytes decode to exactly the storm #119 hung on.
	if program[0]%13 != 10 {
		t.Fatalf("precondition: 0xda must decode to op 10 (authed request), got %d", program[0]%13)
	}
	if program[1]%13 != 8 {
		t.Fatalf("precondition: 0xb1 must decode to op 8 (password change), got %d", program[1]%13)
	}

	start := time.Now()
	acRunProgram(t, w, program)
	elapsed := time.Since(start)

	if elapsed > 10*time.Second {
		t.Fatalf("capped password-change storm took %s, want < 10s — the password-change cap did not engage", elapsed)
	}
	t.Logf("#119 capped storm elapsed=%s (uncapped replay of the same input was ~85s)", elapsed)
}

// TestAuthCacheDifferential_LoginStormIsCapped is the #119-class guard for the
// OTHER bcrypt-heavy op: login (op%13==0) runs bcrypt.CompareHashAndPassword on
// every attempt, so a 48-login program would hang exactly like the password-
// change storm. 0x00 decodes to op 0; the cap must bound it the same way.
func TestAuthCacheDifferential_LoginStormIsCapped(t *testing.T) {
	w := acBuildWorld(t)

	program := make([]byte, 48) // all zero → 48 login ops
	if program[0]%13 != 0 {
		t.Fatalf("precondition: 0x00 must decode to op 0 (login), got %d", program[0]%13)
	}

	start := time.Now()
	acRunProgram(t, w, program)
	elapsed := time.Since(start)

	if elapsed > 10*time.Second {
		t.Fatalf("capped login storm took %s, want < 10s — the login cap did not engage", elapsed)
	}
	t.Logf("#119-class login storm elapsed=%s (uncapped would be ~48 bcrypt compares)", elapsed)
}
