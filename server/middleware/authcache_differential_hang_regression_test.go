package middleware

import (
	"testing"
)

// TestAuthCacheDifferential_PasswordChangeStormIsCapped is the regression for
// fuzz-corpus issue #119. The saved crasher is one 0xda byte (op%13==10, an
// authenticated-request step) followed by 47 0xb1 bytes (op%13==8, password
// change → bcrypt). Run uncapped, that 48-op program does 47 bcrypt hashes and
// takes ~85s on the reporting host — over Go's per-input fuzz-worker hang limit,
// which the worker reports as "fuzzing process hung or terminated unexpectedly"
// rather than any oracle failure. With acdMaxBcryptOpsPerKind applied by
// acRunProgram the same program runs only 3 hashes.
//
// The test asserts the op counts acRunProgram reports, not wall time: elapsed
// time is only a proxy for the cap, and under -race on a shared CI runner the
// capped program alone took 43s (merge-queue run 43820833109). The counts are
// deterministic: a regression that removed the cap would execute 47 password
// changes, one that raised it would execute more than 3, and either fails here.
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

	stats := acRunProgram(t, w, program)

	if got := stats.executed[8]; got != acdMaxBcryptOpsPerKind {
		t.Fatalf("password-change ops executed = %d, want exactly acdMaxBcryptOpsPerKind (%d): the password-change cap did not engage", got, acdMaxBcryptOpsPerKind)
	}
	if got, want := stats.skipped[8], 47-acdMaxBcryptOpsPerKind; got != want {
		t.Fatalf("password-change ops skipped = %d, want %d", got, want)
	}
	// The cap only drops surplus bcrypt ops; the authenticated-request step
	// still runs.
	if got := stats.executed[10]; got != 1 {
		t.Fatalf("authenticated-request ops executed = %d, want 1", got)
	}
}

// TestAuthCacheDifferential_LoginStormIsCapped is the #119-class guard for the
// OTHER bcrypt-heavy op: login (op%13==0) runs bcrypt.CompareHashAndPassword on
// every attempt, so a 48-login program would hang exactly like the password-
// change storm. 0x00 decodes to op 0; the cap must bound it the same way. Like
// the password-change test it asserts op counts, not wall time.
func TestAuthCacheDifferential_LoginStormIsCapped(t *testing.T) {
	w := acBuildWorld(t)

	program := make([]byte, 48) // all zero → 48 login ops
	if program[0]%13 != 0 {
		t.Fatalf("precondition: 0x00 must decode to op 0 (login), got %d", program[0]%13)
	}

	stats := acRunProgram(t, w, program)

	if got := stats.executed[0]; got != acdMaxBcryptOpsPerKind {
		t.Fatalf("login ops executed = %d, want exactly acdMaxBcryptOpsPerKind (%d): the login cap did not engage", got, acdMaxBcryptOpsPerKind)
	}
	if got, want := stats.skipped[0], 48-acdMaxBcryptOpsPerKind; got != want {
		t.Fatalf("login ops skipped = %d, want %d", got, want)
	}
}
