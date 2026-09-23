package rules

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzSecretValuePolicyValidate fuzzes SecretValuePolicy.Validate over arbitrary
// value bytes. The value comes from whatever a client writes at secret
// create/rotate time, so it is fully attacker-controlled — including invalid
// UTF-8, which flows through strings.ToLower/TrimSpace here. The check must never
// panic, and it must never reject a value it was told to ignore.
//
// Invariants: (a) never panics; (b) a DISABLED policy accepts every input (the
// opt-out must be absolute — a disabled quality gate can't start rejecting
// writes); (c) an ENABLED policy with a positive MinLength rejects any value
// shorter than that many BYTES (len(value), matching the implementation).
func FuzzSecretValuePolicyValidate(f *testing.F) {
	const minLen = 8
	enabled := SecretValuePolicy{
		Enabled:       true,
		MinLength:     minLen,
		RejectCommon:  true,
		ExtraDenylist: []string{"corp-shared", "Rotate-Me"},
	}
	disabled := DefaultSecretValuePolicy() // Enabled == false

	seeds := [][]byte{
		nil, {}, []byte("x"), []byte("changeme"), []byte("CHANGEME"),
		[]byte("  changeme  "), []byte("corp-shared"), []byte("a-strong-enough-value"),
		[]byte("\xff\xfe\x00weird"), []byte("1234567"), []byte("12345678"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, value []byte) {
		var errDisabled, errEnabled error
		fuzzutil.Guard(t.Fatalf, "SecretValuePolicy.Validate", func() {
			errDisabled = disabled.Validate(value)
			errEnabled = enabled.Validate(value)
		})
		if errDisabled != nil {
			t.Fatalf("disabled SecretValuePolicy rejected a value (len=%d): %v", len(value), errDisabled)
		}
		if len(value) < minLen && errEnabled == nil {
			t.Fatalf("enabled SecretValuePolicy accepted a %d-byte value below the %d-byte minimum", len(value), minLen)
		}
	})
}

// FuzzPasswordPolicyValidate fuzzes PasswordPolicy.Validate over arbitrary
// password strings against the conservative DefaultPasswordPolicy (ADR-025). The
// per-rune classification loop (unicode.IsUpper/IsPunct/IsSymbol/...) runs over
// fully attacker-controlled, possibly invalid-UTF-8 input, and must never panic.
// A nil user is passed so the personal-info branch (guarded by user != nil) is
// skipped; that path needs its own harness with a populated user.
//
// Invariants: (a) never panics; (b) the effective minimum length cannot be
// disabled (a non-positive MinLength falls back to the built-in default), so any
// password shorter than the default minimum in BYTES must be rejected.
func FuzzPasswordPolicyValidate(f *testing.F) {
	policy := DefaultPasswordPolicy()
	effectiveMin := policy.MinLength // 16, and > 0 so it is honored as-is

	seeds := []string{
		"", "short", "aaaaaaaaaaaaaaaa", "Aa1!Aa1!Aa1!Aa1!",
		"correct horse battery staple", "P@ssw0rd", "пароль-пароль-пароль",
		"\xff\xff\xff\xff", "🔐🔐🔐🔐🔐🔐🔐🔐",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, pw string) {
		var err error
		fuzzutil.Guard(t.Fatalf, "PasswordPolicy.Validate", func() {
			err = policy.Validate(pw, nil)
		})
		if len(pw) < effectiveMin && err == nil {
			t.Fatalf("DefaultPasswordPolicy accepted a %d-byte password below the %d-byte floor: %q", len(pw), effectiveMin, pw)
		}
	})
}
