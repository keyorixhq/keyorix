package core

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzValidateSCIMTokenStrength fuzzes ValidateSCIMTokenStrength, the startup
// guard that rejects an operator-supplied SCIM bearer token below
// MinSCIMTokenLength. Unlike PAT/machine tokens (server-generated, 32 random
// bytes), the SCIM token is configured by hand (scim.token / KEYORIX_SCIM_TOKEN)
// and, before this guard, had no strength floor: a short, guessable value would be
// accepted by the constant-time compare and authenticate every /scim/v2 request
// forever. The function is small but sits on a security boundary, and a regression
// (a flipped comparison, an off-by-one, a rune-vs-byte length mixup, or accepting
// empty as configured) would silently reweaken provisioning auth.
//
// The contract is a pure length decision on the BYTE length (the function uses
// len(token), not rune count): empty -> nil (SCIM legitimately disabled/unset);
// 1..MinSCIMTokenLength-1 bytes -> error (too short); >=MinSCIMTokenLength bytes
// -> nil. This harness re-derives that decision independently and asserts Verify
// never panics and never disagrees. It deliberately exercises multi-byte UTF-8
// tokens, whose rune count differs from their byte length, to pin the len()
// semantics the constant-time compare later relies on.
func FuzzValidateSCIMTokenStrength(f *testing.F) {
	seeds := []string{
		"",      // empty -> disabled, accepted
		"short", // clearly too short
		strings.Repeat("a", MinSCIMTokenLength-1), // 19 bytes -> just too short
		strings.Repeat("a", MinSCIMTokenLength),   // 20 bytes -> just long enough
		strings.Repeat("a", MinSCIMTokenLength+1), // 21 bytes -> long enough
		strings.Repeat("a", 64),                   // comfortably long
		"Okta-Provisioning-Token-2026-xyz123",     // realistic long token
		"aaaaaaaaaaaaaaaaaaa",                     // 19 'a'
		"aaaaaaaaaaaaaaaaaaaa",                    // 20 'a'
		"日本語トークン",                                 // multi-byte: few runes, may cross byte floor
		strings.Repeat("é", 10),                   // 10 runes / 20 bytes -> long enough by bytes
		strings.Repeat("é", 9),                    // 9 runes / 18 bytes -> too short by bytes
		"\x00\x00\x00\x00\x00",                    // NUL bytes, too short
		" " + strings.Repeat("x", 25),             // leading space, long
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, token string) {
		var err error
		fuzzutil.Guard(t.Fatalf, "ValidateSCIMTokenStrength", func() {
			err = ValidateSCIMTokenStrength(token)
		})

		switch {
		case token == "":
			// SCIM disabled / not configured is legitimate: must be accepted.
			if err != nil {
				t.Fatalf("ValidateSCIMTokenStrength(%q): empty token must be accepted (SCIM disabled), got err=%v", token, err)
			}
		case len(token) < MinSCIMTokenLength:
			// WEAK-CREDENTIAL invariant: a non-empty token below the byte floor must
			// be rejected, otherwise a guessable provisioning credential is accepted.
			if err == nil {
				t.Fatalf("SCIM WEAK TOKEN ACCEPTED: %d-byte token %q < minimum %d was accepted", len(token), token, MinSCIMTokenLength)
			}
		default:
			// >= MinSCIMTokenLength bytes: must be accepted.
			if err != nil {
				t.Fatalf("ValidateSCIMTokenStrength(%q): %d-byte token (>= %d) was rejected: %v", token, len(token), MinSCIMTokenLength, err)
			}
		}

		// Length decision must be byte-based, not rune-based: assert the guard did
		// not use rune count where that would flip the accept/reject decision.
		if rc := utf8.RuneCountInString(token); rc != len(token) && rc < MinSCIMTokenLength && len(token) >= MinSCIMTokenLength {
			if err != nil {
				t.Fatalf("ValidateSCIMTokenStrength(%q): rejected a token that is long enough in BYTES (%d) though short in runes (%d) — length check must be byte-based", token, len(token), rc)
			}
		}
	})
}
