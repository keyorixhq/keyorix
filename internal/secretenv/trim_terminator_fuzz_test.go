package secretenv

// FuzzTrimOneTerminator checks trimOneTerminator -- the normalisation applied to
// every secret read from a file (readSecretFileJudged) and the reason
// KEYORIX_MASTER_PASSWORD_FILE and `--passphrase-file` derive the SAME KEK from
// the same bytes (internal/crypto/passphrase.go strips identically). The file
// content is untrusted operator/orchestrator input; a bug here either changes
// the derived key (strip too much) or leaves a stray terminator in a token
// (strip too little), both silent.
//
// ORACLE (exact spec of the removed suffix -- cannot false-positive):
//
//	Let out = trimOneTerminator(s). Then:
//	  - out is a prefix of s (the function only removes a trailing run), and
//	  - the removed suffix s[len(out):] is EXACTLY one of "", "\n", "\r", "\r\n".
//
// That second clause is the whole contract: "strip ONE trailing line
// terminator" -- a "\n", "\r\n" or lone "\r", and nothing more. Any other
// removed suffix (e.g. "\n\n" from a TrimRight bug, or "x" from an off-by-one)
// fails it. The set is closed and derived from the spec, not from re-running the
// implementation, so the assertion cannot false-positive.
//
// WHAT THIS DOES NOT VERIFY:
//   - It does not compare against passphrase.go's copy of the rule (a
//     cross-package drift test would belong there); it only pins this function
//     to its stated contract.
//   - It does not assert WHICH of the four suffixes is removed for a given input
//     (that would re-implement the function); only that the removed suffix is a
//     legal one.
//   - It says nothing about the empty-result handling (readSecretFileJudged
//     turns an empty trimmed value into an error) -- that is the caller's.

import (
	"strings"
	"testing"
)

func FuzzTrimOneTerminator(f *testing.F) {
	for _, s := range []string{
		"", "secret", "secret\n", "secret\r\n", "secret\r",
		"secret\n\n", "secret\r\r", "secret\n\r", "\n", "\r\n", "\r",
		"a\nb\n", "has\rinternal\rcr", "trailing spaces   ", "\x00binary\x00",
	} {
		f.Add(s)
	}

	allowed := map[string]bool{"": true, "\n": true, "\r": true, "\r\n": true}

	f.Fuzz(func(t *testing.T, s string) {
		out := trimOneTerminator(s)

		if !strings.HasPrefix(s, out) {
			t.Fatalf("trimOneTerminator(%q)=%q is not a prefix of the input", s, out)
		}
		removed := s[len(out):]
		if !allowed[removed] {
			t.Fatalf("trimOneTerminator(%q)=%q removed suffix %q, which is not one line terminator", s, out, removed)
		}
	})
}
