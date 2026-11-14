package cmd

// names_fuzz_test.go: FuzzSanitizeSecretName drives the provider-name → Keyorix-secret-name
// normaliser with hostile bytes. sanitizeSecretName is on the write path of every import
// command: a Vault KV key, an AWS/Azure/GCP secret name (all attacker-controlled at first
// contact) is passed through it to derive the target Keyorix secret name (cmd/vault.go,
// cmd/cloud_common.go buildCloudPlanEntries). Idempotent re-runs (task oracle (d)) depend on
// this deriving the SAME name every run, and a name that still carries a path separator, an
// un-trimmed shape, or a control character would reach the target mapping malformed (task
// oracle (c)).
//
// All oracles below are fatal by default (campaign FINDING F1 is fixed, so production upholds
// them). The doc comment promises path separators / spaces / colons collapse to '-', control
// characters are dropped, repeated '-' collapse, surrounding '-' are trimmed, and the function
// is a fixed point. Output must therefore contain no '/', '\\', ' ', ':', no "--", no
// leading/trailing '-', no control character, and sanitizing it again must not change it. A
// violation is a real DEFECT. These checks do NOT verify the Keyorix server then accepts the
// name (server concern).
//
// Note on empty results: sanitizeSecretName MAY legitimately return "" for a degenerate input
// made entirely of separators/control characters (e.g. "---"). That is not a function-level
// defect — the call sites skip such an entry with a reported reason rather than sending an empty
// name to the API (see emptyDerivedNameSkipReason, TestSanitizeSecretName_EmptyDerivedNameIsSkipped).

import (
	"strconv"
	"strings"
	"testing"
	"unicode"
)

func FuzzSanitizeSecretName(f *testing.F) {
	for _, s := range []string{
		``,
		`simple`,
		`a/b/c`,
		`a\b:c d`,
		`  spaced  `,
		`---`,
		`a//b`,
		`../../etc/passwd`,
		`/absolute/path`,
		"ctrl\x00char",
		"new\nline",
		"team-a/db-password",
		strings.Repeat("a/", 1000),
		"секрет/ключ",
		"a:::b",
		"0\v/",
		"0\u00a0\b",
		"a\u00a0-",
		"a\u00a0/",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		out := sanitizeSecretName(s)

		// No separator survives, no doubled or edge '-'.
		for _, bad := range []string{"/", "\\", " ", ":"} {
			if strings.Contains(out, bad) {
				t.Fatalf("sanitizeSecretName(%q) = %q still contains separator %q", s, out, bad)
			}
		}
		if strings.Contains(out, "--") {
			t.Fatalf("sanitizeSecretName(%q) = %q still contains a doubled '-'", s, out)
		}
		if strings.HasPrefix(out, "-") || strings.HasSuffix(out, "-") {
			t.Fatalf("sanitizeSecretName(%q) = %q has an untrimmed edge '-'", s, out)
		}

		// No control character may reach the derived name (task oracle (c)).
		for _, r := range out {
			if unicode.IsControl(r) {
				t.Fatalf("sanitizeSecretName(%q) = %q carries control char %s into the Keyorix secret name", s, out, strconv.QuoteRune(r))
			}
		}

		// The function is a fixed point: a second pass must not change the result (idempotency,
		// task oracle (d)).
		if again := sanitizeSecretName(out); again != out {
			t.Fatalf("sanitizeSecretName not a fixed point: %q -> %q -> %q", s, out, again)
		}
	})
}
