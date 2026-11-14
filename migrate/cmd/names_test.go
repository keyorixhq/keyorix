package cmd

import (
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/cloudentry"
	"github.com/keyorixhq/keyorix/migrate/internal/plan"
	"github.com/keyorixhq/keyorix/migrate/internal/vaultsource"
)

// TestSanitizeSecretName_StripsControlAndIsFixedPoint is the F1 regression: control characters
// must never survive into a derived Keyorix secret name, and the function must be a fixed point
// so a re-run derives the identical name. Pre-fix, "0\v/" -> "0\v" (a trailing vertical tab) and
// a second pass changed it to "0".
func TestSanitizeSecretName_StripsControlAndIsFixedPoint(t *testing.T) {
	cases := map[string]string{
		"0\v/":         "0",
		"ctrl\x00char": "ctrlchar",
		"new\nline":    "newline",
		"a/b\tc":       "a-bc",
		"team-a/db":    "team-a-db",
		"---":          "", // all-separator: empty is allowed (callers skip it)
		"\x00":         "", // all-control: empty
		"секрет/ключ":  "секрет-ключ",
		// A non-ASCII space (NBSP, U+2003, ...) next to a control byte or '-' at an edge used to
		// survive the first pass (TrimSpace ran before the strip and the '-' trim) and was removed
		// by the second: not a fixed point (FuzzSanitizeSecretName: "0\u00a0\b" -> "0\u00a0" -> "0").
		"0\u00a0\b":   "0",
		"a\u00a0-":    "a",
		"a\u00a0\x00": "a",
		"\x00\u00a0a": "a",
		"a\u00a0/":    "a",
		"-\u2003-a":   "a",
		"a\u00a0b":    "a\u00a0b", // an inner Unicode space is kept (only edges are trimmed)
	}
	for in, want := range cases {
		got := sanitizeSecretName(in)
		if got != want {
			t.Errorf("sanitizeSecretName(%q) = %q, want %q", in, got, want)
		}
		if again := sanitizeSecretName(got); again != got {
			t.Errorf("sanitizeSecretName not a fixed point for %q: %q -> %q", in, got, again)
		}
	}
}

// TestBuildCloudPlanEntries_EmptyDerivedNameIsSkipped proves the call-site half of the F1 fix: a
// source item whose name normalises to "" is reported as a Skip, never planned as a Create under
// an empty name.
func TestBuildCloudPlanEntries_EmptyDerivedNameIsSkipped(t *testing.T) {
	entries := []cloudentry.Entry{
		{RawName: "---", Value: "v1", Locator: "loc-empty"},
		{RawName: "real", Value: "v2", Locator: "loc-real"},
	}
	out, skipped := buildCloudPlanEntries("aws", entries, func(e cloudentry.Entry) string { return "sid-" + e.RawName })
	if len(out) != 1 || out[0].Name != "real" {
		t.Fatalf("out = %+v, want exactly one entry named \"real\"", out)
	}
	if len(skipped) != 1 {
		t.Fatalf("skipped = %+v, want exactly one skip for the empty-derived name", skipped)
	}
	if skipped[0].Outcome != plan.Skip || skipped[0].Reason != emptyDerivedNameSkipReason {
		t.Errorf("skip = %+v, want Outcome=Skip Reason=%q", skipped[0], emptyDerivedNameSkipReason)
	}
	if skipped[0].Entry.Path != "loc-empty" {
		t.Errorf("skip locator = %q, want loc-empty", skipped[0].Entry.Path)
	}
}

// TestBuildVaultPlanEntries_EmptyDerivedNameIsSkipped is the vault-side twin of the cloud test
// above: a walked Vault entry whose path (or path-field) normalises to "" is reported as a Skip
// under its human-readable vault: path, never planned as a Create under an empty name.
func TestBuildVaultPlanEntries_EmptyDerivedNameIsSkipped(t *testing.T) {
	entries := []vaultsource.Entry{
		{Path: "---", Value: "v1"},
		{Path: "/", Field: "\x00", Value: "v2"},
		{Path: "app/db", Field: "password", Value: "v3", Version: 2},
	}
	out, skipped := buildVaultPlanEntries("https://vault.example", "secret", entries)
	if len(out) != 1 || out[0].Name != "app-db-password" || out[0].SourceVersion != "2" {
		t.Fatalf("out = %+v, want exactly one entry named \"app-db-password\" at version 2", out)
	}
	wantPaths := []string{"vault:secret/---", "vault:secret//#\x00"}
	if len(skipped) != len(wantPaths) {
		t.Fatalf("skipped = %+v, want %d skips for the empty-derived names", skipped, len(wantPaths))
	}
	for i, s := range skipped {
		if s.Outcome != plan.Skip || s.Reason != emptyDerivedNameSkipReason || s.Entry.Path != wantPaths[i] {
			t.Errorf("skipped[%d] = %+v, want Outcome=Skip Reason=%q Path=%q", i, s, emptyDerivedNameSkipReason, wantPaths[i])
		}
	}
}
