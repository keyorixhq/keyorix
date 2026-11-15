package cloudfuzz

import (
	"errors"
	"testing"
)

// captureFatalf returns a fatalf-style callback and a pointer to a bool it sets
// when called, so scanSecretsInError (the core of AssertNoSecretInError) can be
// proven to FIRE on a leak and stay quiet on a clean input — the red/green
// discipline applied to the oracle itself so it is demonstrably not vacuous.
func captureFatalf() (func(string, ...any), *bool) {
	fired := new(bool)
	return func(string, ...any) { *fired = true }, fired
}

// TestScanSecretsInError_FiresOnLeak is the RED proof: an error containing a sent
// credential must trip the oracle.
func TestScanSecretsInError_FiresOnLeak(t *testing.T) {
	fatalf, fired := captureFatalf()
	scanSecretsInError(fatalf, "op", errors.New("auth failed for AKIACANARY123 at host"), "AKIACANARY123")
	if !*fired {
		t.Fatal("oracle did not fire when a sent credential appeared in the error — it is vacuous")
	}
}

// TestScanSecretsInError_SilentWhenClean is the GREEN proof: an error with no
// credential, a nil error, and an empty-secret entry must all pass.
func TestScanSecretsInError_SilentWhenClean(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		secret string
	}{
		{"no-secret-in-msg", errors.New("connection refused"), "AKIACANARY123"},
		{"nil-error", nil, "AKIACANARY123"},
		{"empty-secret-ignored", errors.New("whatever AKIACANARY123"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fatalf, fired := captureFatalf()
			scanSecretsInError(fatalf, "op", tc.err, tc.secret)
			if *fired {
				t.Fatalf("oracle fired on a clean case (%s) — false positive", tc.name)
			}
		})
	}
}

// TestClampHTTPStatus covers the range contract: in-range passes through
// unchanged (guards against an earlier version that folded every value through
// modulo), out-of-range maps into [200,599] and never 1xx.
func TestClampHTTPStatus(t *testing.T) {
	for _, v := range []int{200, 204, 301, 307, 400, 403, 429, 500, 503, 599} {
		if got := ClampHTTPStatus(v); got != v {
			t.Fatalf("in-range status %d was remapped to %d (must pass through unchanged)", v, got)
		}
	}
	for _, v := range []int{-1, -600, 0, 100, 150, 199, 600, 1200, 99999} {
		got := ClampHTTPStatus(v)
		if got < 200 || got > 599 {
			t.Fatalf("out-of-range status %d mapped to %d, outside [200,599]", v, got)
		}
	}
}
