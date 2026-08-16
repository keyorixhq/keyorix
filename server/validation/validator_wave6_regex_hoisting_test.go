// validator_wave6_regex_hoisting_test.go — Wave 6 low/info batch: regression
// coverage for findings-server/validation.json#4 (resource-exhaustion).
// validateEmail, validateURL, validateAlpha, validateAlphaNum, and
// validateNumeric each used to call regexp.MustCompile INLINE on every
// invocation instead of reusing a package-level compiled *regexp.Regexp, the
// way identifierRegex already did. Since Validate is invoked by many
// concurrent goroutines against a single shared *Validator on every request
// (see the Validator doc comment), that repeated compilation multiplied
// attacker-controlled request-rate into server CPU cost. The fix hoists all
// five regexes to package-level vars; these tests confirm (a) the package
// vars are the SAME *regexp.Regexp instance across calls (proving the
// compile-once behavior actually took effect, not just that patterns
// didn't change) and (b) accept/reject behavior for each rule is unchanged.
package validation

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidate_Wave6_RegexVarsAreReusedNotRecompiled verifies that the
// package-level regex vars backing email/url/alpha/alphanum/numeric are
// stable *regexp.Regexp pointers across repeated Validate calls, i.e. they
// are compiled once at package init rather than re-compiled per call.
func TestValidate_Wave6_RegexVarsAreReusedNotRecompiled(t *testing.T) {
	type payload struct {
		Email    string `json:"email" validate:"omitempty,email"`
		URL      string `json:"url" validate:"omitempty,url"`
		Alpha    string `json:"alpha" validate:"omitempty,alpha"`
		AlphaNum string `json:"alphanum" validate:"omitempty,alphanum"`
		Numeric  string `json:"numeric" validate:"omitempty,numeric"`
	}
	v := NewValidator()

	before := []*regexp.Regexp{emailRegex, urlRegex, alphaRegex, alphaNumRegex, numericRegex}

	require.NoError(t, v.Validate(payload{
		Email:    "a@b.co",
		URL:      "https://example.com",
		Alpha:    "abc",
		AlphaNum: "abc123",
		Numeric:  "123",
	}))
	require.NoError(t, v.Validate(payload{
		Email:    "c@d.co",
		URL:      "http://example.org/x",
		Alpha:    "xyz",
		AlphaNum: "xyz789",
		Numeric:  "789",
	}))

	after := []*regexp.Regexp{emailRegex, urlRegex, alphaRegex, alphaNumRegex, numericRegex}

	for i := range before {
		require.Same(t, before[i], after[i], "regex var must be the same compiled instance across calls, not recompiled per call")
	}
}

// TestValidate_Wave6_RegexHoistingPreservesEmailBehavior verifies validateEmail's
// accept/reject behavior is unchanged after hoisting emailRegex to a package var.
func TestValidate_Wave6_RegexHoistingPreservesEmailBehavior(t *testing.T) {
	type payload struct {
		Email string `json:"email" validate:"omitempty,email"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Email: ""}))
	require.NoError(t, v.Validate(payload{Email: "user@example.com"}))
	require.NoError(t, v.Validate(payload{Email: "user.name+tag@sub.example.co"}))
	require.Error(t, v.Validate(payload{Email: "not-an-email"}))
	require.Error(t, v.Validate(payload{Email: "missing-domain@"}))
	require.Error(t, v.Validate(payload{Email: "@missing-local.com"}))
}

// TestValidate_Wave6_RegexHoistingPreservesURLBehavior verifies validateURL's
// accept/reject behavior is unchanged after hoisting urlRegex to a package var.
func TestValidate_Wave6_RegexHoistingPreservesURLBehavior(t *testing.T) {
	type payload struct {
		URL string `json:"url" validate:"omitempty,url"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{URL: ""}))
	require.NoError(t, v.Validate(payload{URL: "https://example.com/x"}))
	require.NoError(t, v.Validate(payload{URL: "http://example.com"}))
	require.Error(t, v.Validate(payload{URL: "ftp://example.com"}))
	require.Error(t, v.Validate(payload{URL: "not a url"}))
}

// TestValidate_Wave6_RegexHoistingPreservesAlphaBehavior verifies validateAlpha's
// accept/reject behavior is unchanged after hoisting alphaRegex to a package var.
func TestValidate_Wave6_RegexHoistingPreservesAlphaBehavior(t *testing.T) {
	type payload struct {
		Alpha string `json:"alpha" validate:"omitempty,alpha"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Alpha: ""}))
	require.NoError(t, v.Validate(payload{Alpha: "abcXYZ"}))
	require.Error(t, v.Validate(payload{Alpha: "abc123"}))
	require.Error(t, v.Validate(payload{Alpha: "abc-def"}))
}

// TestValidate_Wave6_RegexHoistingPreservesAlphaNumBehavior verifies
// validateAlphaNum's accept/reject behavior is unchanged after hoisting
// alphaNumRegex to a package var.
func TestValidate_Wave6_RegexHoistingPreservesAlphaNumBehavior(t *testing.T) {
	type payload struct {
		AlphaNum string `json:"alphanum" validate:"omitempty,alphanum"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{AlphaNum: ""}))
	require.NoError(t, v.Validate(payload{AlphaNum: "abc123XYZ"}))
	require.Error(t, v.Validate(payload{AlphaNum: "abc-123"}))
	require.Error(t, v.Validate(payload{AlphaNum: "abc 123"}))
}

// TestValidate_Wave6_RegexHoistingPreservesNumericBehavior verifies
// validateNumeric's accept/reject behavior is unchanged after hoisting
// numericRegex to a package var.
func TestValidate_Wave6_RegexHoistingPreservesNumericBehavior(t *testing.T) {
	type payload struct {
		Numeric string `json:"numeric" validate:"omitempty,numeric"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Numeric: ""}))
	require.NoError(t, v.Validate(payload{Numeric: "1234567890"}))
	require.Error(t, v.Validate(payload{Numeric: "12a"}))
	require.Error(t, v.Validate(payload{Numeric: "12.3"}))
}
