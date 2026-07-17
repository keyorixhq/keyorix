package validation

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- isBlank direct tests ---

// TestIsBlank_S22_EmptyString verifies that an empty string is blank.
func TestIsBlank_S22_EmptyString(t *testing.T) {
	assert.True(t, isBlank(""))
}

// TestIsBlank_S22_PureSpaces verifies that a string of only spaces is blank.
func TestIsBlank_S22_PureSpaces(t *testing.T) {
	assert.True(t, isBlank("   "))
}

// TestIsBlank_S22_TabAndNewline verifies that tab and newline are treated as blank.
func TestIsBlank_S22_TabAndNewline(t *testing.T) {
	assert.True(t, isBlank("\t\n\r"))
}

// TestIsBlank_S22_ControlChars verifies that Unicode Cc characters are treated as blank.
func TestIsBlank_S22_ControlChars(t *testing.T) {
	// U+0001 SOH and U+001F (US) are both Cc (control) characters.
	assert.True(t, isBlank("\x01\x1f"))
}

// TestIsBlank_S22_FormatChars verifies that Unicode Cf characters (zero-width non-joiner,
// soft-hyphen, etc.) are treated as blank.
func TestIsBlank_S22_FormatChars(t *testing.T) {
	// U+200C ZERO WIDTH NON-JOINER and U+00AD SOFT HYPHEN are both Cf.
	assert.True(t, isBlank("‌­"))
}

// TestIsBlank_S22_NonBlankLetterFalse verifies that a string with a real letter is not blank.
func TestIsBlank_S22_NonBlankLetterFalse(t *testing.T) {
	assert.False(t, isBlank("a"))
}

// TestIsBlank_S22_MixedBlankAndReal verifies that a real char among blanks makes isBlank false.
func TestIsBlank_S22_MixedBlankAndReal(t *testing.T) {
	assert.False(t, isBlank("  x  "))
}

// TestIsBlank_S22_UnicodeDigitIsNotBlank verifies that a Unicode digit is treated as non-blank.
func TestIsBlank_S22_UnicodeDigitIsNotBlank(t *testing.T) {
	// U+0660 ARABIC-INDIC DIGIT ZERO — not a space or Cf/Cc category.
	assert.False(t, isBlank("٠"))
}

// --- isEmpty — Uint kinds ---

// TestIsEmpty_S22_UintZero verifies that a uint(0) is considered empty.
func TestIsEmpty_S22_UintZero(t *testing.T) {
	v := &Validator{}
	assert.True(t, v.isEmpty(reflect.ValueOf(uint(0))))
}

// TestIsEmpty_S22_UintNonZero verifies that a non-zero uint is not considered empty.
func TestIsEmpty_S22_UintNonZero(t *testing.T) {
	v := &Validator{}
	assert.False(t, v.isEmpty(reflect.ValueOf(uint(1))))
}

// TestIsEmpty_S22_Uint8Variants exercises uint8 / uint16 / uint32 / uint64 kinds.
func TestIsEmpty_S22_Uint8Variants(t *testing.T) {
	v := &Validator{}

	assert.True(t, v.isEmpty(reflect.ValueOf(uint8(0))))
	assert.False(t, v.isEmpty(reflect.ValueOf(uint8(255))))

	assert.True(t, v.isEmpty(reflect.ValueOf(uint16(0))))
	assert.False(t, v.isEmpty(reflect.ValueOf(uint16(1))))

	assert.True(t, v.isEmpty(reflect.ValueOf(uint32(0))))
	assert.False(t, v.isEmpty(reflect.ValueOf(uint32(1))))

	assert.True(t, v.isEmpty(reflect.ValueOf(uint64(0))))
	assert.False(t, v.isEmpty(reflect.ValueOf(uint64(1))))
}

// TestIsEmpty_S22_Array exercises the Array branch of isEmpty.
func TestIsEmpty_S22_Array(t *testing.T) {
	v := &Validator{}

	// A [0]int array has length 0 — empty.
	emptyArr := reflect.ValueOf([0]int{})
	assert.True(t, v.isEmpty(emptyArr))

	// A [2]int array has length > 0 — not empty.
	nonEmptyArr := reflect.ValueOf([2]int{0, 0})
	assert.False(t, v.isEmpty(nonEmptyArr))
}

// --- derefForRule ---

// TestDerefForRule_S22_NonPointerPassthrough verifies that a non-pointer field
// is returned unchanged.
func TestDerefForRule_S22_NonPointerPassthrough(t *testing.T) {
	val := reflect.ValueOf("hello")
	resolved, ok := derefForRule(val)
	assert.True(t, ok)
	assert.Equal(t, "hello", resolved.String())
}

// TestDerefForRule_S22_NonNilPointerDeref verifies that a non-nil pointer is
// dereferenced and ok==true is returned.
func TestDerefForRule_S22_NonNilPointerDeref(t *testing.T) {
	s := "world"
	val := reflect.ValueOf(&s)
	resolved, ok := derefForRule(val)
	assert.True(t, ok)
	assert.Equal(t, "world", resolved.String())
}

// TestDerefForRule_S22_NilPointerReturnsFalse verifies that a nil pointer yields
// ok==false so the calling rule skips validation.
func TestDerefForRule_S22_NilPointerReturnsFalse(t *testing.T) {
	var p *string
	val := reflect.ValueOf(p)
	_, ok := derefForRule(val)
	assert.False(t, ok)
}

// --- validateMin / validateMax — slice and array branches via Validate ---

// TestValidate_S22_MinSlice verifies min enforcement on a slice field.
func TestValidate_S22_MinSlice(t *testing.T) {
	type payload struct {
		Tags []string `json:"tags" validate:"min=2"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Tags: []string{"a", "b"}}))
	require.Error(t, v.Validate(payload{Tags: []string{"a"}}), "below min")
	require.NoError(t, v.Validate(payload{Tags: []string{"a", "b", "c"}}))
}

// TestValidate_S22_MaxSlice verifies max enforcement on a slice field.
func TestValidate_S22_MaxSlice(t *testing.T) {
	type payload struct {
		Tags []string `json:"tags" validate:"max=2"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Tags: []string{"a", "b"}}))
	require.Error(t, v.Validate(payload{Tags: []string{"a", "b", "c"}}), "above max")
	require.NoError(t, v.Validate(payload{Tags: []string{}}))
}

// TestValidate_S22_MinMaxExactBoundary verifies that values at exactly the min and max
// boundaries pass validation.
func TestValidate_S22_MinMaxExactBoundary(t *testing.T) {
	type payload struct {
		Age int `json:"age" validate:"min=1,max=5"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Age: 1}), "exactly at min")
	require.NoError(t, v.Validate(payload{Age: 5}), "exactly at max")
	require.Error(t, v.Validate(payload{Age: 0}), "one below min")
	require.Error(t, v.Validate(payload{Age: 6}), "one above max")
}

// TestValidate_S22_MinMaxUintBoundary verifies uint fields at boundary values.
func TestValidate_S22_MinMaxUintBoundary(t *testing.T) {
	type payload struct {
		Count uint `json:"count" validate:"min=1,max=5"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Count: 1}), "exactly at min")
	require.NoError(t, v.Validate(payload{Count: 5}), "exactly at max")
	// Count=0 is isEmpty → would be skipped only if omitempty; without it, min fires.
	require.Error(t, v.Validate(payload{Count: 6}), "above max")
}

// TestValidate_S22_MinPointerNilSkips verifies that a nil *int pointer skips min
// (derefForRule returns ok=false).
func TestValidate_S22_MinPointerNilSkips(t *testing.T) {
	type payload struct {
		Count *int `json:"count" validate:"min=1"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Count: nil}), "nil pointer must skip min rule")
}

// TestValidate_S22_MaxPointerNilSkips verifies that a nil *int pointer skips max.
func TestValidate_S22_MaxPointerNilSkips(t *testing.T) {
	type payload struct {
		Count *int `json:"count" validate:"max=10"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Count: nil}), "nil pointer must skip max rule")
}

// --- validateEmail — nil pointer and non-string ---

// TestValidate_S22_EmailNilPointerSkips verifies that a nil *string pointer skips
// email validation.
func TestValidate_S22_EmailNilPointerSkips(t *testing.T) {
	type payload struct {
		Email *string `json:"email" validate:"email"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Email: nil}))
}

// TestValidate_S22_EmailEmptyStringPasses verifies that an empty email string passes
// (the rule delegates required enforcement to a separate `required` tag).
func TestValidate_S22_EmailEmptyStringPasses(t *testing.T) {
	type payload struct {
		Email string `json:"email" validate:"email"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Email: ""}))
}

// TestValidate_S22_EmailUnicodeLocalPartRejected verifies that an email with a
// Unicode local part is rejected by the ASCII-only regex.
func TestValidate_S22_EmailUnicodeLocalPartRejected(t *testing.T) {
	type payload struct {
		Email string `json:"email" validate:"email"`
	}
	v := NewValidator()

	// ñ is outside [a-zA-Z0-9._%+-], so the regex should reject it.
	require.Error(t, v.Validate(payload{Email: "ñoño@example.com"}))
}

// TestValidate_S22_EmailSubdomainAccepted verifies that a multi-label domain is
// accepted by the email validator.
func TestValidate_S22_EmailSubdomainAccepted(t *testing.T) {
	type payload struct {
		Email string `json:"email" validate:"email"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Email: "user@mail.example.co.uk"}))
}

// --- validateURL ---

// TestValidate_S22_URLNilPointerSkips verifies that a nil *string pointer skips URL
// validation.
func TestValidate_S22_URLNilPointerSkips(t *testing.T) {
	type payload struct {
		URL *string `json:"url" validate:"url"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{URL: nil}))
}

// TestValidate_S22_URLEmptyStringPasses verifies that an empty URL string passes.
func TestValidate_S22_URLEmptyStringPasses(t *testing.T) {
	type payload struct {
		URL string `json:"url" validate:"url"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{URL: ""}))
}

// TestValidate_S22_URLWithPathAndQueryAccepted verifies that a URL with a path and
// query string is accepted.
func TestValidate_S22_URLWithPathAndQueryAccepted(t *testing.T) {
	type payload struct {
		URL string `json:"url" validate:"url"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{URL: "https://api.example.com/v1/secrets?page=1"}))
}

// TestValidate_S22_URLSpaceInValueRejected verifies that whitespace inside a URL
// causes rejection.
func TestValidate_S22_URLSpaceInValueRejected(t *testing.T) {
	type payload struct {
		URL string `json:"url" validate:"url"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{URL: "https://example.com/path with space"}))
}

// --- validateAlpha ---

// TestValidate_S22_AlphaNilPointerSkips verifies that a nil *string pointer skips
// alpha validation.
func TestValidate_S22_AlphaNilPointerSkips(t *testing.T) {
	type payload struct {
		Name *string `json:"name" validate:"alpha"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: nil}))
}

// TestValidate_S22_AlphaEmptyStringPasses verifies that an empty string passes alpha.
func TestValidate_S22_AlphaEmptyStringPasses(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"alpha"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: ""}))
}

// TestValidate_S22_AlphaUpperAndLowerPasses verifies that mixed-case alpha strings pass.
func TestValidate_S22_AlphaUpperAndLowerPasses(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"alpha"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: "HelloWorld"}))
}

// TestValidate_S22_AlphaSpaceRejected verifies that a space character is rejected
// by alpha validation.
func TestValidate_S22_AlphaSpaceRejected(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"alpha"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Name: "hello world"}))
}

// TestValidate_S22_AlphaUnicodeLetterRejected verifies that a non-ASCII Unicode
// letter is rejected (the regex is ASCII-only).
func TestValidate_S22_AlphaUnicodeLetterRejected(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"alpha"`
	}
	v := NewValidator()

	// "café" contains é (U+00E9) which is outside [a-zA-Z].
	require.Error(t, v.Validate(payload{Name: "café"}))
}

// --- validateAlphaNum ---

// TestValidate_S22_AlphaNumNilPointerSkips verifies that a nil *string pointer skips
// alphanum validation.
func TestValidate_S22_AlphaNumNilPointerSkips(t *testing.T) {
	type payload struct {
		Code *string `json:"code" validate:"alphanum"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Code: nil}))
}

// TestValidate_S22_AlphaNumEmptyStringPasses verifies that an empty string passes alphanum.
func TestValidate_S22_AlphaNumEmptyStringPasses(t *testing.T) {
	type payload struct {
		Code string `json:"code" validate:"alphanum"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Code: ""}))
}

// TestValidate_S22_AlphaNumUnderscoreRejected verifies that an underscore is rejected
// by alphanum (only [a-zA-Z0-9] allowed).
func TestValidate_S22_AlphaNumUnderscoreRejected(t *testing.T) {
	type payload struct {
		Code string `json:"code" validate:"alphanum"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Code: "abc_123"}))
}

// --- validateNumeric ---

// TestValidate_S22_NumericNilPointerSkips verifies that a nil *string pointer skips
// numeric validation.
func TestValidate_S22_NumericNilPointerSkips(t *testing.T) {
	type payload struct {
		Pin *string `json:"pin" validate:"numeric"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Pin: nil}))
}

// TestValidate_S22_NumericEmptyStringPasses verifies that an empty string passes numeric.
func TestValidate_S22_NumericEmptyStringPasses(t *testing.T) {
	type payload struct {
		Pin string `json:"pin" validate:"numeric"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Pin: ""}))
}

// TestValidate_S22_NumericLeadingZeroAccepted verifies that a leading-zero number
// string passes (numeric only checks charset, not integer semantics).
func TestValidate_S22_NumericLeadingZeroAccepted(t *testing.T) {
	type payload struct {
		Pin string `json:"pin" validate:"numeric"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Pin: "007"}))
}

// TestValidate_S22_NumericDecimalRejected verifies that a decimal point is rejected
// by the numeric validator.
func TestValidate_S22_NumericDecimalRejected(t *testing.T) {
	type payload struct {
		Pin string `json:"pin" validate:"numeric"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Pin: "3.14"}))
}

// TestValidate_S22_NumericNegativeRejected verifies that a leading minus sign is
// rejected by the numeric validator.
func TestValidate_S22_NumericNegativeRejected(t *testing.T) {
	type payload struct {
		Pin string `json:"pin" validate:"numeric"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Pin: "-5"}))
}

// --- validateOneOf ---

// TestValidate_S22_OneOfNilPointerSkips verifies that a nil *string pointer skips
// oneof validation.
func TestValidate_S22_OneOfNilPointerSkips(t *testing.T) {
	type payload struct {
		Role *string `json:"role" validate:"oneof=admin viewer editor"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Role: nil}))
}

// TestValidate_S22_OneOfEmptyStringPasses verifies that an empty string passes oneof
// (enforcement of non-empty is a separate `required` concern).
func TestValidate_S22_OneOfEmptyStringPasses(t *testing.T) {
	type payload struct {
		Role string `json:"role" validate:"oneof=admin viewer"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Role: ""}))
}

// TestValidate_S22_OneOfSingleOption verifies that oneof works with a single allowed
// value.
func TestValidate_S22_OneOfSingleOption(t *testing.T) {
	type payload struct {
		Status string `json:"status" validate:"oneof=active"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Status: "active"}))
	require.Error(t, v.Validate(payload{Status: "inactive"}))
}

// TestValidate_S22_OneOfCaseSensitive verifies that oneof comparison is case-sensitive.
func TestValidate_S22_OneOfCaseSensitive(t *testing.T) {
	type payload struct {
		Env string `json:"env" validate:"oneof=dev staging prod"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Env: "Dev"}), "oneof must be case-sensitive")
	require.Error(t, v.Validate(payload{Env: "PROD"}), "oneof must be case-sensitive")
}

// --- validateIdentifier ---

// TestValidate_S22_IdentifierUnicodePunctuationRejected verifies that Unicode punctuation
// outside the allowlist is rejected.
func TestValidate_S22_IdentifierUnicodePunctuationRejected(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"identifier"`
	}
	v := NewValidator()

	// U+2019 RIGHT SINGLE QUOTATION MARK — not in [a-zA-Z0-9 _-].
	require.Error(t, v.Validate(payload{Name: "it’s"}))
}

// TestValidate_S22_IdentifierHyphenAndUnderscoreAccepted verifies that hyphens and
// underscores are accepted by the identifier validator.
func TestValidate_S22_IdentifierHyphenAndUnderscoreAccepted(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"identifier"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: "prod-db_01"}))
}

// TestValidate_S22_IdentifierSpaceAccepted verifies that an internal space is accepted
// by the identifier validator.
func TestValidate_S22_IdentifierSpaceAccepted(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"identifier"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: "my project"}))
}

// TestValidate_S22_IdentifierEmptyStringPasses verifies that an empty string passes
// the identifier validator (use `required` to enforce non-empty).
func TestValidate_S22_IdentifierEmptyStringPasses(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"identifier"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: ""}))
}

// TestValidate_S22_IdentifierAtSignRejected verifies that @ is rejected.
func TestValidate_S22_IdentifierAtSignRejected(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"identifier"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Name: "user@example"}))
}

// TestValidate_S22_IdentifierDotRejected verifies that a dot is rejected.
func TestValidate_S22_IdentifierDotRejected(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"identifier"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Name: "v1.2"}))
}

// --- JSON field name resolution ---

// TestValidate_S22_JSONTagDashFallsBackToGoName verifies that when the json tag is
// "-" the Go field name is used in the error.
func TestValidate_S22_JSONTagDashFallsBackToGoName(t *testing.T) {
	type payload struct {
		MyField string `json:"-" validate:"required"`
	}
	v := NewValidator()

	err := v.Validate(payload{})
	require.Error(t, err)
	ve := err.(ValidationErrors)
	require.Len(t, ve.Errors, 1)
	assert.Equal(t, "MyField", ve.Errors[0].Field, "'-' json tag must fall back to Go field name")
}

// TestValidate_S22_JSONTagCommaOnlyFallsBackToGoName verifies that a json tag of
// ",omitempty" (blank name part) falls back to the Go field name.
func TestValidate_S22_JSONTagCommaOnlyFallsBackToGoName(t *testing.T) {
	type payload struct {
		MyField string `json:",omitempty" validate:"required"`
	}
	v := NewValidator()

	err := v.Validate(payload{MyField: ""})
	require.Error(t, err)
	ve := err.(ValidationErrors)
	require.Len(t, ve.Errors, 1)
	assert.Equal(t, "MyField", ve.Errors[0].Field, "blank json name must fall back to Go field name")
}

// --- Unknown rule ---

// TestValidate_S22_UnknownRuleIsIgnored verifies that an unrecognised validation tag
// rule name produces no error rather than panicking or failing validation.
func TestValidate_S22_UnknownRuleIsIgnored(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"unknown_rule"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: "anything"}))
}

// --- ValidationError Value field (json:"value,omitempty") ---

// TestValidationError_S22_OmitsValueWhenNil verifies that the Value field is omitted
// from the struct zero value (nil interface).
func TestValidationError_S22_OmitsValueWhenNil(t *testing.T) {
	ve := ValidationError{Field: "f", Message: "m"}
	assert.Nil(t, ve.Value)
}

// TestValidationError_S22_PreservesValueWhenSet verifies that a non-nil Value is
// preserved on the ValidationError struct.
func TestValidationError_S22_PreservesValueWhenSet(t *testing.T) {
	ve := ValidationError{Field: "f", Message: "m", Value: "bad-input"}
	assert.Equal(t, "bad-input", ve.Value)
}

// --- ValidationErrors.Error format ---

// TestValidationErrors_S22_SingleError verifies the error string for a single entry.
func TestValidationErrors_S22_SingleError(t *testing.T) {
	ve := ValidationErrors{Errors: []ValidationError{{Field: "email", Message: "invalid format"}}}
	assert.Equal(t, "email: invalid format", ve.Error())
}

// TestValidationErrors_S22_EmptyErrors verifies that an empty Errors slice produces
// an empty string (no panic, no separator).
func TestValidationErrors_S22_EmptyErrors(t *testing.T) {
	ve := ValidationErrors{}
	assert.Equal(t, "", ve.Error())
}

// --- Min/Max string — exact boundary ---

// TestValidate_S22_MinStringExactBoundary verifies that a string of exactly min length
// passes.
func TestValidate_S22_MinStringExactBoundary(t *testing.T) {
	type payload struct {
		Code string `json:"code" validate:"min=3"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Code: "abc"}), "exactly 3 chars must pass min=3")
	require.Error(t, v.Validate(payload{Code: "ab"}), "2 chars must fail min=3")
}

// TestValidate_S22_MaxStringExactBoundary verifies that a string of exactly max length
// passes.
func TestValidate_S22_MaxStringExactBoundary(t *testing.T) {
	type payload struct {
		Code string `json:"code" validate:"max=3"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Code: "abc"}), "exactly 3 chars must pass max=3")
	require.Error(t, v.Validate(payload{Code: "abcd"}), "4 chars must fail max=3")
}

// TestValidate_S22_MaxStringVeryLong verifies that a very long string fails max.
func TestValidate_S22_MaxStringVeryLong(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"max=100"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Name: strings.Repeat("a", 101)}))
}
