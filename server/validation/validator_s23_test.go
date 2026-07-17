package validation

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- validateField: empty rule after TrimSpace ---

// TestValidateField_S23_EmptyRuleSkipped verifies that a blank rule segment
// produced by a tag like "required, ,min=3" (space between commas) is silently
// skipped rather than causing a panic or unexpected error.
func TestValidateField_S23_EmptyRuleSkipped(t *testing.T) {
	// A tag with a stray comma-space produces an empty string after TrimSpace,
	// exercising the `if rule == "" { continue }` branch in validateField.
	type payload struct {
		Name string `validate:"required, ,min=1"`
	}
	v := NewValidator()

	// Valid value: required passes and the empty segment is silently skipped.
	require.NoError(t, v.Validate(payload{Name: "x"}))

	// Invalid value: required fires (empty segment is still silently skipped).
	require.Error(t, v.Validate(payload{Name: ""}))
}

// --- validateMin: uint field below min ---

// TestValidateMin_S23_UintBelowMin verifies that a uint field whose value is
// less than min triggers the "must be at least N" error.
func TestValidateMin_S23_UintBelowMin(t *testing.T) {
	type payload struct {
		Count uint `json:"count" validate:"min=5"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Count: 4}), "uint below min must fail")
	require.NoError(t, v.Validate(payload{Count: 5}), "uint at exactly min must pass")
}

// TestValidateMin_S23_Uint64BelowMin exercises the uint64 branch with a value
// strictly below the min boundary.
func TestValidateMin_S23_Uint64BelowMin(t *testing.T) {
	v := &Validator{}
	errs := make(map[string][]string)
	field := reflect.ValueOf(uint64(2))
	v.validateField(errs, "count", field, "min=3")
	assert.NotEmpty(t, errs["count"], "uint64 below min must record an error")
}

// --- validateMin: negative min param on uint field (IntToUint64 error path) ---

// TestValidateMin_S23_NegativeMinOnUintField verifies that a negative min
// parameter on a uint field returns the "invalid min value" error from
// IntToUint64, rather than panicking or silently passing.
func TestValidateMin_S23_NegativeMinOnUintField(t *testing.T) {
	v := &Validator{}
	errs := make(map[string][]string)
	field := reflect.ValueOf(uint(10))
	v.validateField(errs, "val", field, "min=-1")
	assert.NotEmpty(t, errs["val"], "negative min param on uint field must produce an error")
}

// --- validateMax: negative max param on uint field (IntToUint64 error path) ---

// TestValidateMax_S23_NegativeMaxOnUintField verifies that a negative max
// parameter on a uint field returns the "invalid max value" error from
// IntToUint64.
func TestValidateMax_S23_NegativeMaxOnUintField(t *testing.T) {
	v := &Validator{}
	errs := make(map[string][]string)
	field := reflect.ValueOf(uint(0))
	v.validateField(errs, "val", field, "max=-1")
	assert.NotEmpty(t, errs["val"], "negative max param on uint field must produce an error")
}

// --- validateEmail: non-string field (kind != String early return) ---

// TestValidateEmail_S23_NonStringFieldSkipped verifies that an int field tagged
// with "email" is silently skipped (returns nil) rather than panicking.
func TestValidateEmail_S23_NonStringFieldSkipped(t *testing.T) {
	type payload struct {
		Count int `json:"count" validate:"email"`
	}
	v := NewValidator()
	require.NoError(t, v.Validate(payload{Count: 42}))
}

// --- validateURL: non-string field ---

// TestValidateURL_S23_NonStringFieldSkipped verifies that an int field tagged
// with "url" is silently skipped.
func TestValidateURL_S23_NonStringFieldSkipped(t *testing.T) {
	type payload struct {
		Count int `json:"count" validate:"url"`
	}
	v := NewValidator()
	require.NoError(t, v.Validate(payload{Count: 1}))
}

// --- validateAlpha: non-string field ---

// TestValidateAlpha_S23_NonStringFieldSkipped verifies that an int field tagged
// with "alpha" is silently skipped.
func TestValidateAlpha_S23_NonStringFieldSkipped(t *testing.T) {
	type payload struct {
		Count int `json:"count" validate:"alpha"`
	}
	v := NewValidator()
	require.NoError(t, v.Validate(payload{Count: 7}))
}

// --- validateAlphaNum: non-string field ---

// TestValidateAlphaNum_S23_NonStringFieldSkipped verifies that an int field
// tagged with "alphanum" is silently skipped.
func TestValidateAlphaNum_S23_NonStringFieldSkipped(t *testing.T) {
	type payload struct {
		Count int `json:"count" validate:"alphanum"`
	}
	v := NewValidator()
	require.NoError(t, v.Validate(payload{Count: 3}))
}

// --- validateNumeric: non-string field ---

// TestValidateNumeric_S23_NonStringFieldSkipped verifies that an int field
// tagged with "numeric" is silently skipped.
func TestValidateNumeric_S23_NonStringFieldSkipped(t *testing.T) {
	type payload struct {
		Count int `json:"count" validate:"numeric"`
	}
	v := NewValidator()
	require.NoError(t, v.Validate(payload{Count: 5}))
}

// --- validateOneOf: non-string field ---

// TestValidateOneOf_S23_NonStringFieldSkipped verifies that an int field tagged
// with "oneof=1 2 3" is silently skipped (the kind != String guard returns nil).
func TestValidateOneOf_S23_NonStringFieldSkipped(t *testing.T) {
	type payload struct {
		Count int `json:"count" validate:"oneof=1 2 3"`
	}
	v := NewValidator()
	require.NoError(t, v.Validate(payload{Count: 99}))
}

// --- validateIdentifier: non-string field ---

// TestValidateIdentifier_S23_NonStringFieldSkipped verifies that an int field
// tagged with "identifier" is silently skipped (the kind != String guard
// returns nil without invoking the regex).
func TestValidateIdentifier_S23_NonStringFieldSkipped(t *testing.T) {
	type payload struct {
		Count int `json:"count" validate:"identifier"`
	}
	v := NewValidator()
	require.NoError(t, v.Validate(payload{Count: 0}))
}

// --- validateMin/validateMax: non-pointer int kinds (Int8 / Int16 / Int32) ---

// TestValidateMin_S23_Int8BelowMin exercises the Int8 sub-kind via the
// Int/Int8/… case in validateMin.
func TestValidateMin_S23_Int8BelowMin(t *testing.T) {
	v := &Validator{}
	errs := make(map[string][]string)
	field := reflect.ValueOf(int8(1))
	v.validateField(errs, "val", field, "min=5")
	assert.NotEmpty(t, errs["val"], "int8 below min must error")
}

// TestValidateMax_S23_Int16AboveMax exercises the Int16 sub-kind via the
// Int/Int16/… case in validateMax.
func TestValidateMax_S23_Int16AboveMax(t *testing.T) {
	v := &Validator{}
	errs := make(map[string][]string)
	field := reflect.ValueOf(int16(20))
	v.validateField(errs, "val", field, "max=10")
	assert.NotEmpty(t, errs["val"], "int16 above max must error")
}
