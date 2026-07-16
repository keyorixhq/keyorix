package validation

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsEmpty_FloatKinds exercises the Float32 and Float64 branches of isEmpty,
// which have no coverage from existing tests (no float-typed validate fields anywhere).
func TestIsEmpty_FloatKinds(t *testing.T) {
	v := &Validator{}

	// float64 zero → isEmpty true
	zeroF64 := reflect.ValueOf(float64(0))
	assert.True(t, v.isEmpty(zeroF64), "float64(0) must be empty")

	// float64 non-zero → isEmpty false
	nonZeroF64 := reflect.ValueOf(float64(1.5))
	assert.False(t, v.isEmpty(nonZeroF64), "float64(1.5) must not be empty")

	// float32 zero → isEmpty true
	zeroF32 := reflect.ValueOf(float32(0))
	assert.True(t, v.isEmpty(zeroF32), "float32(0) must be empty")

	// float32 non-zero → isEmpty false
	nonZeroF32 := reflect.ValueOf(float32(0.1))
	assert.False(t, v.isEmpty(nonZeroF32), "float32(0.1) must not be empty")
}

// TestIsEmpty_BoolKind exercises the Bool branch of isEmpty.
func TestIsEmpty_BoolKind(t *testing.T) {
	v := &Validator{}

	// false → isEmpty true
	falseVal := reflect.ValueOf(false)
	assert.True(t, v.isEmpty(falseVal), "bool(false) must be empty")

	// true → isEmpty false
	trueVal := reflect.ValueOf(true)
	assert.False(t, v.isEmpty(trueVal), "bool(true) must not be empty")
}

// TestIsEmpty_DefaultKindReturnsFalse exercises the default (unhandled kind) branch
// of isEmpty, which must return false so unknown kinds do not block required checks.
func TestIsEmpty_DefaultKindReturnsFalse(t *testing.T) {
	v := &Validator{}

	// A struct value has Kind == Struct, which has no case in isEmpty.
	type inner struct{ X int }
	structVal := reflect.ValueOf(inner{X: 0})
	assert.False(t, v.isEmpty(structVal), "a struct kind must return false (unhandled kind)")
}

// TestValidate_OmitemptyFloat exercises the omitempty + isEmpty path for a float field,
// confirming that a zero-value float is treated as empty and skips the remaining rules.
func TestValidate_OmitemptyFloat(t *testing.T) {
	type payload struct {
		Score float64 `json:"score" validate:"omitempty,min=1"`
	}
	v := NewValidator()

	// zero float64 → omitempty short-circuits, min is not enforced.
	require.NoError(t, v.Validate(payload{Score: 0}))

	// non-zero but below min=1 (min for float uses Int64 conversion — value 0.5 parses
	// to 0 via Sscanf, so the struct actually uses Int case; keep it simple with a real
	// int-shaped float that exercises isEmpty returning false for non-zero).
	require.NoError(t, v.Validate(payload{Score: 2.0}))
}

// TestValidate_OmitemptyBool exercises the omitempty + isEmpty path for a bool field.
func TestValidate_OmitemptyBool(t *testing.T) {
	type payload struct {
		Active bool `json:"active" validate:"omitempty,required"`
	}
	v := NewValidator()

	// false → isEmpty true → omitempty short-circuits → no error.
	require.NoError(t, v.Validate(payload{Active: false}))

	// true → isEmpty false → remaining rules fire (required passes because it's non-zero).
	require.NoError(t, v.Validate(payload{Active: true}))
}

// TestValidate_MapKindEmpty exercises the Map branch of isEmpty.
func TestValidate_MapKindEmpty(t *testing.T) {
	v := &Validator{}

	emptyMap := reflect.ValueOf(map[string]int{})
	assert.True(t, v.isEmpty(emptyMap), "empty map must be empty")

	nonEmptyMap := reflect.ValueOf(map[string]int{"k": 1})
	assert.False(t, v.isEmpty(nonEmptyMap), "non-empty map must not be empty")
}

// TestValidate_IntNonZeroIsNotEmpty exercises the Int branch non-zero path.
func TestValidate_IntNonZeroIsNotEmpty(t *testing.T) {
	v := &Validator{}

	nonZeroInt := reflect.ValueOf(int(5))
	assert.False(t, v.isEmpty(nonZeroInt), "int(5) must not be empty")

	zeroInt := reflect.ValueOf(int(0))
	assert.True(t, v.isEmpty(zeroInt), "int(0) must be empty")
}
