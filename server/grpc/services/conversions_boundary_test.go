package services

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIntToU32_Boundaries locks down intToU32's clamp-on-overflow behavior
// (CodeQL #1115/#1116 triage: the sinks here are outbound DB-row-to-proto
// conversions, not attacker-controlled input, but the helper is worth
// pinning at its exact boundaries regardless of call-site direction).
func TestIntToU32_Boundaries(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want uint32
	}{
		{"zero", 0, 0},
		{"one", 1, 1},
		{"max_uint32", math.MaxUint32, math.MaxUint32},
		{"max_uint32_plus_one_clamps", math.MaxUint32 + 1, 0},
		{"negative_one_clamps", -1, 0},
		{"min_int_clamps", math.MinInt, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, intToU32(c.in))
		})
	}
}

// TestI64ToU32_Boundaries covers i64ToU32's negative-clamp path plus the
// uint32 upper bound it delegates to intToU32 for.
func TestI64ToU32_Boundaries(t *testing.T) {
	cases := []struct {
		name string
		in   int64
		want uint32
	}{
		{"zero", 0, 0},
		{"max_uint32", math.MaxUint32, math.MaxUint32},
		{"max_uint32_plus_one_clamps", math.MaxUint32 + 1, 0},
		{"negative_one_clamps", -1, 0},
		{"max_int64_clamps", math.MaxInt64, 0},
		{"min_int64_clamps", math.MinInt64, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, i64ToU32(c.in))
		})
	}
}

// TestIntToI32_Boundaries covers both the overflow and underflow edges of
// intToI32's int32 range check (gosec G115).
func TestIntToI32_Boundaries(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int32
	}{
		{"zero", 0, 0},
		{"negative_one", -1, -1},
		{"max_int32", math.MaxInt32, math.MaxInt32},
		{"max_int32_plus_one_clamps", math.MaxInt32 + 1, 0},
		{"min_int32", math.MinInt32, math.MinInt32},
		{"min_int32_minus_one_clamps", math.MinInt32 - 1, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, intToI32(c.in))
		})
	}
}

// TestIntPtrToInt32Ptr_Boundaries covers the same int32 boundary via the
// pointer-returning wrapper, which clamps to 0 rather than propagating the
// safeconv error.
func TestIntPtrToInt32Ptr_Boundaries(t *testing.T) {
	over := math.MaxInt32 + 1
	under := math.MinInt32 - 1
	maxVal := math.MaxInt32

	got := intPtrToInt32Ptr(&over)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(0), *got, "overflow must clamp to 0")
	}

	got = intPtrToInt32Ptr(&under)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(0), *got, "underflow must clamp to 0")
	}

	got = intPtrToInt32Ptr(&maxVal)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(math.MaxInt32), *got)
	}

	assert.Nil(t, intPtrToInt32Ptr(nil))
}
