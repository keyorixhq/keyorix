package safeconv

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUintToUint32(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		got, err := UintToUint32(0)
		require.NoError(t, err)
		assert.Equal(t, uint32(0), got)
	})

	t.Run("max boundary is allowed", func(t *testing.T) {
		got, err := UintToUint32(math.MaxUint32)
		require.NoError(t, err)
		assert.Equal(t, uint32(math.MaxUint32), got)
	})

	t.Run("just over max overflows", func(t *testing.T) {
		// On 64-bit platforms uint is 64-bit, so MaxUint32+1 is representable.
		_, err := UintToUint32(uint(math.MaxUint32) + 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "overflow")
	})
}

func TestIntToInt32(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		got, err := IntToInt32(0)
		require.NoError(t, err)
		assert.Equal(t, int32(0), got)
	})

	t.Run("positive and negative boundaries are allowed", func(t *testing.T) {
		hi, err := IntToInt32(math.MaxInt32)
		require.NoError(t, err)
		assert.Equal(t, int32(math.MaxInt32), hi)

		lo, err := IntToInt32(math.MinInt32)
		require.NoError(t, err)
		assert.Equal(t, int32(math.MinInt32), lo)
	})

	t.Run("over max overflows", func(t *testing.T) {
		_, err := IntToInt32(math.MaxInt32 + 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "int32 range")
	})

	t.Run("under min overflows", func(t *testing.T) {
		_, err := IntToInt32(math.MinInt32 - 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "int32 range")
	})
}

func TestIntToUint64(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		got, err := IntToUint64(0)
		require.NoError(t, err)
		assert.Equal(t, uint64(0), got)
	})

	t.Run("positive value", func(t *testing.T) {
		got, err := IntToUint64(math.MaxInt32)
		require.NoError(t, err)
		assert.Equal(t, uint64(math.MaxInt32), got)
	})

	t.Run("max int converts", func(t *testing.T) {
		got, err := IntToUint64(math.MaxInt64)
		require.NoError(t, err)
		assert.Equal(t, uint64(math.MaxInt64), got)
	})

	t.Run("negative is rejected", func(t *testing.T) {
		_, err := IntToUint64(-1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "negative")
	})
}
