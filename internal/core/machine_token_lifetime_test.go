package core

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMachineTokenExpiresAt is the shared validator both IssueMachineToken
// transports call (IDENTITY-INPUT-BOUNDS-1 item 2).
func TestMachineTokenExpiresAt(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

	got, err := MachineTokenExpiresAt(0, now)
	require.NoError(t, err)
	assert.Nil(t, got, "0 = never expires")

	got, err = MachineTokenExpiresAt(MaxMachineTokenLifetimeDays, now)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, now.AddDate(0, 0, MaxMachineTokenLifetimeDays), *got)

	for _, d := range []int64{-1, math.MinInt32, MaxMachineTokenLifetimeDays + 1, math.MaxInt32, math.MaxUint32, math.MaxInt64, math.MinInt64} {
		got, err := MachineTokenExpiresAt(d, now)
		assert.ErrorIs(t, err, ErrInvalidInput, "%d", d)
		assert.Nil(t, got, "%d", d)
	}
}

// TestMachineTokenExpiresAt_IsUTCWhateverTheClockZone: both transports pass time.Now(), which is in
// the host zone; the stored and returned expiry must not carry that offset.
func TestMachineTokenExpiresAt_IsUTCWhateverTheClockZone(t *testing.T) {
	for _, zone := range []string{"Asia/Tokyo", "Pacific/Auckland"} {
		loc, err := time.LoadLocation(zone)
		require.NoError(t, err)
		now := time.Date(2026, 11, 11, 12, 0, 0, 0, loc)
		got, err := MachineTokenExpiresAt(30, now)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, time.UTC, got.Location(), zone)
		assert.True(t, got.Equal(now.UTC().AddDate(0, 0, 30)), zone)
	}
}
