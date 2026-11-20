package core

import (
	"context"
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

// TestMachineTokenExpiresAt_CrossesDSTChange: the window starts before the New York fall-back
// (2026-11-01 02:00 local) and ends after it. The expiry is computed in UTC, so it is exactly
// N*24h after the issue instant; a wall-clock AddDate in the host zone would be an hour off.
func TestMachineTokenExpiresAt_CrossesDSTChange(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	require.NoError(t, err)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, loc)

	got, err := MachineTokenExpiresAt(30, now)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, time.UTC, got.Location())
	assert.Equal(t, 30*24*time.Hour, got.Sub(now), "expiry is 30 UTC days after issue across the DST change")
}

// TestIssueMachineToken_ExpiresAtStoredInUTC pins that a caller-supplied ExpiresAt in a non-UTC
// zone is stored in UTC. The normalisation is models.MachineIdentityCredential.BeforeSave, not
// IssueMachineToken: this test passes on the base without any core change, so it is a regression
// pin for that behaviour, not proof of a fix.
func TestIssueMachineToken_ExpiresAtStoredInUTC(t *testing.T) {
	t.Parallel()
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()

	const adminID = 1 // the bootstrapped admin holds roles.assign at the project scope
	m, err := c.CreateMachineIdentity(ctx, 1, "mt-expiry-utc", MachineTypeService, "", "", 0, adminID)
	require.NoError(t, err)
	loc, err := time.LoadLocation("Asia/Tokyo")
	require.NoError(t, err)
	exp := time.Now().In(loc).Add(48 * time.Hour)

	res, err := c.IssueMachineToken(ctx, 1, m.ID, adminID, IssueMachineTokenParams{Name: "tokyo-expiry", ExpiresAt: &exp})
	require.NoError(t, err)
	require.NotNil(t, res.Credential.ExpiresAt)
	assert.Equal(t, time.UTC, res.Credential.ExpiresAt.Location())
	assert.True(t, res.Credential.ExpiresAt.Equal(exp))
	assert.Equal(t, loc, exp.Location(), "the caller's value is not mutated")
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
