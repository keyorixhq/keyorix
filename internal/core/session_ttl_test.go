package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fixedClock is the reference "now" used across the session-TTL tests.
var sessionTestNow = time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)

func newSessionCore(store *MockStorage, access, absolute time.Duration) *KeyorixCore {
	return &KeyorixCore{
		storage:            store,
		now:                func() time.Time { return sessionTestNow },
		passwordPolicy:     DefaultPasswordPolicy(),
		sessionAccessTTL:   access,
		sessionAbsoluteTTL: absolute,
	}
}

// captureCreatedSession records the session handed to CreateSession (so the test
// can assert on the computed expiry fields) and echoes it straight back. The mock
// returns the same pointer, which Run has already populated, so RefreshSession's
// returned session carries the rotated token.
func captureCreatedSession(store *MockStorage) *models.Session {
	captured := &models.Session{}
	store.On("CreateSession", mock.Anything, mock.AnythingOfType("*models.Session")).
		Run(func(args mock.Arguments) {
			*captured = *args.Get(1).(*models.Session)
		}).
		Return(captured, nil)
	return captured
}

// mintSession with no absolute TTL configured stamps only the access window.
func TestMintSession_AccessTTLOnly(t *testing.T) {
	store := new(MockStorage)
	captured := captureCreatedSession(store)
	c := newSessionCore(store, 30*time.Minute, 0)

	_, err := c.mintSession(context.Background(), 1, "ua", "ip")
	require.NoError(t, err)

	require.NotNil(t, captured.ExpiresAt)
	require.Equal(t, sessionTestNow.Add(30*time.Minute), *captured.ExpiresAt)
	require.Nil(t, captured.AbsoluteExpiresAt, "no ceiling configured")
}

// mintSession with an absolute TTL stamps both the access window and the ceiling.
func TestMintSession_WithAbsoluteCeiling(t *testing.T) {
	store := new(MockStorage)
	captured := captureCreatedSession(store)
	c := newSessionCore(store, 30*time.Minute, 12*time.Hour)

	_, err := c.mintSession(context.Background(), 1, "ua", "ip")
	require.NoError(t, err)

	require.Equal(t, sessionTestNow.Add(30*time.Minute), *captured.ExpiresAt)
	require.NotNil(t, captured.AbsoluteExpiresAt)
	require.Equal(t, sessionTestNow.Add(12*time.Hour), *captured.AbsoluteExpiresAt)
}

// A ceiling shorter than one access window is clamped so the first window never
// already overruns the ceiling.
func TestMintSession_CeilingShorterThanAccessClamped(t *testing.T) {
	store := new(MockStorage)
	captured := captureCreatedSession(store)
	c := newSessionCore(store, 1*time.Hour, 10*time.Minute)

	_, err := c.mintSession(context.Background(), 1, "ua", "ip")
	require.NoError(t, err)

	require.Equal(t, *captured.ExpiresAt, *captured.AbsoluteExpiresAt,
		"ceiling pulled up to the access window")
}

// An unset access TTL falls back to the historic 24h default.
func TestMintSession_DefaultAccessTTL(t *testing.T) {
	store := new(MockStorage)
	captured := captureCreatedSession(store)
	c := newSessionCore(store, 0, 0)

	_, err := c.mintSession(context.Background(), 1, "ua", "ip")
	require.NoError(t, err)
	require.Equal(t, sessionTestNow.Add(24*time.Hour), *captured.ExpiresAt)
}

// Refreshing within the absolute window carries the ceiling unchanged onto the new
// session and starts a fresh access window. The old session is deleted.
func TestRefreshSession_CarriesCeiling(t *testing.T) {
	store := new(MockStorage)
	captured := captureCreatedSession(store)
	c := newSessionCore(store, 30*time.Minute, 12*time.Hour)

	ceiling := sessionTestNow.Add(8 * time.Hour) // still within the window
	oldExpiry := sessionTestNow.Add(-5 * time.Minute)
	old := &models.Session{ID: 7, UserID: 1, SessionToken: "old", ExpiresAt: &oldExpiry, AbsoluteExpiresAt: &ceiling}
	store.On("GetSession", mock.Anything, "old").Return(old, nil)
	store.On("DeleteSession", mock.Anything, uint(7)).Return(nil)

	out, err := c.RefreshSession(context.Background(), "old")
	require.NoError(t, err)
	require.NotEqual(t, "old", out.SessionToken, "token rotated")
	require.Equal(t, sessionTestNow.Add(30*time.Minute), *captured.ExpiresAt, "fresh access window")
	require.NotNil(t, captured.AbsoluteExpiresAt)
	require.Equal(t, ceiling, *captured.AbsoluteExpiresAt, "ceiling unchanged")
	store.AssertCalled(t, "DeleteSession", mock.Anything, uint(7))
}

// The last access window before the ceiling is clamped so it cannot overrun it.
func TestRefreshSession_ClampsLastWindowToCeiling(t *testing.T) {
	store := new(MockStorage)
	captured := captureCreatedSession(store)
	c := newSessionCore(store, 30*time.Minute, 12*time.Hour)

	ceiling := sessionTestNow.Add(10 * time.Minute) // less than one access window away
	old := &models.Session{ID: 7, UserID: 1, SessionToken: "old", AbsoluteExpiresAt: &ceiling}
	store.On("GetSession", mock.Anything, "old").Return(old, nil)
	store.On("DeleteSession", mock.Anything, uint(7)).Return(nil)

	_, err := c.RefreshSession(context.Background(), "old")
	require.NoError(t, err)
	require.Equal(t, ceiling, *captured.ExpiresAt, "new window clamped to the ceiling")
}

// Refreshing at or past the ceiling is refused and the stale session is deleted —
// re-authentication is required rather than another rotation.
func TestRefreshSession_RefusedPastCeiling(t *testing.T) {
	store := new(MockStorage)
	c := newSessionCore(store, 30*time.Minute, 12*time.Hour)

	ceiling := sessionTestNow.Add(-1 * time.Minute) // already past
	old := &models.Session{ID: 7, UserID: 1, SessionToken: "old", AbsoluteExpiresAt: &ceiling}
	store.On("GetSession", mock.Anything, "old").Return(old, nil)
	store.On("DeleteSession", mock.Anything, uint(7)).Return(nil)

	_, err := c.RefreshSession(context.Background(), "old")
	require.Error(t, err)
	require.Contains(t, err.Error(), "re-authentication required")
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
	store.AssertCalled(t, "DeleteSession", mock.Anything, uint(7))
}

// With no ceiling (legacy behaviour) a session refreshes indefinitely.
func TestRefreshSession_NoCeilingRefreshesForever(t *testing.T) {
	store := new(MockStorage)
	captured := captureCreatedSession(store)
	c := newSessionCore(store, 24*time.Hour, 0)

	old := &models.Session{ID: 7, UserID: 1, SessionToken: "old"} // AbsoluteExpiresAt nil
	store.On("GetSession", mock.Anything, "old").Return(old, nil)
	store.On("DeleteSession", mock.Anything, uint(7)).Return(nil)

	_, err := c.RefreshSession(context.Background(), "old")
	require.NoError(t, err)
	require.Equal(t, sessionTestNow.Add(24*time.Hour), *captured.ExpiresAt)
	require.Nil(t, captured.AbsoluteExpiresAt)
}
