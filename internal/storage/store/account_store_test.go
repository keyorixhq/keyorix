package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestMain initialises i18n once for the store test package so error paths that
// call i18n.T (e.g. not-found lookups) do not panic.
func TestMain(m *testing.M) {
	if err := i18n.InitializeForTesting(); err != nil {
		panic(err)
	}
	code := m.Run()
	i18n.ResetForTesting()
	os.Exit(code)
}

func newAccountTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Session{}, &models.PersonalAccessToken{}))
	return NewLocalStorage(db)
}

func TestSessionListAndRevoke(t *testing.T) {
	ctx := context.Background()
	ls := newAccountTestStore(t)
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	// Two live sessions for user 1, one expired, one for user 2.
	for _, s := range []*models.Session{
		{UserID: 1, SessionToken: "u1-a", ExpiresAt: &future},
		{UserID: 1, SessionToken: "u1-b", ExpiresAt: &future},
		{UserID: 1, SessionToken: "u1-expired", ExpiresAt: &past},
		{UserID: 2, SessionToken: "u2-a", ExpiresAt: &future},
	} {
		_, err := ls.CreateSession(ctx, s)
		require.NoError(t, err)
	}

	got, err := ls.ListSessionsByUser(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, got, 2, "only user 1's non-expired sessions are returned")

	// DeleteSessionsForUserExcept keeps one and drops the rest for user 1 only.
	keep := got[0]
	require.NoError(t, ls.DeleteSessionsForUserExcept(ctx, 1, keep.ID))
	remaining, err := ls.ListSessionsByUser(ctx, 1)
	require.NoError(t, err)
	require.Len(t, remaining, 1)
	assert.Equal(t, keep.ID, remaining[0].ID)

	// User 2's session is untouched.
	u2, err := ls.ListSessionsByUser(ctx, 2)
	require.NoError(t, err)
	assert.Len(t, u2, 1)
}

func TestTouchSessionThrottle(t *testing.T) {
	ctx := context.Background()
	ls := newAccountTestStore(t)
	future := time.Now().Add(time.Hour)
	s, err := ls.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: "tok", ExpiresAt: &future})
	require.NoError(t, err)

	// First touch writes (last_seen_at was nil).
	t1 := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, ls.TouchSession(ctx, s.ID, t1, 30*time.Second))
	got, err := ls.GetSessionByID(ctx, s.ID)
	require.NoError(t, err)
	require.NotNil(t, got.LastSeenAt)
	assert.True(t, got.LastSeenAt.Equal(t1))

	// A touch a few seconds later is throttled away (within the staleness window).
	require.NoError(t, ls.TouchSession(ctx, s.ID, t1.Add(5*time.Second), 30*time.Second))
	got, _ = ls.GetSessionByID(ctx, s.ID)
	assert.True(t, got.LastSeenAt.Equal(t1), "within window → no write")

	// A touch past the window writes through.
	t2 := t1.Add(time.Minute)
	require.NoError(t, ls.TouchSession(ctx, s.ID, t2, 30*time.Second))
	got, _ = ls.GetSessionByID(ctx, s.ID)
	assert.True(t, got.LastSeenAt.Equal(t2), "past window → write")
}

func TestPATLifecycle(t *testing.T) {
	ctx := context.Background()
	ls := newAccountTestStore(t)

	created, err := ls.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
		UserID: 1, Name: "ci", TokenHash: "hash-1", TokenPrefix: "kx_pat_abc",
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)

	// Indexed hash lookup (the auth hot path).
	byHash, err := ls.GetPersonalAccessTokenByHash(ctx, "hash-1")
	require.NoError(t, err)
	assert.Equal(t, created.ID, byHash.ID)

	// List by user.
	list, err := ls.ListPersonalAccessTokensByUser(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// Revoke flips the flag (no delete).
	require.NoError(t, ls.RevokePersonalAccessToken(ctx, created.ID))
	got, err := ls.GetPersonalAccessTokenByID(ctx, created.ID)
	require.NoError(t, err)
	assert.True(t, got.Revoked)

	// Unknown hash → error.
	_, err = ls.GetPersonalAccessTokenByHash(ctx, "nope")
	require.Error(t, err)
}
