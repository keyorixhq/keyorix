// local_hygiene_counts_test.go — unit tests for local_hygiene_counts.go.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newHygieneCountsStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "hygiene_counts_"+t.Name(),
		&models.HygieneTrendSnapshot{},
		&models.PersonalAccessToken{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{},
	)
}

// ─── SaveHygieneTrendSnapshot / ListHygieneTrendSnapshots ───────────────────

func TestSaveHygieneTrendSnapshot_CreatesRow(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()
	today := time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)

	snap := &models.HygieneTrendSnapshot{
		StalePATs: 3, ExpiredPATs: 1, StaleMachines: 2,
		TotalPATs: 10, TotalMachines: 5, SnapshotDate: today,
	}
	require.NoError(t, ls.SaveHygieneTrendSnapshot(ctx, snap))
	assert.NotZero(t, snap.ID)

	snaps, err := ls.ListHygieneTrendSnapshots(ctx, 30)
	require.NoError(t, err)
	require.Len(t, snaps, 1)
	assert.Equal(t, 3, snaps[0].StalePATs)
}

func TestSaveHygieneTrendSnapshot_Upserts(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()
	day := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	first := &models.HygieneTrendSnapshot{StalePATs: 5, SnapshotDate: day}
	require.NoError(t, ls.SaveHygieneTrendSnapshot(ctx, first))

	second := &models.HygieneTrendSnapshot{StalePATs: 9, SnapshotDate: day}
	require.NoError(t, ls.SaveHygieneTrendSnapshot(ctx, second))

	snaps, err := ls.ListHygieneTrendSnapshots(ctx, 30)
	require.NoError(t, err)
	require.Len(t, snaps, 1, "upsert must not create a second row for the same day")
	assert.Equal(t, 9, snaps[0].StalePATs)
}

func TestListHygieneTrendSnapshots_Empty(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()

	snaps, err := ls.ListHygieneTrendSnapshots(ctx, 30)
	require.NoError(t, err)
	assert.Empty(t, snaps)
}

func TestListHygieneTrendSnapshots_NonPositiveDaysDefaultsTo30(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()

	// Insert 5 snapshots.
	for i := range 5 {
		d := time.Date(2026, 6, 5-i, 0, 0, 0, 0, time.UTC)
		require.NoError(t, ls.SaveHygieneTrendSnapshot(ctx, &models.HygieneTrendSnapshot{SnapshotDate: d}))
	}

	// days=0 must behave like days=30 (return all 5).
	snaps, err := ls.ListHygieneTrendSnapshots(ctx, 0)
	require.NoError(t, err)
	assert.Len(t, snaps, 5)

	// days=-1 similarly.
	snaps, err = ls.ListHygieneTrendSnapshots(ctx, -1)
	require.NoError(t, err)
	assert.Len(t, snaps, 5)
}

// ─── CountStalePATs ─────────────────────────────────────────────────────────

func TestCountStalePATs_EmptyDB(t *testing.T) {
	ls := newHygieneCountsStore(t)
	n, err := ls.CountStalePATs(context.Background(), time.Now().Add(-30*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestCountStalePATs_CountsNeverUsed(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()

	// Active (non-revoked, non-expired) PAT that was never used → stale.
	pat := &models.PersonalAccessToken{
		UserID: 1, Name: "unused", TokenHash: "h1", LastUsedAt: nil, Revoked: false,
	}
	require.NoError(t, ls.db.WithContext(ctx).Create(pat).Error)

	n, err := ls.CountStalePATs(ctx, time.Now().Add(-30*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestCountStalePATs_SkipsRevoked(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()

	revoked := &models.PersonalAccessToken{
		UserID: 1, Name: "revoked", TokenHash: "h2", Revoked: true,
	}
	require.NoError(t, ls.db.WithContext(ctx).Create(revoked).Error)

	n, err := ls.CountStalePATs(ctx, time.Now().Add(-30*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 0, n, "revoked PATs must not be counted as stale")
}

func TestCountStalePATs_SkipsRecentlyUsed(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()

	recent := time.Now().Add(-5 * 24 * time.Hour)
	pat := &models.PersonalAccessToken{
		UserID: 1, Name: "recent", TokenHash: "h3", LastUsedAt: &recent, Revoked: false,
	}
	require.NoError(t, ls.db.WithContext(ctx).Create(pat).Error)

	n, err := ls.CountStalePATs(ctx, time.Now().Add(-30*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 0, n, "recently-used PATs must not be counted as stale")
}

// ─── CountExpiredPATs ───────────────────────────────────────────────────────

func TestCountExpiredPATs_EmptyDB(t *testing.T) {
	ls := newHygieneCountsStore(t)
	n, err := ls.CountExpiredPATs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestCountExpiredPATs_CountsExpired(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()

	past := time.Now().Add(-24 * time.Hour)
	pat := &models.PersonalAccessToken{
		UserID: 1, Name: "expired", TokenHash: "h4", ExpiresAt: &past, Revoked: false,
	}
	require.NoError(t, ls.db.WithContext(ctx).Create(pat).Error)

	n, err := ls.CountExpiredPATs(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestCountExpiredPATs_SkipsRevoked(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()

	past := time.Now().Add(-24 * time.Hour)
	pat := &models.PersonalAccessToken{
		UserID: 1, Name: "exp-revoked", TokenHash: "h5", ExpiresAt: &past, Revoked: true,
	}
	require.NoError(t, ls.db.WithContext(ctx).Create(pat).Error)

	n, err := ls.CountExpiredPATs(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "revoked PATs must not be counted as expired")
}

func TestCountExpiredPATs_SkipsFuture(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()

	future := time.Now().Add(24 * time.Hour)
	pat := &models.PersonalAccessToken{
		UserID: 1, Name: "future", TokenHash: "h6", ExpiresAt: &future, Revoked: false,
	}
	require.NoError(t, ls.db.WithContext(ctx).Create(pat).Error)

	n, err := ls.CountExpiredPATs(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "non-expired PATs must not be counted")
}

// ─── CountStaleMachineCredentials ───────────────────────────────────────────

func TestCountStaleMachineCredentials_EmptyDB(t *testing.T) {
	ls := newHygieneCountsStore(t)
	n, err := ls.CountStaleMachineCredentials(context.Background(), time.Now().Add(-30*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestCountStaleMachineCredentials_ActiveWithNoCredentials(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()

	m := &models.MachineIdentity{Name: "no-creds", State: "active"}
	require.NoError(t, ls.db.WithContext(ctx).Create(m).Error)

	n, err := ls.CountStaleMachineCredentials(ctx, time.Now().Add(-30*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 1, n, "machine with no credentials should be counted as stale")
}

func TestCountStaleMachineCredentials_SkipsRevoked(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()

	m := &models.MachineIdentity{Name: "revoked-machine", State: "revoked"}
	require.NoError(t, ls.db.WithContext(ctx).Create(m).Error)

	n, err := ls.CountStaleMachineCredentials(ctx, time.Now().Add(-30*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 0, n, "non-active machines must not be counted")
}

func TestCountStaleMachineCredentials_NotStaleWhenRecentlyUsed(t *testing.T) {
	ls := newHygieneCountsStore(t)
	ctx := context.Background()

	m := &models.MachineIdentity{Name: "recent-machine", State: "active"}
	require.NoError(t, ls.db.WithContext(ctx).Create(m).Error)

	recent := time.Now().Add(-2 * 24 * time.Hour)
	cred := &models.MachineIdentityCredential{
		MachineIdentityID: m.ID, TokenHash: "mh1",
		LastUsedAt: &recent, Revoked: false,
	}
	require.NoError(t, ls.db.WithContext(ctx).Create(cred).Error)

	n, err := ls.CountStaleMachineCredentials(ctx, time.Now().Add(-30*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 0, n, "machine with recently-used credential must not be stale")
}
