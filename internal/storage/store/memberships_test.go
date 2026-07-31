package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newMembershipStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.ProjectMembership{}))
	return NewLocalStorage(db)
}

func TestProjectMembership_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ls := newMembershipStore(t)
	now := time.Date(2026, 6, 4, 9, 0, 0, 0, time.UTC)

	created, err := ls.CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: 1, UserID: 2, Role: "project_developer",
		State: "invited", InvitedBy: 9, InvitedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)

	// Get + update through a transition.
	got, err := ls.GetProjectMembership(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "invited", got.State)

	got.State = "active"
	require.NoError(t, ls.UpdateProjectMembership(ctx, got))
	reloaded, err := ls.GetProjectMembership(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "active", reloaded.State)

	// Active membership is the non-revoked one for (project, user).
	active, err := ls.GetActiveProjectMembership(ctx, 1, 2)
	require.NoError(t, err)
	assert.Equal(t, created.ID, active.ID)
}

func TestGetActiveProjectMembership_IgnoresRevoked(t *testing.T) {
	ctx := context.Background()
	ls := newMembershipStore(t)
	now := time.Now().UTC()
	_, err := ls.CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: 1, UserID: 2, State: "revoked", InvitedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)

	_, err = ls.GetActiveProjectMembership(ctx, 1, 2)
	assert.Error(t, err, "a revoked membership must not count as active")
}

func TestListStaleInvitedMemberships(t *testing.T) {
	ctx := context.Background()
	ls := newMembershipStore(t)
	now := time.Date(2026, 6, 4, 9, 0, 0, 0, time.UTC)

	mk := func(state string, invitedAt time.Time) {
		_, err := ls.CreateProjectMembership(ctx, &models.ProjectMembership{
			ProjectID: 1, UserID: 2, State: state, InvitedAt: invitedAt, UpdatedAt: invitedAt,
		})
		require.NoError(t, err)
	}
	mk("invited", now.Add(-10*24*time.Hour)) // stale
	mk("invited", now.Add(-1*time.Hour))     // fresh
	mk("active", now.Add(-30*24*time.Hour))  // old but not invited

	cutoff := now.Add(-7 * 24 * time.Hour)
	stale, err := ls.ListStaleInvitedMemberships(ctx, cutoff)
	require.NoError(t, err)
	require.Len(t, stale, 1, "only the old invited membership is stale")
	assert.Equal(t, "invited", stale[0].State)
}

func TestListUserProjectMemberships(t *testing.T) {
	ctx := context.Background()
	ls := newMembershipStore(t)
	now := time.Now().UTC()

	// Two memberships for user 2, one for user 3.
	_, err := ls.CreateProjectMembership(ctx, &models.ProjectMembership{ProjectID: 1, UserID: 2, State: "active", InvitedAt: now.Add(-2 * time.Hour), UpdatedAt: now})
	require.NoError(t, err)
	_, err = ls.CreateProjectMembership(ctx, &models.ProjectMembership{ProjectID: 5, UserID: 2, State: "invited", InvitedAt: now.Add(-1 * time.Hour), UpdatedAt: now})
	require.NoError(t, err)
	_, err = ls.CreateProjectMembership(ctx, &models.ProjectMembership{ProjectID: 1, UserID: 3, State: "active", InvitedAt: now, UpdatedAt: now})
	require.NoError(t, err)

	rows, err := ls.ListUserProjectMemberships(ctx, 2)
	require.NoError(t, err)
	require.Len(t, rows, 2, "only user 2's memberships")
	// Newest first (invited_at DESC): project 5 (most recent) before project 1.
	assert.Equal(t, uint(5), rows[0].ProjectID)
	assert.Equal(t, uint(1), rows[1].ProjectID)
}

func TestCountProjectMembershipsByUsers(t *testing.T) {
	ctx := context.Background()
	ls := newMembershipStore(t)
	now := time.Now().UTC()

	// User 2: 2 active + 1 invited + 1 revoked → active 2, total 3 (revoked excluded).
	for _, st := range []string{"active", "active", "invited", "revoked"} {
		_, err := ls.CreateProjectMembership(ctx, &models.ProjectMembership{ProjectID: 1, UserID: 2, State: st, InvitedAt: now, UpdatedAt: now})
		require.NoError(t, err)
	}
	// User 3: 1 active.
	_, err := ls.CreateProjectMembership(ctx, &models.ProjectMembership{ProjectID: 1, UserID: 3, State: "active", InvitedAt: now, UpdatedAt: now})
	require.NoError(t, err)

	counts, err := ls.CountProjectMembershipsByUsers(ctx, []uint{2, 3, 99})
	require.NoError(t, err)
	assert.Equal(t, 2, counts[2].Active)
	assert.Equal(t, 3, counts[2].Total)
	assert.Equal(t, 1, counts[3].Active)
	assert.Equal(t, 1, counts[3].Total)
	_, present := counts[99]
	assert.False(t, present, "a user with no memberships is absent from the map")

	// Empty input returns an empty (non-nil) map without a query.
	empty, err := ls.CountProjectMembershipsByUsers(ctx, nil)
	require.NoError(t, err)
	assert.NotNil(t, empty)
	assert.Empty(t, empty)
}
