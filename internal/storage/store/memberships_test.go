package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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
