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

func newInviteStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.ProjectInvitation{}, &models.AccessRequest{}))
	return NewLocalStorage(db)
}

func TestProjectInvitation_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ls := newInviteStore(t)
	now := time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC)

	created, err := ls.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: 1, Email: "a@b.com", Role: "project_developer", State: "pending",
		InvitedBy: 9, CreatedAt: now,
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)

	got, err := ls.GetProjectInvitation(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "pending", got.State)

	got.State = "revoked"
	require.NoError(t, ls.UpdateProjectInvitation(ctx, got))

	// Scoped list.
	_, err = ls.CreateProjectInvitation(ctx, &models.ProjectInvitation{ProjectID: 2, Email: "c@d.com", State: "pending", CreatedAt: now})
	require.NoError(t, err)
	list, err := ls.ListProjectInvitations(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "revoked", list[0].State)
}

func TestAccessRequest_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ls := newInviteStore(t)
	now := time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC)

	created, err := ls.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: 1, UserID: 2, SuggestedRole: "project_viewer", State: "pending", CreatedAt: now,
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)

	created.State = "approved"
	created.GrantedRole = "project_viewer"
	require.NoError(t, ls.UpdateAccessRequest(ctx, created))

	got, err := ls.GetAccessRequest(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "approved", got.State)

	list, err := ls.ListAccessRequests(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, list, 1)
}
