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
	ok, err := ls.UpdateProjectInvitation(ctx, got)
	require.NoError(t, err)
	require.True(t, ok)

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
	ok, err := ls.UpdateAccessRequest(ctx, created)
	require.NoError(t, err)
	require.True(t, ok)

	got, err := ls.GetAccessRequest(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "approved", got.State)

	list, err := ls.ListAccessRequests(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, list, 1)
}

// TestUpdateProjectInvitation_ConditionalOnPending_Sequential proves the storage
// guard itself (#412): a second write against a row that's no longer "pending"
// (because the first write already moved it) reports RowsAffected==0 via the bool,
// rather than silently clobbering the winner the way the old unconditional Save did.
func TestUpdateProjectInvitation_ConditionalOnPending_Sequential(t *testing.T) {
	ctx := context.Background()
	ls := newInviteStore(t)
	now := time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC)

	created, err := ls.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: 1, Email: "a@b.com", Role: "project_developer", State: "pending", CreatedAt: now,
	})
	require.NoError(t, err)

	// The "revoke" read-mutate-write.
	revokeCopy, err := ls.GetProjectInvitation(ctx, created.ID)
	require.NoError(t, err)
	revokeCopy.State = "revoked"

	// The "accept" read-mutate-write, reading the SAME still-pending row before
	// either write lands (the TOCTOU window #412 closes).
	acceptCopy, err := ls.GetProjectInvitation(ctx, created.ID)
	require.NoError(t, err)
	acceptCopy.State = "accepted"

	// Revoke lands first and wins.
	ok, err := ls.UpdateProjectInvitation(ctx, revokeCopy)
	require.NoError(t, err)
	require.True(t, ok, "the first writer (revoke) must win")

	// Accept's write, against a row that is no longer pending, must be rejected —
	// not silently applied over the revoke.
	ok, err = ls.UpdateProjectInvitation(ctx, acceptCopy)
	require.NoError(t, err)
	require.False(t, ok, "the second writer (accept) must lose, not clobber the revoke")

	final, err := ls.GetProjectInvitation(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "revoked", final.State, "the winning revoke must be the persisted state")
}

// TestUpdateAccessRequest_ConditionalOnPending_Sequential is the access-request
// analogue (#277): a second write against a row no longer "pending" is rejected,
// not silently applied over the winner.
func TestUpdateAccessRequest_ConditionalOnPending_Sequential(t *testing.T) {
	ctx := context.Background()
	ls := newInviteStore(t)
	now := time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC)

	created, err := ls.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: 1, UserID: 2, SuggestedRole: "project_viewer", State: "pending", CreatedAt: now,
	})
	require.NoError(t, err)

	approveCopy, err := ls.GetAccessRequest(ctx, created.ID)
	require.NoError(t, err)
	approveCopy.State = "approved"
	approveCopy.GrantedRole = "project_viewer"

	withdrawCopy, err := ls.GetAccessRequest(ctx, created.ID)
	require.NoError(t, err)
	withdrawCopy.State = "withdrawn"

	ok, err := ls.UpdateAccessRequest(ctx, approveCopy)
	require.NoError(t, err)
	require.True(t, ok, "the first writer (approve) must win")

	ok, err = ls.UpdateAccessRequest(ctx, withdrawCopy)
	require.NoError(t, err)
	require.False(t, ok, "the second writer (withdraw) must lose, not clobber the approval")

	final, err := ls.GetAccessRequest(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "approved", final.State, "the winning approval must be the persisted state")
}
