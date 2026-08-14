package http

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForGroups builds the standard #452/#507 two-server
// harness (see remote_storage_invitations_test.go's identical helper): an
// "upstream" exercised through the REAL production NewRouter/handlers
// (including the new /api/v1/system/groups and /api/v1/system/users/{id}/groups
// routes, server/http/handlers/groups_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote (ADR-049), pointed at
// "upstream" over real HTTP via store.RemoteStorage.
func newUpstreamDownstreamForGroups(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createNodeToken(t, upstream)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	t.Cleanup(upstreamSrv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstream = core.NewKeyorixCore(rs)
	return upstream, downstream
}

// TestRemoteStorageGroup_CreateGetUpdateDeleteRestore_RealServer proves the
// group CRUD fix: a group is genuinely persisted on the upstream server via
// the DOWNSTREAM's RemoteStorage, fetchable by ID, updatable, soft-deletable,
// and restorable — all via storage.type: remote against a real router, not a
// protocol mock.
func TestRemoteStorageGroup_CreateGetUpdateDeleteRestore_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForGroups(t)
	ctx := context.Background()

	created, err := downstream.Storage().CreateGroup(ctx, &models.Group{Name: "engineering", Description: "Eng team"})
	require.NoError(t, err, "creating a group must succeed via storage.type: remote")
	require.NotZero(t, created.ID, "the upstream must assign a real ID")
	assert.Equal(t, "engineering", created.Name)
	assert.Equal(t, "Eng team", created.Description)

	// Confirm it is a REAL row in the upstream's own storage (not just "the
	// call didn't error"), by reading it back directly against upstream.
	direct, err := upstream.Storage().GetGroup(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "engineering", direct.Name)

	// GetGroup via the downstream (RemoteStorage) round-trips correctly.
	fetched, err := downstream.Storage().GetGroup(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, fetched.ID)
	assert.Equal(t, "engineering", fetched.Name)
	assert.Equal(t, "Eng team", fetched.Description)

	// UpdateGroup via the downstream persists on the upstream.
	fetched.Name = "platform-engineering"
	fetched.Description = "Platform team"
	updated, err := downstream.Storage().UpdateGroup(ctx, fetched)
	require.NoError(t, err)
	assert.Equal(t, "platform-engineering", updated.Name)
	direct, err = upstream.Storage().GetGroup(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "platform-engineering", direct.Name, "the update must be a REAL upstream write")

	// DeleteGroup via the downstream soft-deletes on the upstream.
	require.NoError(t, downstream.Storage().DeleteGroup(ctx, created.ID))
	_, err = upstream.Storage().GetGroup(ctx, created.ID)
	require.Error(t, err, "a soft-deleted group must no longer be readable as active")

	// RestoreGroup via the downstream brings it back.
	require.NoError(t, downstream.Storage().RestoreGroup(ctx, created.ID))
	restored, err := upstream.Storage().GetGroup(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "platform-engineering", restored.Name, "restore must bring back the SAME row, not a blank one")
}

// TestRemoteStorageGroup_GetNotFound_RealServer proves a clean not-found error
// (not a panic, not a garbage 500) for a nonexistent group ID.
func TestRemoteStorageGroup_GetNotFound_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForGroups(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetGroup(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageGroup_ListAndListPage_RealServer proves ListGroups and
// ListGroupsPage both work via storage.type: remote against a real server.
func TestRemoteStorageGroup_ListAndListPage_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForGroups(t)
	ctx := context.Background()

	names := []string{"alpha-team", "beta-team", "gamma-team"}
	for _, n := range names {
		_, err := downstream.Storage().CreateGroup(ctx, &models.Group{Name: n})
		require.NoError(t, err)
	}

	all, err := downstream.Storage().ListGroups(ctx)
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, g := range all {
		seen[g.Name] = true
	}
	for _, n := range names {
		assert.True(t, seen[n], "ListGroups must include %q", n)
	}

	page, total, err := downstream.Storage().ListGroupsPage(ctx, 0, 2)
	require.NoError(t, err)
	assert.Len(t, page, 2, "ListGroupsPage must respect the page size limit")
	assert.GreaterOrEqual(t, total, int64(len(names)), "ListGroupsPage must report the true total, not just this page's length")
}

// TestRemoteStorageGroup_Membership_RealServer proves the user-membership fix:
// AddUserToGroup, ListGroupMembers, GetUserGroups, and RemoveUserFromGroup all
// work correctly via storage.type: remote against a real server.
func TestRemoteStorageGroup_Membership_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForGroups(t)
	ctx := context.Background()

	group, err := downstream.Storage().CreateGroup(ctx, &models.Group{Name: "on-call"})
	require.NoError(t, err)

	user, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username: "member1",
		Email:    "member1@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	require.NoError(t, downstream.Storage().AddUserToGroup(ctx, user.ID, group.ID, 0))

	// The membership is a REAL row on the upstream, visible via upstream's own
	// direct storage call.
	directMembers, err := upstream.Storage().ListGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, directMembers, 1)
	assert.Equal(t, user.ID, directMembers[0].ID)

	// ListGroupMembers via the downstream round-trips correctly.
	members, err := downstream.Storage().ListGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, user.ID, members[0].ID)
	assert.Equal(t, "member1", members[0].Username)

	// GetUserGroups via the downstream sees the group — this is the #GetUserGroups
	// silent-empty-slice fix: before it, this always returned zero groups
	// regardless of real membership.
	userGroups, err := downstream.Storage().GetUserGroups(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, userGroups, 1, "GetUserGroups must reflect the real membership, not silently report zero")
	assert.Equal(t, group.ID, userGroups[0].ID)

	// ListGroupMembersByGroupIDs (the batch form) via the downstream.
	byGroup, err := downstream.Storage().ListGroupMembersByGroupIDs(ctx, []uint{group.ID})
	require.NoError(t, err)
	require.Len(t, byGroup[group.ID], 1)
	assert.Equal(t, user.ID, byGroup[group.ID][0].ID)

	// RemoveUserFromGroup via the downstream removes the REAL upstream row.
	require.NoError(t, downstream.Storage().RemoveUserFromGroup(ctx, user.ID, group.ID, 0))
	directMembers, err = upstream.Storage().ListGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	assert.Empty(t, directMembers, "the membership removal must be a REAL upstream write")

	userGroups, err = downstream.Storage().GetUserGroups(ctx, user.ID)
	require.NoError(t, err)
	assert.Empty(t, userGroups)
}
