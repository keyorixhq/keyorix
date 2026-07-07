package http

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteStorageEnvironment_ListGet_RealServer proves the read fix: environments
// seeded by CreateProject on the upstream are listed (globally and per-project) and
// fetched correctly via the DOWNSTREAM's RemoteStorage, against a real router.
func TestRemoteStorageEnvironment_ListGet_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForProjectCatalog(t)
	ctx := context.Background()

	project, err := upstream.CreateProject(ctx, "env-catalog-project", "")
	require.NoError(t, err)
	seeded, err := upstream.Storage().ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, seeded, "CreateProject must seed default environments")
	envID := seeded[0].ID

	// ListEnvironments via the downstream (global list) sees the real upstream rows.
	all, err := downstream.Storage().ListEnvironments(ctx)
	require.NoError(t, err)
	found := false
	for _, e := range all {
		if e.ID == envID {
			found = true
		}
	}
	assert.True(t, found, "ListEnvironments must include the real upstream environment")

	// ListEnvironmentsByProject via the downstream.
	byProject, err := downstream.Storage().ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	assert.Len(t, byProject, len(seeded))

	// GetEnvironment via the downstream round-trips correctly.
	fetched, err := downstream.Storage().GetEnvironment(ctx, envID)
	require.NoError(t, err)
	assert.Equal(t, envID, fetched.ID)
	assert.Equal(t, project.ID, fetched.ProjectID)
	assert.Equal(t, seeded[0].Name, fetched.Name)
}

// TestRemoteStorageEnvironment_GetNotFound_RealServer proves a clean not-found error
// for a nonexistent environment ID.
func TestRemoteStorageEnvironment_GetNotFound_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForProjectCatalog(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetEnvironment(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageEnvironment_DeleteRestore_RealServer proves the DeleteEnvironment/
// RestoreEnvironment/ListEnvironmentsByProjectIncludingDeleted fix: an environment
// with no active secrets is soft-deletable and restorable via the downstream's
// RemoteStorage, and the soft-deleted row is only visible via the
// include-deleted listing.
func TestRemoteStorageEnvironment_DeleteRestore_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForProjectCatalog(t)
	ctx := context.Background()

	project, err := upstream.CreateProject(ctx, "env-delete-project", "")
	require.NoError(t, err)
	seeded, err := upstream.Storage().ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, seeded)
	envID := seeded[0].ID

	// DeleteEnvironment via the downstream soft-deletes the real upstream row.
	require.NoError(t, downstream.Storage().DeleteEnvironment(ctx, envID))
	_, err = upstream.Storage().GetEnvironment(ctx, envID)
	require.Error(t, err, "a soft-deleted environment must no longer be readable as active")

	live, err := downstream.Storage().ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	for _, e := range live {
		assert.NotEqual(t, envID, e.ID, "the live listing must exclude the soft-deleted environment")
	}

	includingDeleted, err := downstream.Storage().ListEnvironmentsByProjectIncludingDeleted(ctx, project.ID)
	require.NoError(t, err)
	foundDeleted := false
	for _, e := range includingDeleted {
		if e.ID == envID {
			foundDeleted = true
		}
	}
	assert.True(t, foundDeleted, "the include-deleted listing must still show the soft-deleted environment")

	// RestoreEnvironment via the downstream brings it back.
	require.NoError(t, downstream.Storage().RestoreEnvironment(ctx, project.ID, envID))
	restored, err := upstream.Storage().GetEnvironment(ctx, envID)
	require.NoError(t, err)
	assert.Equal(t, envID, restored.ID)
	assert.Equal(t, seeded[0].Name, restored.Name, "restore must bring back the SAME row")
}

// TestRemoteStorageEnvironment_DeleteBlockedByActiveSecret_RealServer proves
// DeleteEnvironment's active-secret guard survives the HTTP hop unchanged: it is a
// single storage.Storage call (no core-layer decomposition), so one proxied round
// trip preserves LocalStorage's own count-then-reject semantics exactly — unlike
// DeleteProject(force=false), no new atomic primitive was needed here (see
// project_catalog_proxy.go's package doc for the contrast).
func TestRemoteStorageEnvironment_DeleteBlockedByActiveSecret_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForProjectCatalog(t)
	ctx := context.Background()

	project, err := upstream.CreateProject(ctx, "env-guard-project", "")
	require.NoError(t, err)
	seeded, err := upstream.Storage().ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, seeded)
	envID := seeded[0].ID

	_, err = upstream.Storage().CreateSecret(ctx, &models.SecretNode{
		Name:          "guard-secret",
		ProjectID:     project.ID,
		EnvironmentID: envID,
		IsSecret:      true,
		Status:        "active",
	})
	require.NoError(t, err)

	err = downstream.Storage().DeleteEnvironment(ctx, envID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "active secret")

	direct, err := upstream.Storage().GetEnvironment(ctx, envID)
	require.NoError(t, err)
	assert.Equal(t, envID, direct.ID, "a rejected delete must leave the environment live")
}
