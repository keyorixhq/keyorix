package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListProjectsWithCounts_CountsAndActivity covers the aggregate fields the
// Projects list page renders: secret/environment counts and a last-activity
// timestamp (most recent of the project's own update or any secret change).
func TestListProjectsWithCounts_CountsAndActivity(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)
	for _, name := range []string{"dev", "prod"} {
		_, err = ls.CreateEnvironment(ctx, &models.Environment{Name: name, ProjectID: proj.ID})
		require.NoError(t, err)
	}
	for _, name := range []string{"db-pw", "api-key", "token"} {
		_, err = ls.CreateSecret(ctx, &models.SecretNode{
			ProjectID: proj.ID, EnvironmentID: 1, Name: name, IsSecret: true, Type: "text", Status: "active",
		})
		require.NoError(t, err)
	}

	got, err := ls.ListProjectsWithCounts(ctx, false)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, int64(3), got[0].SecretCount)
	assert.Equal(t, int64(2), got[0].EnvironmentCount)
	assert.NotEmpty(t, got[0].LastActivity, "last activity should reflect the most recent secret update")
}

// A project with no secrets still reports a last-activity timestamp, falling
// back to the project's own updated_at (MAX over zero secret rows is NULL).
func TestListProjectsWithCounts_LastActivityFallsBackToProject(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "empty"})
	require.NoError(t, err)
	_, err = ls.CreateEnvironment(ctx, &models.Environment{Name: "dev", ProjectID: proj.ID})
	require.NoError(t, err)

	got, err := ls.ListProjectsWithCounts(ctx, false)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, int64(0), got[0].SecretCount)
	assert.NotEmpty(t, got[0].LastActivity, "no secrets → fall back to the project's own updated_at")
}
