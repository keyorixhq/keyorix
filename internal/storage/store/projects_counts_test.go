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

// #2951 item 4: last_activity/deleted_at are raw DB strings; they may carry the
// server's local offset ("+02:00") while other rows say "Z", and a lexical
// compare across offsets picks the wrong "latest". The API must report the true
// latest instant, as UTC RFC 3339. Only the output changes, never the stored text.
func TestListProjectsWithCounts_LastActivityIsUTCAndComparedAsInstants(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)
	_, err = ls.CreateEnvironment(ctx, &models.Environment{Name: "dev", ProjectID: proj.ID})
	require.NoError(t, err)
	sec, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: proj.ID, EnvironmentID: 1, Name: "db-pw", IsSecret: true, Type: "text", Status: "active",
	})
	require.NoError(t, err)

	// project: 03:53:40+02:00 == 01:53:40Z, lexically greater but the EARLIER instant
	// secret : 02:30:00Z, lexically smaller but the LATER instant
	require.NoError(t, ls.db.Exec("UPDATE projects SET updated_at = ? WHERE id = ?", "2026-10-10 03:53:40.5+02:00", proj.ID).Error)
	require.NoError(t, ls.db.Exec("UPDATE secret_nodes SET updated_at = ? WHERE id = ?", "2026-10-10T02:30:00Z", sec.ID).Error)

	got, err := ls.ListProjectsWithCounts(ctx, false)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "2026-10-10T02:30:00Z", got[0].LastActivity, "the true latest instant, in UTC")

	// project's own update is the latest: reported as UTC, not with its +02:00
	require.NoError(t, ls.db.Exec("UPDATE secret_nodes SET updated_at = ? WHERE id = ?", "2026-10-10T00:00:00Z", sec.ID).Error)
	got, err = ls.ListProjectsWithCounts(ctx, false)
	require.NoError(t, err)
	assert.Equal(t, "2026-10-10T01:53:40.5Z", got[0].LastActivity)

	var stored string
	require.NoError(t, ls.db.Raw("SELECT updated_at FROM projects WHERE id = ?", proj.ID).Scan(&stored).Error)
	assert.Contains(t, stored, "+02:00", "stored value must not be rewritten")
}
