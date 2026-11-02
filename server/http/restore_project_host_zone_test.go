// restore_project_host_zone_test.go -- SQLITE-UTC-NOWFUNC-1, REVIEW-3868-DEEP-2 F1.
//
// RestoreProject brings back the children whose deleted_at is at or after the
// project's deleted_at. GORM soft-delete (DeleteSecret, DeleteEnvironment) stamps
// deleted_at through NowFunc, which is UTC; deleteProjectCascade stamps the
// project and its children with its own explicit time. SQLite compares the two
// as text, so if the cascade wrote host-zone time, a UTC "15:32 +0000" from an
// earlier independent delete sorted after a host-zone "11:32 -0400" cascade on
// any host west of UTC, and the restore resurrected that secret or environment
// (and cleared its purge_at).
//
// Run in a subprocess whose time.Local comes from TZ (no test assigns
// time.Local), through the real storage factory. SQLite only: Postgres compares
// instants, not text.
package http

import (
	"context"
	"database/sql"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

func TestRestoreProjectKeepsIndependentDeletes_NegativeOffsetHost_SQLite(t *testing.T) {
	const name = "TestRestoreProjectKeepsIndependentDeletes_NegativeOffsetHost_SQLite"
	if _, child := otHostTZChild(t); child {
		restoreKeepsIndependentDeletesOnThisHost(t)
		return
	}
	// West of UTC: the cascade's host-zone text sorts before a UTC stamp of an
	// earlier moment.
	for _, zone := range []string{"America/New_York", "America/Los_Angeles"} {
		t.Run(zone, func(t *testing.T) {
			loadZone(t, zone)
			runInOTHostTZ(t, name, zone)
		})
	}
}

func restoreKeepsIndependentDeletesOnThisHost(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	cfg, _ := rrStorageConfig(t, "sqlite")
	st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	raw, err := sql.Open("sqlite", "file:"+cfg.Storage.Database.Path+"?mode=ro&_busy_timeout=5000")
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "rz-project", Description: "restore host zone"})
	require.NoError(t, err)
	keepEnv, err := st.CreateEnvironment(ctx, &models.Environment{Name: "keep-env", ProjectID: proj.ID})
	require.NoError(t, err)
	goneEnv, err := st.CreateEnvironment(ctx, &models.Environment{Name: "gone-env", ProjectID: proj.ID})
	require.NoError(t, err)
	newSecret := func(name string) *models.SecretNode {
		s, err := st.CreateSecret(ctx, &models.SecretNode{ProjectID: proj.ID, EnvironmentID: keepEnv.ID, Name: name, IsSecret: true, Type: "text", Status: "active"})
		require.NoError(t, err)
		return s
	}
	keep := newSecret("keep")
	gone := newSecret("gone")

	// Retired on their own, then the whole project is deleted.
	require.NoError(t, st.DeleteSecret(ctx, gone.ID))
	require.NoError(t, st.DeleteEnvironment(ctx, goneEnv.ID))
	goneBefore := secretDeleteState(t, raw, gone.ID)
	require.NoError(t, st.DeleteProject(ctx, proj.ID))

	envs, secrets, err := st.RestoreProject(ctx, proj.ID)
	require.NoError(t, err)
	require.Equal(t, 1, envs, "only the cascade-deleted environment may come back")
	require.Equal(t, 1, secrets, "only the cascade-deleted secret may come back")

	_, err = st.GetSecret(ctx, keep.ID)
	require.NoError(t, err, "the cascade-deleted secret is restored")
	_, err = st.GetEnvironment(ctx, keepEnv.ID)
	require.NoError(t, err, "the cascade-deleted environment is restored")
	_, err = st.GetSecret(ctx, gone.ID)
	require.Error(t, err, "an independently deleted secret stays deleted")
	_, err = st.GetEnvironment(ctx, goneEnv.ID)
	require.Error(t, err, "an independently deleted environment stays deleted")
	require.Equal(t, goneBefore, secretDeleteState(t, raw, gone.ID), "restore must not touch the independently deleted secret (deleted_at, purge_at)")
}

// secretDeleteState is the stored deleted_at and purge_at text of one secret row.
func secretDeleteState(t *testing.T, raw *sql.DB, id uint) [2]sql.NullString {
	t.Helper()
	var st [2]sql.NullString
	require.NoError(t, raw.QueryRow("SELECT CAST(deleted_at AS TEXT), CAST(purge_at AS TEXT) FROM secret_nodes WHERE id = ?", id).Scan(&st[0], &st[1]))
	require.True(t, st[0].Valid, "secret %d is soft-deleted", id)
	return st
}
