package store

// REVIEW-3921-DEEP-2 F1/F2: RestoreProject against the deleted_at text the pre-UTC writer really left.
//
// Before the UTC campaign deleteProjectCascade stamped time.Now(), which carries a monotonic clock
// reading, and modernc binds a time.Time with t.String(): the column holds
// "2026-11-01 13:37:30.058117 +0100 CET m=+0.014210209", in every host zone (UTC hosts included).
// modernc's own reader strips the " m=" suffix, so the project's DeletedAt still scans; the child
// text is parsed by parseDBTimestamp and must parse too, or every cascade child stays deleted.
// A child that still does not parse must fail the whole restore, not return a silent partial one.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedRestoreProject creates a project with one environment and one secret and returns their ids.
func seedRestoreProject(t *testing.T, ls *LocalStorage) (projectID, envID, secretID uint) {
	t.Helper()
	ctx := context.Background()
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: proj.ID, EnvironmentID: env.ID, Name: "s",
		IsSecret: true, Type: "text", Status: "active"})
	require.NoError(t, err)
	return proj.ID, env.ID, secret.ID
}

// deletedFlags reads deleted_at IS NOT NULL / purge_at IS NOT NULL raw, without scanning a model.
func deletedFlags(t *testing.T, ls *LocalStorage, projectID, envID, secretID uint) (projDeleted, envDeleted, secretDeleted, secretPurge bool) {
	t.Helper()
	require.NoError(t, ls.db.Raw("SELECT deleted_at IS NOT NULL FROM projects WHERE id = ?", projectID).Scan(&projDeleted).Error)
	require.NoError(t, ls.db.Raw("SELECT deleted_at IS NOT NULL FROM environments WHERE id = ?", envID).Scan(&envDeleted).Error)
	require.NoError(t, ls.db.Raw("SELECT deleted_at IS NOT NULL FROM secret_nodes WHERE id = ?", secretID).Scan(&secretDeleted).Error)
	require.NoError(t, ls.db.Raw("SELECT purge_at IS NOT NULL FROM secret_nodes WHERE id = ?", secretID).Scan(&secretPurge).Error)
	return
}

// The cascade is written exactly as the old writer did: one time.Now() value (monotonic reading
// included) bound through the production modernc dialect for the project and both children.
func TestRestoreProjectRestoresPreUpgradeMonotonicCascade(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)
	projectID, envID, secretID := seedRestoreProject(t, ls)

	deletedAt := time.Now() // deliberately not .UTC(): the pre-upgrade writer's value
	purgeAt := deletedAt.Add(30 * 24 * time.Hour)
	require.NoError(t, ls.db.Exec("UPDATE projects SET deleted_at = ? WHERE id = ?", deletedAt, projectID).Error)
	require.NoError(t, ls.db.Exec("UPDATE environments SET deleted_at = ? WHERE id = ?", deletedAt, envID).Error)
	require.NoError(t, ls.db.Exec("UPDATE secret_nodes SET deleted_at = ?, purge_at = ? WHERE id = ?",
		deletedAt, purgeAt, secretID).Error)

	// Premise: the stored child text really is the monotonic String() form this test is about.
	var stored string
	require.NoError(t, ls.db.Raw("SELECT CAST(deleted_at AS TEXT) FROM environments WHERE id = ?", envID).Scan(&stored).Error)
	require.Contains(t, stored, " m=", "premise: the old writer's text carries the monotonic suffix")

	restoredEnvs, restoredSecrets, err := ls.RestoreProject(ctx, projectID)
	require.NoError(t, err)
	require.Equal(t, 1, restoredEnvs)
	require.Equal(t, 1, restoredSecrets)

	projDeleted, envDeleted, secretDeleted, secretPurge := deletedFlags(t, ls, projectID, envID, secretID)
	require.False(t, projDeleted)
	require.False(t, envDeleted, "the cascade environment must come back")
	require.False(t, secretDeleted, "the cascade secret must come back")
	require.False(t, secretPurge, "a restored secret loses its frozen purge date")
}

// Literal old-writer texts, so the east/west ordering is pinned independent of the test host's zone.
func TestRestoreProjectComparesMonotonicSuffixTextAsInstants(t *testing.T) {
	cascade := time.Date(2026, 11, 1, 13, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name        string
		deletedText string
		restored    bool
	}{
		// 21:00 +0900 is 12:00Z, an hour before the cascade.
		{"east-of-UTC monotonic text before the cascade stays deleted", "2026-11-01 21:00:00.058117 +0900 JST m=+0.014210209", false},
		// 06:00 -0700 is 13:00Z, the cascade instant.
		{"west-of-UTC monotonic text of the cascade is restored", "2026-11-01 06:00:00 -0700 MST m=+12.5", true},
		{"UTC-host monotonic text of the cascade is restored", "2026-11-01 13:00:00.5 +0000 UTC m=+0.000000001", true},
		{"negative monotonic reading parses too", "2026-11-01 14:00:00 +0100 CET m=-3.25", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ls := newRestoreTestStore(t)
			projectID, envID, secretID := seedRestoreProject(t, ls)

			require.NoError(t, ls.db.Exec("UPDATE projects SET deleted_at = ? WHERE id = ?", cascade, projectID).Error)
			require.NoError(t, ls.db.Exec("UPDATE environments SET deleted_at = ? WHERE id = ?", tc.deletedText, envID).Error)
			require.NoError(t, ls.db.Exec("UPDATE secret_nodes SET deleted_at = ? WHERE id = ?", tc.deletedText, secretID).Error)

			restoredEnvs, restoredSecrets, err := ls.RestoreProject(ctx, projectID)
			require.NoError(t, err)
			_, envDeleted, secretDeleted, _ := deletedFlags(t, ls, projectID, envID, secretID)
			if tc.restored {
				require.Equal(t, 1, restoredEnvs)
				require.Equal(t, 1, restoredSecrets)
				require.False(t, envDeleted)
				require.False(t, secretDeleted)
				return
			}
			require.Zero(t, restoredEnvs)
			require.Zero(t, restoredSecrets)
			require.True(t, envDeleted)
			require.True(t, secretDeleted)
		})
	}
}

// F2: a child whose deleted_at parses as no known form aborts the restore. The transaction rolls
// back, so the project and the child that DID parse stay deleted and the secret keeps its purge
// date: the operator sees an error and can retry after the row is fixed, instead of a restored
// project whose child is later purged by the retention job.
func TestRestoreProjectFailsOnUnparseableChildDeletedAt(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)
	projectID, envID, secretID := seedRestoreProject(t, ls)

	cascade := time.Date(2026, 11, 1, 13, 0, 0, 0, time.UTC)
	frozenPurge := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, ls.db.Exec("UPDATE projects SET deleted_at = ? WHERE id = ?", cascade, projectID).Error)
	require.NoError(t, ls.db.Exec("UPDATE environments SET deleted_at = ? WHERE id = ?", cascade, envID).Error)
	require.NoError(t, ls.db.Exec("UPDATE secret_nodes SET deleted_at = ?, purge_at = ? WHERE id = ?",
		"not a timestamp", frozenPurge, secretID).Error)

	restoredEnvs, restoredSecrets, err := ls.RestoreProject(ctx, projectID)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "unparseable deleted_at"), "error names the cause: %v", err)
	require.Zero(t, restoredEnvs)
	require.Zero(t, restoredSecrets)

	projDeleted, envDeleted, secretDeleted, secretPurge := deletedFlags(t, ls, projectID, envID, secretID)
	require.True(t, projDeleted, "the project stays deleted: the restore rolled back")
	require.True(t, envDeleted, "the parseable environment is rolled back too")
	require.True(t, secretDeleted)
	require.True(t, secretPurge, "the secret keeps its frozen purge date")
}
