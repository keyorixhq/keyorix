package store

// TZ-RESIDUE-1 item 3 (#3913): RestoreProject must compare deleted_at as an instant, not as text.
//
// SQLite stores deleted_at as text in the zone the writer used. A row soft-deleted before the UTC
// upgrade on a non-UTC host still holds host-zone text, and a text comparison against the cascade
// stamp orders it by wall clock: east of UTC a pre-cascade row sorted AFTER the cascade and was
// resurrected (with its frozen purge_at cleared); west of UTC a row of the cascade written in
// host-zone text sorted BEFORE it and was left behind. The texts below are written by hand into the
// column, as the old code left them.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestRestoreProjectComparesDeletedAtAsInstants(t *testing.T) {
	cascade := time.Date(2026, 11, 1, 13, 0, 0, 0, time.UTC)
	frozenPurge := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name        string
		deletedText string // what the column holds for the child
		restored    bool
	}{
		// 21:00+09:00 is 12:00Z, an hour BEFORE the cascade, but its text sorts after "13:00".
		{"pre-upgrade east-of-UTC row before the cascade stays deleted", "2026-11-01 21:00:00+09:00", false},
		// The old writer's own form ("... +0900 JST"), same instant.
		{"modernc host-zone form before the cascade stays deleted", "2026-11-01 21:00:00 +0900 JST", false},
		// 06:00-07:00 is 13:00Z, the cascade instant itself, but its text sorts before "13:00".
		{"pre-upgrade west-of-UTC row of the cascade is restored", "2026-11-01 06:00:00-07:00", true},
		// New-format UTC text, one minute after the cascade (same cascade, later sweep).
		{"UTC row at the cascade stamp is restored", "2026-11-01 13:00:00+00:00", true},
		{"UTC row before the cascade stays deleted", "2026-11-01 12:59:00+00:00", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ls := newRestoreTestStore(t)

			proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
			require.NoError(t, err)
			env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
			require.NoError(t, err)
			secret, err := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: proj.ID, EnvironmentID: env.ID, Name: "s",
				IsSecret: true, Type: "text", Status: "active"})
			require.NoError(t, err)

			require.NoError(t, ls.db.Unscoped().Model(&models.Project{}).Where("id = ?", proj.ID).
				Update("deleted_at", cascade).Error)
			require.NoError(t, ls.db.Exec("UPDATE environments SET deleted_at = ? WHERE id = ?", tc.deletedText, env.ID).Error)
			require.NoError(t, ls.db.Exec("UPDATE secret_nodes SET deleted_at = ?, purge_at = ? WHERE id = ?",
				tc.deletedText, frozenPurge, secret.ID).Error)

			restoredEnvs, restoredSecrets, err := ls.RestoreProject(ctx, proj.ID)
			require.NoError(t, err)

			// Raw reads: the hand-written host-zone text is not guaranteed to scan back into a model.
			var envDeleted, secretDeleted, secretPurge bool
			require.NoError(t, ls.db.Raw("SELECT deleted_at IS NOT NULL FROM environments WHERE id = ?", env.ID).Scan(&envDeleted).Error)
			require.NoError(t, ls.db.Raw("SELECT deleted_at IS NOT NULL FROM secret_nodes WHERE id = ?", secret.ID).Scan(&secretDeleted).Error)
			require.NoError(t, ls.db.Raw("SELECT purge_at IS NOT NULL FROM secret_nodes WHERE id = ?", secret.ID).Scan(&secretPurge).Error)

			if tc.restored {
				require.Equal(t, 1, restoredEnvs)
				require.Equal(t, 1, restoredSecrets)
				require.False(t, envDeleted)
				require.False(t, secretDeleted)
				require.False(t, secretPurge, "a restored secret loses its frozen purge date")
				return
			}
			require.Zero(t, restoredEnvs)
			require.Zero(t, restoredSecrets)
			require.True(t, envDeleted, "environment must stay deleted")
			require.True(t, secretDeleted, "secret must stay deleted")
			require.True(t, secretPurge, "a secret that stays deleted keeps its frozen purge date")
		})
	}
}
