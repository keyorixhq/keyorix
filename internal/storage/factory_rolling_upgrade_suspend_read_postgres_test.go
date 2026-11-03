package storage

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// v0963TransitionSecretStatus is the statement a v0.96.x replica's
// TransitionSecretStatus sends (v0.96.3:internal/storage/store/local_secrets.go,
// Select("Status", "UpdatedAt")): it never names suspend_clear_synced_copies.
const v0963TransitionSecretStatus = `UPDATE "secret_nodes" SET "status"=$1,"updated_at"=$2 WHERE (id = $3 AND status = $4) AND "secret_nodes"."deleted_at" IS NULL`

// #3362 through this binary's own code: a new replica suspends with "also clear
// the synced copies", an old replica resumes and then suspends plainly (its exact
// statements), and this binary's read of the secret must not carry the marker
// (versions.go turns SuspendClearSyncedCopies into the clear_synced_copies flag
// of the SecretSuspended refusal the operator and k8s-sync act on).
func TestSecretSuspendMarker_OldBinaryResumeThenPlainSuspend_NewReadNoClear_Postgres(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	ctx := context.Background()
	dsn := pgIsolatedDatabaseDSN(t, pgTestDSN(t))
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn
	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	if c, ok := st.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = c.Close() })
	}
	db := pgRawOpen(t, dsn)
	require.NoError(t, db.Exec(`INSERT INTO secret_nodes (project_id, environment_id, name, is_secret, status, created_at, updated_at)
VALUES (1, 1, 'old-binary-probe', true, 'active', now(), now())`).Error)
	var id uint
	require.NoError(t, db.Raw("SELECT id FROM secret_nodes WHERE name = 'old-binary-probe'").Scan(&id).Error)

	read := func() *models.SecretNode {
		s, err := st.GetSecret(ctx, id)
		require.NoError(t, err)
		return s
	}
	transition := func(to string, clear bool, from string) {
		s := read()
		s.Status, s.SuspendClearSyncedCopies, s.UpdatedAt = to, clear, time.Now()
		ok, err := st.TransitionSecretStatus(ctx, s, from)
		require.NoError(t, err)
		require.True(t, ok)
	}
	oldBinary := func(to, from string) {
		res := db.Exec(v0963TransitionSecretStatus, to, time.Now(), id, from)
		require.NoError(t, res.Error)
		require.EqualValues(t, 1, res.RowsAffected)
	}

	// New replica: suspend with "also clear the synced copies".
	transition("suspended", true, "active")
	require.True(t, read().SuspendClearSyncedCopies, "precondition: this suspension asked for the clear")

	// Old replica: resume, then a plain suspend.
	oldBinary("active", "suspended")
	oldBinary("suspended", "active")

	s := read()
	require.Equal(t, "suspended", s.Status)
	require.False(t, s.SuspendClearSyncedCopies, "a plain suspend by a v0.96.x replica must not tell clients to clear the synced Kubernetes copies")

	// This binary's own clear-copies suspend after that still carries it.
	transition("active", false, "suspended")
	transition("suspended", true, "active")
	require.True(t, read().SuspendClearSyncedCopies)
}
