package store

// local_machine_credentials_postgres_test.go verifies
// GetMachineIdentityCredentialWithIdentityStateByHash's JOIN query against a
// real Postgres server, not just SQLite (SESSION-PERF, #2403 follow-up,
// item 2) — the query was written once and relied on for both backends, and a
// SQLite-only test could pass on backend-specific quoting/aliasing quirks that
// don't hold on Postgres (or vice versa).
//
// Gated behind KEYORIX_TEST_PG_DSN, same opt-in shape as every other
// Postgres-gated test in this repo (see postgres_contention_helpers_test.go).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestGetMachineIdentityCredentialWithIdentityStateByHash_Postgres(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityCredential{}))

	identity := &models.MachineIdentity{ID: 1, Name: "ci-bot", State: "active"}
	require.NoError(t, db.Create(identity).Error)
	cred := &models.MachineIdentityCredential{
		ID: 1, MachineIdentityID: 1, Name: "ci", TokenHash: "deadbeef",
		AllowedCIDRs: `["10.0.0.0/8"]`,
	}
	require.NoError(t, db.Create(cred).Error)

	ls := NewLocalStorage(db)

	t.Run("matching hash returns both credential and identity state", func(t *testing.T) {
		got, state, err := ls.GetMachineIdentityCredentialWithIdentityStateByHash(context.Background(), "deadbeef")
		require.NoError(t, err)
		require.Equal(t, cred.ID, got.ID)
		require.Equal(t, cred.AllowedCIDRs, got.AllowedCIDRs)
		require.Equal(t, "active", state)
	})

	t.Run("unknown hash errors, not a zero-value false-positive", func(t *testing.T) {
		_, _, err := ls.GetMachineIdentityCredentialWithIdentityStateByHash(context.Background(), "no-such-hash")
		require.Error(t, err)
	})

	t.Run("revoked after creation is reflected immediately (no caching in this query)", func(t *testing.T) {
		require.NoError(t, db.Model(cred).Update("revoked", true).Error)
		got, _, err := ls.GetMachineIdentityCredentialWithIdentityStateByHash(context.Background(), "deadbeef")
		require.NoError(t, err)
		require.True(t, got.Revoked)
	})
}
