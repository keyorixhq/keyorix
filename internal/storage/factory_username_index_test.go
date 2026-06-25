package storage

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A soft-deleted (e.g. SCIM-deprovisioned) username must be reusable — the partial
// unique index scopes uniqueness to live rows, so re-provisioning the same userName
// no longer collides on INSERT. Two LIVE users with the same username must still fail.
func TestUsernamePartialUniqueIndex_ReuseAfterSoftDelete(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "username-index.db")

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ctx := context.Background()

	// Provision "alice".
	alice, err := st.CreateUser(ctx, &models.User{Username: "alice", Email: "alice@x.io", IsActive: true})
	require.NoError(t, err)

	// A second LIVE "alice" is rejected (live uniqueness still holds).
	_, err = st.CreateUser(ctx, &models.User{Username: "alice", Email: "alice2@x.io", IsActive: true})
	require.Error(t, err, "two live users may not share a username")

	// Deprovision alice (soft delete), then re-provision the same userName — must succeed.
	require.NoError(t, st.DeleteUser(ctx, alice.ID))
	reAlice, err := st.CreateUser(ctx, &models.User{Username: "alice", Email: "alice@x.io", IsActive: true})
	require.NoError(t, err, "a soft-deleted username must be reusable on re-provisioning")
	assert.NotEqual(t, alice.ID, reAlice.ID, "re-provisioning creates a fresh row")
}
